# Design: HashiCorp Vault secrets engine for Temporal Cloud

**Date:** 2026-08-06
**Status:** Approved, ready for implementation planning

## Problem

Temporal Cloud authenticates clients with either mTLS certificates or API keys. API keys are
the easier path — no CA to run — but they are awkward to operate:

- The token is displayed exactly once, at creation. Lose it and your only option is to make a new one.
- Keys must expire. The maximum is 2 years, and there is no non-expiring option.
- Rotation is manual and multi-step: create a new key, verify it, switch clients over, delete the old one.
- Nothing ties a key's lifetime to the lifetime of the workload holding it. A key issued to a
  worker that was decommissioned six months ago is still a valid credential.

That is the shape of problem HashiCorp Vault's dynamic secrets solve. This repository builds a Vault
secrets engine that issues short-lived Temporal Cloud API keys on demand and deletes them when the
Vault lease ends, so no long-lived Temporal Cloud credential has to exist anywhere.

## Goals

- Vault provisions and owns Temporal Cloud **service accounts**, declaratively.
- Applications read a path and get a **fresh, short-lived API key**; Vault deletes it on lease expiry.
- The one long-lived admin credential Vault needs can **rotate itself**, so the bootstrap key does
  not have to survive setup.
- Clean enough to demo live in a few commands, and documented well enough to hand to a customer.

## Non-goals

Explicitly out of scope. Each is a clean follow-on, and keeping them out keeps the first
implementation reviewable:

- mTLS / certificate management
- Namespace CRUD
- User and user-group management
- Nexus endpoints
- Namespace-scoped service accounts (`create-scoped`)
- Vault's scheduled automated rotation (`rotation_schedule` / `rotation_period`)

## Key facts about the Temporal Cloud API

Verified against Temporal documentation before designing. These drive several decisions below.

| Fact | Consequence for this design |
| --- | --- |
| Cloud Ops API: gRPC `saas-api.tmprl.cloud:443`, HTTP `https://saas-api.tmprl.cloud` | Use gRPC via `go.temporal.io/cloud-sdk` |
| The Go client lives in `go.temporal.io/cloud-sdk` v0.16.0, package `cloudclient` — **not** in `go.temporal.io/api`, which has no `cloud/` package at all. `github.com/temporalio/cloud-api` is protos-only with no Go code. | Correct dependency; verified by inspecting the module |
| All mutations are **async** — return an operation ID to poll | A polling layer hides this from all callers |
| Terminal async states are `FULFILLED` (success), `FAILED`, `CANCELLED`, `REJECTED` — there is no `SUCCEEDED` | Poll until `FULFILLED`; treat the other three as errors |
| `CreateApiKeyResponse` carries `KeyId` and `Token` directly on the response | Token is available without a follow-up read |
| The SDK's default retry interceptor already sets `async_operation_id` on writes and retries with exponential backoff + jitter, max 7 attempts | Do **not** hand-roll idempotency keys or retries |
| API key tokens are returned **once**, at creation | Perfect fit for Vault's dynamic-secret model |
| `CreateApiKey` supports **service-account owners only** (not users) | Root credential must itself be a service-account key |
| **Max 20 non-expired keys per service account** | Hard ceiling of 20 concurrent leases per SA |
| Max API key expiry: **2 years**; expiry is mandatory | Even the root key expires; `rotate-root` is not optional |
| **Minimum API key expiry: 24 hours.** Found by live testing on 2026-08-06 — undocumented anywhere; the server rejects a shorter expiry with `expiry must be after <now+24h>`. | Key expiry must be floored at 24h and can no longer track `max_ttl`. See *The 24-hour expiry floor*. |
| Account roles: `owner`, `admin`, `developer`, `finance-admin`, `read`, `metrics-read` | Enum validated at write time |
| Namespace permissions: `admin`, `write`, `read` | Enum validated at write time |
| No whoami RPC — a token does not reveal its owning identity | Operator must supply `admin_service_account_id` |
| `ApiKeySpec`: `owner_id`, `owner_type`, `display_name`, `description`, `disabled`, `expiry_time` | Shape of the create call |
| Mutations accept a client-supplied `async_operation_id` as an idempotency key | Retries cannot double-create |

## Design decisions

Each was chosen over stated alternatives.

**One API key per lease, minted on a shared service account.** A Vault entry names one Temporal
Cloud service account; each credential request mints a new API key on it. Rejected: creating a fresh
service account per lease — two chained async operations per read, and it burns service-account quota.
Trade-off accepted: Temporal Cloud audit logs attribute activity to the service account, not to the
individual lease. Per-lease attribution comes from Vault's own audit log, which records who read
which path when.

**Vault creates and owns the service accounts.** A `service-accounts/<name>` path does real CRUD
against the Cloud Ops API. Rejected: referencing only pre-existing service accounts — that leaves the
engine not actually managing service accounts, which was half the requirement.

**Two path layers, not three.** `service-accounts/<name>` carries both the Temporal Cloud spec
(account role, namespace access) and the credential policy (`ttl`, `max_ttl`). `creds/<name>` mints
against it. Rejected: a conventional intermediate `roles/` layer — it exists in other engines to map a
Vault-side name onto a cloud-side identity, but `service-accounts/<name>` already *is* a Vault-side
name for a cloud-side identity, so `roles/` would be pure indirection. `creds/<name>` remains
policy-targetable, which is the only thing `roles/` was really buying. Cost of this choice: two
credential profiles (say a 15m CI TTL and a 12h worker TTL) against one Temporal Cloud service
account require two Vault entries and therefore two service accounts. Acceptable.

**Root credential is a service-account API key with self-rotation.** Rejected: no rotation (bootstrap
key lives forever, and someone keeps a copy) and scheduled auto-rotation (depends on Vault 1.19+
rotation-manager plumbing; deferred to a follow-on).

**Fail fast at the 20-key ceiling.** Rejected: evicting the oldest lease to make room — a running
worker silently losing its credential is a bad production failure mode. Also rejected: a pool of N
identical service accounts to lift the ceiling to 20N — roughly doubles engine complexity for a limit
most deployments will not reach.

**Live-only integration tests.** Chosen deliberately over an in-process fake. Consequence, recorded
here rather than argued: there is no CI-runnable integration suite, and a test that dies mid-flight
leaves real resources behind. Mitigated by the fast/live split and cleanup discipline in *Testing*
below. The `CloudOps` interface makes adding a fake later a pure addition, with no redesign. Worth
noting for that follow-on: `cloudclient.Options` exposes `AllowInsecure` and `GRPCDialOptions`, so an
in-process fake gRPC server over bufconn would be cheap to wire up if the live-only loop proves painful.

## Architecture

```
vault-plugin-temporalcloud/
├── cmd/vault-plugin-secrets-temporalcloud/main.go   plugin entrypoint
├── backend.go                framework.Backend, path wiring, cached client
├── path_config.go            config CRUD + config/rotate-root
├── path_service_accounts.go  service-accounts/<name> CRUD + list
├── path_creds.go             creds/<name> read → mint key, issue lease
├── secret_api_key.go         lease renew + revoke
└── client/
    ├── client.go             CloudOps interface — the seam
    ├── grpc.go               real implementation over go.temporal.io/cloud-sdk/cloudclient
    ├── async.go              poll GetAsyncOperation to terminal state
    └── errors.go             gRPC status → Vault error mapping
```

Module path: `github.com/ausmartway/vault-plugin-secrets-temporalcloud`. Go 1.26.

Dependencies, both current as of 2026-08-06: `go.temporal.io/cloud-sdk` v0.16.0 (Cloud Ops client and
generated protos, bundling Cloud Ops API version v0.19.1) and `github.com/hashicorp/vault/sdk` v0.25.1
(plugin framework).

`client.CloudOps` is the boundary between Vault logic and Temporal Cloud. Everything above it is
plain Vault path handling and never mentions gRPC or async operations; everything below it never
mentions Vault. The interface:

```go
type CloudOps interface {
    CreateServiceAccount(ctx context.Context, spec ServiceAccountSpec) (id string, err error)
    GetServiceAccount(ctx context.Context, id string) (*ServiceAccount, error)
    UpdateServiceAccount(ctx context.Context, id string, spec ServiceAccountSpec) error
    DeleteServiceAccount(ctx context.Context, id string) error
    CreateAPIKey(ctx context.Context, spec APIKeySpec) (*APIKey, error) // APIKey carries the token
    DeleteAPIKey(ctx context.Context, id string) error
    CountAPIKeys(ctx context.Context, serviceAccountID string) (int, error)
}
```

`UpdateServiceAccount` and the delete calls need the resource's current `resource_version` (an etag)
for optimistic concurrency; `grpc.go` fetches it internally rather than leaking it into the interface.

### Storage

Two entry types under the mount:

- `config` — `{address, api_key, api_key_id, admin_service_account_id, root_key_ttl}`
- `service-account/<name>` — `{sa_id, account_role, namespace_access, description, ttl, max_ttl}`

Note the storage prefix is singular (`service-account/`) while the API path is plural
(`service-accounts/`), following the convention in Vault's own engines. They are deliberately
distinct strings, not a typo.

The Temporal Cloud `sa_id` is the only durable link between Vault and Temporal Cloud. The Vault name
is our handle for it. API keys are never stored — Vault holds only the key ID, in the lease's internal
data, which is all revocation needs.

## Path surface

```bash
# ── setup, once ────────────────────────────────────────────────
vault write temporalcloud/config \
    api_key="tmprl_sk_bootstrap..." \
    admin_service_account_id="a1b2c3..." \
    api_key_id="k-bootstrap" \
    address="saas-api.tmprl.cloud:443" \
    root_key_ttl=2160h

vault write -f temporalcloud/config/rotate-root

# ── manage service accounts ────────────────────────────────────
vault write temporalcloud/service-accounts/prod-workers \
    account_role=developer \
    namespace_access="prod.acct1=write,staging.acct1=read" \
    description="Vault-managed workers" \
    ttl=1h max_ttl=8h

vault list   temporalcloud/service-accounts
vault read   temporalcloud/service-accounts/prod-workers
vault delete temporalcloud/service-accounts/prod-workers

# ── consume ────────────────────────────────────────────────────
vault read temporalcloud/creds/prod-workers
```

### `config`

| Field | Required | Default | Notes |
| --- | --- | --- | --- |
| `api_key` | yes | — | Service-account API key with Global Admin. Write-only; never returned on read. |
| `admin_service_account_id` | yes | — | The SA owning `api_key`. See below. |
| `api_key_id` | no | — | ID of `api_key`. Lets `rotate-root` delete the key it replaces. |
| `address` | no | `saas-api.tmprl.cloud:443` | Override for PrivateLink / non-production. |
| `root_key_ttl` | no | `2160h` (90d) | Expiry for keys minted by `rotate-root`. Max 2 years. |

`admin_service_account_id` is required because the Cloud Ops API has no whoami: given only a token,
Vault cannot learn which identity owns it, and `rotate-root` must mint against that exact service
account. Writing `config` validates both facts in one call — `GetServiceAccount(admin_service_account_id)`
succeeding proves the key works *and* that the ID is correct.

`api_key_id` is optional because the bootstrap key's ID is not derivable from its token. When absent,
`rotate-root` succeeds but logs a warning that the previous key must be deleted by hand; once Vault
has rotated once it knows every subsequent key's ID and cleanup is automatic.

The root credential must be a **service-account** key, not a user key, because `CreateApiKey` only
supports service-account owners — a user-owned root key cannot be rotated by this engine.

### `config/rotate-root`

1. Load `config`.
2. `CreateAPIKey(owner_id=admin_service_account_id, owner_type=service-account,
   display_name="vault-root-<unix-timestamp>", expiry_time=now+root_key_ttl)`.
3. Verify the new key before trusting it: build a client with it and call `GetServiceAccount`.
4. Write the new key and its ID to `config`.
5. Delete the previous key by ID. If `api_key_id` was unknown, log a warning instead.

Ordering matters: verify before storing, and store before deleting the old key. A failure at any step
leaves a working configuration.

### `service-accounts/<name>`

| Field | Required | Default | Notes |
| --- | --- | --- | --- |
| `account_role` | yes | — | One of `owner`, `admin`, `developer`, `finance-admin`, `read`, `metrics-read`. |
| `namespace_access` | no | — | Comma-separated `namespace=permission`; permission ∈ `admin`, `write`, `read`. |
| `description` | no | `"Managed by Vault mount <mount>"` | Shows in the Temporal Cloud UI. |
| `ttl` | no | `1h` | Default lease TTL for keys from this SA. |
| `max_ttl` | no | `24h` | Lease ceiling; also sets the Temporal-side key expiry. See below. |

Create calls `CreateServiceAccount` and stores the returned ID. Writing to an existing entry calls
`UpdateServiceAccount`; changing only `ttl`/`max_ttl` touches storage alone and makes no API call.
Delete calls `DeleteServiceAccount`, which invalidates that SA's keys in Temporal Cloud — outstanding
Vault leases become no-ops, and their revocation is treated as successful.

Read returns the spec and `sa_id`. It never returns a key, because keys are not stored.

### `creds/<name>`

Read-only. Returns `api_key`, `api_key_id`, `service_account_id`, `service_account_name`, `expires_at`,
under a Vault lease with `ttl` / `max_ttl` from the service-account entry.

## Credential lifecycle

```
vault read creds/prod-workers
  │
  ├─ 1. load service-account/prod-workers            (missing → 400, clear message)
  ├─ 2. CountAPIKeys(sa_id) ≥ 20 → fail fast, see below
  ├─ 3. CreateAPIKey{ owner_id: sa_id,
  │                   owner_type: service-account,
  │                   display_name: "vault-prod-workers-<random8>",
  │                   description:  "Managed by Vault mount temporalcloud/",
  │                   expiry_time:  now + max_ttl + 10m }   ← max_ttl, not ttl
  │     └─ poll GetAsyncOperation → SUCCEEDED; token is in the response
  └─ 4. framework.Secret{ ttl, max_ttl, internal: {api_key_id, sa_name} }

renew  → extend the lease, capped at max_ttl. No Cloud Ops call.
revoke → DeleteAPIKey(api_key_id). NotFound treated as success.
```

The display name uses a random suffix rather than the lease ID because Vault assigns the lease ID
*after* the handler returns its `Secret` — the ID does not exist at the moment the key is created.
Correlating a Temporal Cloud key back to a Vault lease is therefore done through the key ID, which
Vault stores in the lease's internal data, not through the display name.

### The 24-hour expiry floor

Live testing on 2026-08-06 revealed that Temporal Cloud refuses to mint an API key expiring less
than 24 hours from now. This is undocumented, and it invalidates the original rule below that the
key's expiry simply tracks `max_ttl + grace`: any `max_ttl` under roughly 23h50m made every mint
fail outright. The spec's own `max_ttl=8h` example and the demo's `30m` would both have been
rejected.

The engine therefore floors the expiry:

```go
expiry := now.Add(max(entry.MaxTTL+apiKeyExpiryGrace, minimumAPIKeyExpiry+apiKeyExpiryGrace))
```

**This does not lengthen how long a credential is usable.** The engine's protection comes from
*deleting the key when the lease ends*, not from the key's nominal expiry. A 15-minute lease still
means the key is deleted after 15 minutes, and operators keep full freedom over `ttl` and `max_ttl`.

What it does weaken is the fallback described below. The expiry exists so a key orphaned by a Vault
failure — crash, storage loss, mount deleted — eventually self-destructs on its own. That window was
one `max_ttl`; it is now at least 24 hours. An orphaned key can outlive its lease ceiling by up to a
day. That is a real reduction in defence-in-depth and it is accepted deliberately, because the
alternative is worse.

Rejected alternative: require `max_ttl >= 24h`. It keeps the fallback tight and preserves the
invariant that key expiry equals the lease ceiling, but it takes away the operator's ability to cap
a lease below a day, and it undercuts the short-lived-credential story the engine exists to tell.

### Why the Temporal-side expiry is at least `max_ttl + 10m`

This is the load-bearing detail of the lifecycle.

Setting the key's expiry to the *lease* TTL would break renewal: the key would die at 1h while Vault
extended the lease toward 8h, leaving a live lease holding a dead credential. Setting it to
`max_ttl + grace` instead means renewal never has to touch Temporal Cloud at all — the key already
outlives every lease extension Vault can grant.

It also buys a safety property: if Vault ever loses the lease — crash, storage loss, mount deleted —
the key still self-destructs shortly after its maximum possible lifetime. No orphaned key outlives one
`max_ttl` window. Because `max_ttl` is bounded by Temporal Cloud's 2-year key maximum, `max_ttl + 10m`
must also be validated against it at write time.

### The 20-key ceiling

Temporal Cloud permits 20 non-expired API keys per service account, so this engine supports at most
20 concurrent leases per `service-accounts/<name>` entry. Revoking a lease deletes the key and frees
the slot, so the limit is on concurrency, not on issuance rate.

The engine checks before minting and fails with an actionable message rather than surfacing a raw
`ResourceExhausted`:

```
Error: service account "prod-workers" has 20 of 20 permitted API keys in use.
Temporal Cloud allows 20 non-expired keys per service account. Revoke leases,
lower ttl (currently 1h), or create an additional service account.
```

The README documents the ceiling prominently, including the arithmetic: concurrent consumers must
stay under 20 per service account, and lease revocation — not just expiry — is what returns capacity.

## Error handling

**Async operations.** `async.go` polls `GetAsyncOperation` on a 1s interval with a 60s deadline until
the operation reaches `FULFILLED`. The deadline sits under Vault's 90s default request timeout so the
client gives up first and the operator sees this engine's error rather than a generic gateway timeout.
`FAILED`, `CANCELLED`, and `REJECTED` are terminal errors and surface the operation's `failure_reason`.

Idempotency and retries are **not** implemented here. The SDK's default interceptor already assigns
`async_operation_id` on every write and retries retryable failures with exponential backoff and
jitter, up to 7 attempts. Re-implementing either would fight the SDK.

**gRPC status mapping**, so operators see causes rather than codes:

| gRPC status | Surfaced as |
| --- | --- |
| `NotFound` during revoke | Success — the key already expired or was deleted out of band |
| `NotFound` elsewhere | 400 — the service account ID is wrong or the SA was deleted in Temporal Cloud |
| `PermissionDenied` | 400, naming the likely cause: the root key's SA lacks Global Admin |
| `InvalidArgument` | 400, passing Temporal Cloud's message through verbatim |
| `ResourceExhausted` | 400; the cap pre-check catches the common case first |
| `Unavailable`, `DeadlineExceeded` | 500 — retryable |

**Partial failures.** Two windows where Vault storage and Temporal Cloud can disagree:

- *Service account created, storage write failed.* Issue a best-effort compensating
  `DeleteServiceAccount`. If that also fails, log the orphaned `sa_id` at error level so an operator
  can clean it up. Nothing leaks silently.
- *API key created, lease creation failed.* The key orphans, but `expiry_time = max_ttl + 10m` already
  bounds the exposure to a single maximum lifetime.

**Root key expiry is the sharp edge.** Because every Temporal Cloud key expires, failing to re-run
`rotate-root` within `root_key_ttl` leaves the mount inert until an operator writes `config` with a
fresh hand-made key. Recoverable, and loud rather than silent — but it goes in the README as a warning,
not a footnote, and is the reason `rotate-root` exists at all.

## Security notes

An operator with write access to `service-accounts/*` can create a service account with
`account_role=owner` and then mint keys for it — a privilege-escalation path through Vault into
Temporal Cloud.

This design deliberately does **not** add an `allowed_account_roles` allowlist to guard it. Vault
policy is already the access-control layer for path access, and a second overlapping mechanism invites
drift between the two. Instead the README states the operational requirement directly: protect
`temporalcloud/service-accounts/*` with policy so only platform operators can write it, and grant
applications only `read` on their specific `creds/<name>`.

Other properties worth stating:

- API key tokens are never written to Vault storage. Only the key ID is, in lease internal data.
- `config` read never returns `api_key`.
- Every key Vault mints carries an independent expiry, so a lost lease cannot produce an
  indefinitely-valid credential.

## Testing

Split by whether a test needs credentials. Most of the logic does not, which keeps the development
loop fast despite integration tests being live-only.

**Fast, no network, table-driven:**

- `namespace_access` parsing and validation — well-formed input, and every malformed shape
  (missing `=`, empty namespace, unknown permission, duplicate namespace)
- Cap check — boundaries at 19, 20, 21 keys
- TTL math — `ttl`/`max_ttl` defaults, `ttl > max_ttl` rejection, `expiry = max_ttl + grace`,
  rejection when that exceeds Temporal Cloud's 2-year maximum
- `account_role` enum validation
- gRPC status → Vault response mapping, per row of the table above

**Live, requires `TEMPORAL_CLOUD_API_KEY` and `TEMPORAL_CLOUD_ADMIN_SA_ID`:**

- `config` write validates against a real `GetServiceAccount`; bad ID and bad key both rejected
- `config/rotate-root` — new key authenticates, old key is gone
- Service account create / read / update / delete / list
- `creds/<name>` — minted key authenticates against Temporal Cloud, then revoke, then the key is gone
- Renewal extends the lease without a Cloud Ops call, and stops at `max_ttl`

Path-level tests drive the backend in-process through `b.HandleRequest` with inmem storage, so no
Vault binary is needed.

**Debris control**, since a mid-flight failure leaves real Temporal Cloud resources:

- Every test names resources `vault-acctest-<random>`, making orphans identifiable at a glance.
- `t.Cleanup` is registered **immediately** after each create, before any assertion that could fail.
- `make sweep` lists service accounts matching the test prefix and deletes them, for manual recovery.

## Developer experience

Because this is customer-facing demo material, the repository ships:

- `make build` — compiles the plugin binary and prints its SHA256 for registration
- `make dev` — builds, starts `vault server -dev` with the plugin registered and the mount enabled;
  one command from clone to a working demo
- `make test` — fast tests only
- `make test-live` — live tests, failing with a clear message if credentials are absent
- `make sweep` — delete leftover test resources
- `README.md` — what problem this solves, setup, every path documented with examples, the 20-key
  ceiling, the `rotate-root` warning, and the policy guidance from *Security notes*
- `examples/` — a worked end-to-end walkthrough: configure, create a service account, read creds,
  connect a worker with the key, watch the lease expire and the key vanish

## Success criteria

1. `make dev` yields a working mount against a real Temporal Cloud account.
2. `vault read temporalcloud/creds/<name>` returns a key that authenticates to Temporal Cloud.
3. Revoking the lease deletes the key; the same key then fails to authenticate.
4. `config/rotate-root` replaces the root key, the new one works, and the old one is deleted.
5. At 20 live keys, `creds/<name>` fails with the actionable message rather than a raw gRPC error.
6. Fast tests pass with no credentials present.
7. `make sweep` leaves no `vault-acctest-` resources in the account.
