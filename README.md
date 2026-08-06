# vault-plugin-secrets-temporalcloud

A HashiCorp Vault secrets engine that issues short-lived Temporal Cloud API
keys as Vault dynamic secrets. It provisions Temporal Cloud service accounts,
mints API keys bound to Vault leases, and deletes each key the moment its
lease ends.

This has been proven against a real Temporal Cloud account — every path below
is exercised by a live acceptance test suite, not mocked out.

## The problem

Temporal Cloud API keys are a static credential with a few sharp edges:

- The token is shown **once**, at creation. If you lose it, you cannot
  retrieve it — you delete the key and mint another.
- Every key **must** expire, with a maximum lifetime of two years. Nothing is
  permanent, so someone has to rotate every key eventually.
- Rotating one by hand is a four-step dance: mint the replacement, wire it
  into whatever holds the old one, verify the new one works, delete the old
  one. Skip step three and you can lock yourself out; skip step four and the
  old key lingers as a standing credential nobody is watching.
- The key has no lifecycle tie to the workload using it. A worker that gets
  torn down does not take its API key down with it — the key just sits there,
  valid, until someone remembers to clean it up.

Vault's dynamic-secrets model solves exactly this: a credential minted for a
lease, and deleted when that lease ends. This engine puts Temporal Cloud API
keys behind that model.

## Quick start

```bash
make dev
```

builds the plugin and starts Vault in `-dev` mode with it mounted at
`temporalcloud/`. In another terminal, with `TEMPORAL_CLOUD_API_KEY` and
`TEMPORAL_CLOUD_ADMIN_SA_ID` set to a Global-Admin-owned service account key:

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
./examples/demo.sh
```

walks the full lifecycle: configure, rotate the bootstrap key away, create a
service account, mint a credential, revoke it, tear down. Also set
`TEMPORAL_CLOUD_API_KEY_ID` to the bootstrap key's own ID if you have it —
without it the rotation step cannot delete the key you pasted, and says so.
See [`examples/README.md`](examples/README.md) for what to look at in the
Temporal Cloud UI at each step.

## Paths

### `config`

Write-once-then-update configuration: the root credential and how to reach
Temporal Cloud.

| Field | Description |
| --- | --- |
| `api_key` | Required. A Temporal Cloud API key owned by a service account with the Global Admin (or Account Owner) role. Never returned by a read. |
| `admin_service_account_id` | Required. The ID of the service account that owns `api_key`. The Cloud Ops API has no "whoami" call — given only a token, there is no way to discover which identity it belongs to, and `rotate-root` needs that identity to mint a replacement. |
| `api_key_id` | Optional. The ID of the key given in `api_key`, so `rotate-root` can delete the key it replaces. Not knowable for a hand-issued bootstrap key unless you looked it up yourself. |
| `address` | Cloud Ops API host:port. Defaults to `saas-api.tmprl.cloud:443`. Override for PrivateLink or non-production endpoints. |
| `root_key_ttl` | Expiry applied to keys minted by `rotate-root`. Defaults to 90 days. Minimum 24 hours, maximum two years — Temporal Cloud enforces both, and a value outside them is rejected here at write time rather than by Temporal Cloud at rotation time. The 24-hour minimum is undocumented by Temporal Cloud; the usual way to run into it is setting a short `root_key_ttl` to demo rotation quickly. |

Writing `config` validates the credential immediately by calling
`GetServiceAccount` on `admin_service_account_id` — you find out now if the
key is wrong or the ID doesn't match, not on the first `creds/` read.

```bash
vault write temporalcloud/config \
    api_key="tcld_..." \
    admin_service_account_id="svcacct-abc123"
```

**The root credential must be a service-account key, not a user key.**
Temporal Cloud's `CreateApiKey` call only supports service-account owners —
there is no way to mint a replacement key for a user identity. If you hand
this engine a user-owned key, `rotate-root` has nothing it can do, so use a
service account from the start.

### `config/rotate-root`

Write-only, no fields. Mints a new API key on the configured admin service
account, verifies the new key actually works (by reading the admin service
account with it), stores it as the credential, then deletes the key it
replaced.

```bash
vault write -f temporalcloud/config/rotate-root
```

Run this immediately after the first `config` write. Doing so means the
bootstrap key you pasted by hand is destroyed, and the only working root
credential from that point on is one that has never existed outside Vault.

The ordering inside `rotate-root` is deliberate: verify before storing means a
non-working key never becomes the stored credential; store before deleting
means a failure at the last step leaves two working keys rather than zero.
Every intermediate failure leaves the mount usable — worst case you get a
warning that the old key needs manual cleanup, never a bricked mount.

> **Every Temporal Cloud API key expires — including Vault's own.**
> Re-run `config/rotate-root` before `root_key_ttl` (default 90 days)
> elapses. If it expires anyway, the mount stops issuing anything until an
> operator writes `config` again with a fresh, hand-made key. There is no
> automatic recovery from a root key that has actually expired — this engine
> cannot mint a replacement for a key it no longer has one that works.

### `service-accounts/<name>`

Defines a Temporal Cloud service account and the credential policy for keys
issued from it.

| Field | Description |
| --- | --- |
| `account_role` | Required on every write. One of `owner`, `admin`, `developer`, `finance-admin`, `read`, `metrics-read`. |
| `namespace_access` | Namespace permissions as `namespace=permission` pairs (`admin`, `write`, or `read`), e.g. `prod.acct1=write,staging.acct1=read`. |
| `description` | Shown in the Temporal Cloud UI. Defaults to `Managed by Vault mount <mount>`. |
| `ttl` | Default Vault lease TTL for keys issued here. Defaults to 1 hour. |
| `max_ttl` | Maximum lease TTL. Also drives the key's Temporal Cloud-side expiry (see below). Defaults to 24 hours. |
| `force` | Only meaningful on create. If a service account with this name already exists in Temporal Cloud, adopt it instead of failing. See below. |

```bash
vault write temporalcloud/service-accounts/prod-workers \
    account_role=read \
    namespace_access="prod.acct1=write,staging.acct1=read" \
    ttl=15m max_ttl=8h
```

```bash
vault read temporalcloud/service-accounts/prod-workers
```

Deleting the entry deletes the service account in Temporal Cloud, which
invalidates every API key it owns. **Revoke the outstanding leases first:**

```bash
vault lease revoke -prefix temporalcloud/creds/prod-workers
vault delete temporalcloud/service-accounts/prod-workers
```

Deleting the entry while leases are still outstanding leaves those leases
pointing at API keys whose owning service account no longer exists. Vault will
still revoke them on schedule, and revocation is written to treat an
already-absent key as success — but that specific path (revoking a key whose
service account was deleted out from under it) has never been observed against
a live account, so it is not a path to rely on. Revoking first keeps teardown
on behaviour that has been proven.

#### Write semantics — read this before you write here

Two behaviours on this path surprise people, and both of them change live
state in Temporal Cloud, not just what Vault has stored.

**Create requires the full spec. Update merges.** The first write for a
name needs `account_role` at minimum. Every write after that only changes the
fields you actually pass — a field you omit keeps its previously stored
value. So:

```bash
vault write temporalcloud/service-accounts/prod-workers account_role=admin
```

changes only the role; `namespace_access`, `ttl`, `max_ttl`, and
`description` stay exactly what they were. `namespace_access` needs special
handling because "omitted" and "empty" both look like nothing was passed —
`vault write` gives the field no way to distinguish "don't touch this" from
"clear it out." The engine resolves that by checking whether the field was
present in the request at all: omit it entirely to leave namespace access
untouched; pass it explicitly as an empty string to clear it:

```bash
vault write temporalcloud/service-accounts/prod-workers namespace_access=""
```

That reaches Temporal Cloud and revokes every namespace permission the
service account had. It is not a Vault-only bookkeeping change.

**Creating a name that collides fails, unless you force it.** Temporal Cloud
requires service-account names to be unique across all active accounts. If
you write a name that already exists there — created by someone else, by a
previous mount, by hand in the console — the write fails and names the
colliding account's ID:

```
a service account named "prod-workers" already exists in Temporal Cloud (id svcacct-xyz) and
Vault did not create it. Either choose a different name, or re-run with force=true to have Vault
adopt that account and reset its permissions to this specification.
```

`force=true` adopts it: Vault binds its own entry to that existing account
and immediately overwrites its permissions with whatever you specified.

> **State this plainly, because it is easy to miss until it costs someone
> something: an adopted account becomes fully Vault-managed, exactly as if
> Vault had created it from scratch.** `vault delete` on that entry deletes
> the service account in Temporal Cloud — invalidating every API key it
> owns — the same as for any account Vault created itself. If you adopt a
> colleague's service account with `force=true`, you have handed Vault the
> ability to destroy it. `vault read` on the entry shows an `adopted: true`
> field so this is visible after the fact, but nothing stops the delete from
> happening.

### `creds/<name>`

Read-only. Mints a fresh API key on the named service account and returns it
under a Vault lease.

```bash
vault read temporalcloud/creds/prod-workers
```

```
Key                    Value
---                    -----
lease_id               temporalcloud/creds/prod-workers/abc123...
lease_duration         15m
lease_renewable        true
api_key                tcld_...
api_key_id             apikey-...
expires_at             2026-08-07T09:15:00Z
service_account_id     svcacct-abc123
service_account_name   prod-workers
```

The token is in the response **once**. Vault does not store it and cannot
show it to you again — read the path again for a new key. Renewing the lease
is a Vault-only operation; it never calls Temporal Cloud, because the key was
minted with an expiry that already outlives any renewal Vault can grant (see
"How it works" below). Revoking the lease deletes the key in Temporal Cloud.

## The 20-key ceiling

> Temporal Cloud allows **20 non-expired API keys per service account**, so at
> most **20 concurrent leases** can be outstanding per `service-accounts/<name>`
> entry at any moment. Revoking a lease frees a slot immediately; letting one
> expire does too. If a workload needs more than 20 concurrent credentials,
> give it its own service account rather than trying to raise the number —
> there isn't a knob for that on the Temporal Cloud side.

The arithmetic that catches people: a `ttl` of 15 minutes and 40 workers each
holding one lease at a time is fine as long as no more than 20 are alive
simultaneously — but a `ttl` long enough that leases pile up (say, a `ttl` of
8 hours with new workers reading a fresh credential every hour) can hit the
ceiling well before 40 workers exist. The fix is either a shorter `ttl` so old
leases clear out faster, or a second service account to split the load across.

Reading `creds/<name>` when the ceiling is already hit fails with a message
naming the count and what to do:

```
service account "prod-workers" has 20 of 20 permitted API keys in use. Temporal Cloud allows 20
non-expired keys per service account. Revoke leases, lower ttl (currently 15m0s), or create an
additional service account.
```

## Policy guidance

```hcl
# Platform operators: manage service accounts.
path "temporalcloud/service-accounts/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Applications: read their own credentials, nothing else.
path "temporalcloud/creds/prod-workers" {
  capabilities = ["read"]
}
```

`service-accounts/*` is a privilege boundary, not just a management path.
Anyone who can write there can set `account_role=owner` and then read
`creds/<name>` to mint a key with Account Owner access — full control of the
Temporal Cloud account. This engine doesn't add a second allowlist on top of
that; it relies on Vault policy to keep `service-accounts/*` restricted to
whoever should be trusted with that power, and hands `creds/<name>` reads out
far more freely, scoped one path per application.

## Running tests

- `make test` — the fast suite. No credentials, no network, safe to run
  anywhere.
- `make test-live` — the acceptance suite against a real Temporal Cloud
  account. Needs `TEMPORAL_CLOUD_API_KEY` and `TEMPORAL_CLOUD_ADMIN_SA_ID` set
  in the environment (a Global-Admin-owned service account key). This mutates
  real state — it creates and deletes service accounts and API keys — so
  point it at a Temporal Cloud account you're comfortable with that.
- `make sweep` — deletes leftover `vault-acctest-*` resources from a live test
  run that died mid-flight instead of cleaning up after itself.

The live suite reads four environment variables:

| Variable | Required | What it does |
| --- | --- | --- |
| `TEMPORAL_CLOUD_API_KEY` | Yes | The root credential the tests configure the engine with. |
| `TEMPORAL_CLOUD_ADMIN_SA_ID` | Yes | The ID of the service account owning that key. |
| `TEMPORAL_CLOUD_API_KEY_ID` | No | The ID of that key. Without it, `TestLive_RotateRoot` cannot prove the old key was deleted — rotation just warns that it does not know which key to remove, which is the one thing that test exists to check. |
| `TEMPORAL_CLOUD_ADDRESS` | No | Cloud Ops API host:port. Defaults to `saas-api.tmprl.cloud:443`; set it for PrivateLink or a non-production endpoint. |

Two live tests are opt-in beyond the two required env vars, because of what
they do:

- `TestLive_RotateRoot` **deletes the API key currently configured in your
  environment** as part of proving rotation end-to-end. It's gated behind
  `TEMPORAL_CLOUD_ALLOW_ROOT_ROTATION=1` so it never runs by accident.
- `TestLive_KeyCapacity` mints all 20 keys a service account can hold, to
  prove the ceiling is enforced and the error message is right. It's gated
  behind `TEMPORAL_CLOUD_RUN_CAPACITY_TEST=1`.

## How it works

Reading `creds/<name>`:

```
vault read creds/prod-workers
  │
  ├─ 1. load service-accounts/prod-workers            (missing → error naming the path to create)
  ├─ 2. count non-expired API keys on that service account; ≥ 20 → fail with the ceiling message
  ├─ 3. mint an API key on the service account, expiring at max(max_ttl + 10m, 24h + 10m)
  └─ 4. return the key under a Vault lease with ttl / max_ttl from the entry

renew  → extend the lease, capped at max_ttl. No Temporal Cloud call.
revoke → delete the API key. A key already gone (NotFound) counts as success.
```

**Why the Temporal-side expiry tracks `max_ttl`, not `ttl`.** Setting the
key's expiry to the lease's current TTL would break renewal: the key would
die at, say, 1 hour while Vault tried to extend the lease toward an 8-hour
`max_ttl`, leaving a live lease holding a dead credential. Setting it to
`max_ttl` plus a 10-minute grace margin means renewal never needs to touch
Temporal Cloud at all — the key already outlives every extension Vault can
grant — and a key orphaned by a Vault failure (crash, lost storage, a deleted
mount) still self-destructs within one maximum lifetime rather than lingering
forever.

**Why it's `max(max_ttl + 10m, 24h + 10m)`, not just `max_ttl + 10m`.** Live testing
against the real Cloud Ops API found an undocumented rule: Temporal Cloud
refuses to mint an API key expiring less than 24 hours from now. A
`max_ttl` of 30 minutes — a perfectly reasonable lease ceiling — would make
every mint fail outright with an "invalid argument" error naming that
24-hour floor. The engine works around it by flooring the Temporal-side
expiry at 24 hours plus the same 10-minute grace margin when `max_ttl` is
shorter than that.

This is a real, deliberate trade, and worth being straight about:

- **What it does not change:** your Vault lease can still be however short
  you want — `ttl=5m max_ttl=30m` works fine — and the key is *deleted* the
  moment the lease it belongs to ends, regardless of its nominal Temporal
  Cloud expiry. In the normal case (Vault stays up, leases get revoked or
  expire on schedule), a 30-minute `max_ttl` still means a 30-minute-lived
  credential.
- **What it does change:** the fallback. The Temporal-side expiry exists so
  an *orphaned* key — one Vault never got the chance to revoke, because Vault
  crashed, lost its storage, or the mount was deleted — eventually
  self-destructs on its own instead of living forever. That window used to be
  bounded by `max_ttl`; now it's bounded by at least 24 hours regardless of
  how short `max_ttl` is. An orphaned key can now outlive its lease ceiling by
  up to a day. That's a real reduction in defence-in-depth, accepted
  deliberately because the alternative — refusing to let operators set
  `max_ttl` below 24 hours — would take away the ability to cap a lease
  tightly, which undercuts the entire point of a short-lived-credential
  engine.

## Development

```bash
make build       # compile the plugin, print its SHA256
make dev         # build + start Vault in -dev mode with it mounted
make test        # fast tests
make test-live   # live acceptance tests — see "Running tests" above
make sweep       # clean up debris from a failed live run
```
