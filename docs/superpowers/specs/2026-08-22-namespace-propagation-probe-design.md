# Namespace propagation probe

**Date:** 2026-08-22
**Status:** Approved, not yet implemented

## Problem

Temporal Cloud distributes API keys asynchronously. A key that the Cloud Ops
API reports as created is not yet accepted by every namespace frontend: the key
and the permission set it carries have to reach the cells first. A worker that
takes a credential straight from Vault and connects can be rejected with
`Unauthenticated` or `PermissionDenied` for as long as that propagation takes.

The engine currently returns the credential the moment the control plane
acknowledges it, so that rejection window is invisible to Vault and lands on
the caller.

## What exists today, and why it is not enough

`CreateAPIKey` finishes by calling `confirmAPIKeyExists`
(`client/confirm.go:212`), which polls `GetApiKey` every 500ms for up to 15s
until the key is readable. `pathCredsRead` (`path_creds.go:88`) then builds the
response.

That read-back is against `saas-api.tmprl.cloud` — the control plane. It proves
Temporal Cloud has recorded the key. It says nothing about whether the
namespace frontends in the cells will accept it, because those are a different
plane reached over a different endpoint. The gap this spec closes is exactly
that: control-plane existence is not data-plane usability.

## Decisions

These were settled during design and are not reopened by the implementation:

1. **Probe the data plane.** Dial namespace frontends, not the Cloud Ops API.
2. **Probe every namespace in `namespace_access`, in parallel.** Validate
   against exactly the cells the caller was granted, not a representative
   sample. Latency is the slowest cell, not the sum.
3. **A timeout returns the credential with a warning.** The probe is advisory.
   It never fails a credential request and never deletes a minted key.
4. **Opt in per entry, defaulting off.** No behaviour change for any existing
   mount until an operator asks for it.
5. **Approach A: raw `workflowservice` stubs, probing with
   `DescribeNamespace`.** `go.temporal.io/api` is already vendored as an
   indirect dependency; this promotes it to a direct require and adds no new
   module.

### Why `DescribeNamespace` rather than `GetSystemInfo`

What propagates across cells is not only the key but the key's permission set.
`GetSystemInfo` proves a frontend accepts the token. `DescribeNamespace` proves
the token is accepted *and* carries the namespace grant the entry promised,
which is what a worker actually needs. The weaker probe can pass while the
grant a worker depends on has not landed.

### Why not the Temporal Go SDK

`go.temporal.io/sdk`'s `client.DialContext` performs a `GetSystemInfo`
handshake while connecting, so a successful dial would itself be a probe, with
endpoint, TLS, and auth header correct by construction. It was rejected because
it adds a substantially heavier direct dependency and still yields only the
weaker signal — reaching the strong one means making the `DescribeNamespace`
call anyway, which the vendored stubs can already do.

The cost of that choice is that this engine hand-rolls the auth wiring, and a
wrong metadata key fails identically to an unpropagated namespace. The live
test in the testing section exists to catch precisely that.

## Non-goals

- Probing entries that grant access through `account_role` alone. See the
  account-role-only case below: these are skipped with a warning, not probed
  against an invented namespace.
- Retrying or re-minting a key that fails to propagate. A timeout warns; it
  does not mint a second key.
- Any change to `temporalcloud/config`, to renewal, or to revocation.
- Caching or pooling probe connections. Each probe authenticates as a distinct
  freshly minted key, so there is nothing shareable to pool.

## Design

### 1. Component and seam

A new file `client/probe.go` exports one stateless function:

```go
// ProbeNamespace reports whether a namespace frontend accepts token and
// honours the grant it carries.
func ProbeNamespace(ctx context.Context, token, namespace string) error
```

It dials the namespace endpoint, issues `DescribeNamespace{Namespace:
namespace}`, and closes the connection before returning.

It is deliberately not a method on `CloudOps`. That interface is documented as
the Cloud Ops API wrapper (`client/client.go:1`), and the client behind it is
built from the root credential and shared across requests through
`clientHandle` (`backend.go:100`). A probe authenticates as the newly minted
key — a different credential on every request — so it can never use that
connection.

The backend reaches it through an injected field, mirroring `newClient`
(`backend.go:47`):

```go
probeNamespace func(ctx context.Context, token, namespace string) error
```

defaulting to `client.ProbeNamespace` in `Backend()`. A plain func field rather
than an interface: one implementation, one test fake, nothing that warrants a
named type.

### 2. Endpoint construction

Temporal Cloud's namespace ID is already `<namespace>.<account>`, and the
recommended gRPC endpoint is `<namespace>.<account>.tmprl.cloud:7233`
([cloud/namespaces](https://docs.temporal.io/cloud/namespaces#access-namespaces)).
The keys of `namespace_access` are exactly that ID — `prod.acct1` — so the
endpoint is `<key> + ".tmprl.cloud:7233"` with no account lookup and no new
configuration.

The namespace endpoint is preferred over a regional endpoint because it routes
to whichever region is active, so a namespace with High Availability enabled
does not need the engine to know where it currently lives.

### 3. Data flow in `pathCredsRead`

Inserted after `CreateAPIKey` returns successfully and before the response is
built:

1. If `!entry.VerifyPropagation`, return exactly as today.
2. If `len(entry.NamespaceAccess) == 0`, skip the probe and attach the
   account-role-only warning.
3. Otherwise start one goroutine per namespace under a `sync.WaitGroup` and
   collect a verdict for each. No early cancellation on the first failure: the
   probes run concurrently regardless, and cancelling would leave the operator
   with an incomplete picture of which namespaces are behind.
4. Attach one `resp.AddWarning` per namespace that did not confirm.

The credential is returned in every one of these cases. The probe never changes
what is minted, leased, or stored.

### 4. Timeout budget

The engine already spends up to 60s awaiting the async operation
(`operationTimeout`, `client/async.go:20`) and up to 15s on the control-plane
read-back (`confirmTimeout`, `client/confirm.go:50`). That is 75s of a 90s
default Vault request timeout, leaving roughly 15s. `client/async.go:17`
records that this budget exists so the engine's own error surfaces rather than
Vault timing out underneath it.

A fixed constant would therefore be wrong: it would spend headroom the earlier
stages may already have consumed. The budget is derived from the live deadline
instead:

```go
budget := min(maxProbeTimeout, timeUntil(ctx.Deadline()) - probeSafetyMargin)
```

with `maxProbeTimeout = 10 * time.Second` and `probeSafetyMargin = 5 *
time.Second`. If the resulting budget is under one second, the probe is skipped
and warned about rather than attempted — the key is already minted, and a Vault
request that times out underneath the handler would strand it without a lease.

When the context carries no deadline at all — which Vault does not do in
practice, but unit tests driving the backend directly do — the budget is
`maxProbeTimeout`. The subtraction is skipped rather than applied to a zero
deadline, which would otherwise make every test skip the probe.

Retries within the budget use a 500ms interval, matching `confirmPollInterval`.

### 5. Error classification

A namespace that has not received the key yet and a namespace that will never
accept it both answer `Unauthenticated` or `PermissionDenied`. The probe cannot
tell them apart, so statuses are classified by whether waiting could plausibly
help:

| gRPC status | Treatment |
| --- | --- |
| `OK` | Confirmed |
| `Unauthenticated`, `PermissionDenied`, `NotFound` | Retry until the budget elapses — this is the propagation window |
| `Unavailable`, `DeadlineExceeded` | Retry until the budget elapses — transient |
| Anything else | Stop immediately and warn with the status |

Three distinct warnings, because a warning that means several different things
is one operators learn to ignore:

- **did not confirm within Ns** — propagation may still be in flight; retrying
  the connection is the right response.
- **refused the key**, naming the gRPC status — the likely cause is a namespace
  without "Allow API key authentication" enabled, which will never pass. This
  is a configuration error, not a delay.
- **skipped** — either the entry has no `namespace_access` to verify, or no
  budget remained.

Two namespace configurations fail permanently rather than transiently, and the
"refused" wording exists for them: a namespace that only allows mTLS, and a
namespace running both mTLS and API key auth, which is pre-release and does not
support authenticating with an API key to a namespace endpoint
([cloud/namespaces](https://docs.temporal.io/cloud/namespaces#access-namespaces)).

### 6. Configuration surface

One new field on `service-accounts/<name>`:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `verify_propagation` | bool | `false` | Before returning a credential, verify that every namespace in `namespace_access` accepts the new key. Adds latency; warns rather than fails. |

Stored on `serviceAccountEntry` (`path_service_accounts.go:32`) as
`json:"verify_propagation"` and echoed on read. `temporalcloud/config` is
unchanged.

Operators must be told in the README that this requires egress from the Vault
node to `*.tmprl.cloud:7233`, which is a different destination from the
`saas-api.tmprl.cloud:443` the engine otherwise needs, and that it should only
be enabled for namespaces with API key authentication allowed.

### 7. Testing

- **Unit, fake prober:** flag off means no probe call; empty `namespace_access`
  produces the skip warning and no probe call; two namespaces where one
  confirms and one times out produces exactly one warning naming the right
  namespace; an exhausted budget produces the skip warning.
- **Unit, no network:** a table mapping gRPC status codes to
  retry / fail-fast / success, asserting the classification above.
- **Live, gated:** `TestLive_ProbePropagation` mints a real key and probes a
  real namespace. It requires a new `TEMPORAL_CLOUD_TEST_NAMESPACE` alongside
  the existing `TEMPORAL_CLOUD_API_KEY` and `TEMPORAL_CLOUD_ADMIN_SA_ID`
  (`acceptance_test.go:33`), and skips cleanly when unset, matching how
  `TestLive_RotateRoot` and `TestLive_KeyCapacity` gate themselves.

The live test is load-bearing rather than supplementary. A wrong bearer-token
metadata key produces the same `Unauthenticated` as an unpropagated namespace,
so every mock-based test would pass against a probe that can never succeed.

## Risks to resolve during implementation

Both are answered by running the live test; neither blocks writing the code.

1. **Is a 10s ceiling useful?** Nobody has measured the actual propagation lag
   on this account. If the observed lag routinely exceeds the budget, the
   feature degrades to a warning generator and `maxProbeTimeout` — or the
   `operationTimeout`/`confirmTimeout` split above it — needs revisiting.
2. **Is `DescribeNamespace` authorized for every `account_role` the engine
   permits?** A `metrics-read` service account may not carry namespace read
   permission, in which case its probe would report "refused" permanently. If
   so, those roles fall back to `GetSystemInfo` or are documented as
   unsupported for `verify_propagation`.
