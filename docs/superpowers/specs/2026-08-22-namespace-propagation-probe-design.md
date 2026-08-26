# Namespace propagation probe

**Date:** 2026-08-22
**Status:** Implemented with post-release amendments

> **Timeout amendment:** External 500-trial benchmarks observed maxima of
> 43.368s and 46.670s. Credential work is therefore bounded to 55s from handler
> entry, five seconds below the Vault API client's default 60s timeout. The
> probe may use the full remainder of that 55s budget, up to 55s; it does not
> subtract a second safety margin. The original 50s/90s-server-deadline design
> below is retained as decision history and is superseded on this point.
>
> **Consistency and interval amendment:** One successful call did not prove that
> subsequent connections would work. The implemented probe now requires five
> consecutive `DescribeNamespace` successes. Every attempt creates and closes
> its own gRPC connection, and any failure resets the count. Attempts were
> initially two seconds apart, then tuned to defaults of 50ms and eight
> successes. Those defaults are mount-configurable through `config/probe` as
> `interval` and `consecutive_successes`; every request uses one stored settings
> snapshot. This supersedes the single-success, dial-once, fixed-interval design
> retained below as history.

## Problem

Temporal Cloud distributes API keys asynchronously. A key that the Cloud Ops
API reports as created is not yet accepted by every namespace frontend: the key
and the permission set it carries have to reach the cells first. A worker that
takes a credential straight from Vault and connects can be rejected with
`Unauthenticated` or `PermissionDenied` for as long as that propagation takes.

The engine currently returns the credential the moment the control plane
acknowledges it, so that rejection window is invisible to Vault and lands on
the caller.

### What the rejection costs the caller

The window does not heal itself on the worker's side. Temporal SDKs treat
`Unauthenticated` and `PermissionDenied` as non-retryable — only codes such as
`Unavailable` are in the retryable set — and they fail eagerly on the initial
connection rather than backing off and reconnecting. A Java worker handed an
unpropagated key dies during `WorkerFactory.start()` with `PERMISSION_DENIED:
Request unauthorized`, and the .NET SDK maintainers state that eager failure on
first connect is deliberate.

So an unpropagated key is not a worker that stalls briefly and recovers. It is
a worker that crashes at startup and stays down until something restarts it.
That is what justifies blocking the credential request while the key
propagates, rather than documenting the race and leaving callers to absorb it.

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

   This was revisited after the SDK behaviour above came to light, and kept.
   The argument against it is real: a caller cannot act on a warning it never
   sees, so the timeout path buys operator visibility rather than caller
   recovery. It stands anyway, because the blocking wait is where the value
   is — a timeout means propagation is slower than any budget that fits under
   Vault's request timeout, and turning that into a hard failure would convert
   a slow cell into an outage for the whole entry. Do not "fix" this into a
   hard failure without measuring the timeout rate first.
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

It dials the namespace endpoint **once**, then retries `DescribeNamespace{
Namespace: namespace}` on that single connection until it succeeds, the
classification below says to stop, or the budget elapses. The connection is
closed before returning.

Dialling once is load-bearing, not an optimisation. gRPC carries the bearer
token as per-RPC metadata, so an authentication rejection does not poison the
connection — the same channel can serve every retry. Re-dialling per attempt
would mean a fresh TLS handshake on every attempt — around twenty-five per
namespace across a full budget — for no benefit. The retry loop therefore
lives inside `ProbeNamespace`, below the dial.

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

with `maxProbeTimeout = 50 * time.Second` and `probeSafetyMargin = 5 *
time.Second`. If the resulting budget is under one second, the probe is skipped
and warned about rather than attempted — the key is already minted, and a Vault
request that times out underneath the handler would strand it without a lease.

When the context carries no deadline at all — which Vault does not do in
practice, but unit tests driving the backend directly do — the budget is
`maxProbeTimeout`. The subtraction is skipped rather than applied to a zero
deadline, which would otherwise make every test skip the probe.

Retries within the budget use `probePollInterval = 2 * time.Second` — its own
constant, deliberately not reusing `confirmPollInterval`. The control-plane
read-back polls at 500ms because it expects to succeed almost immediately and
is racing a 15s ceiling. Cross-cell propagation is a slower phenomenon on a
much longer budget, so polling it four times a second is pointless chatter
against a namespace frontend. At 2s, a full budget is roughly twenty-five
attempts.

#### A 50s ceiling does not fit under Vault's default request timeout

Deliberately so, and the deadline-derived budget is what makes that safe
rather than reckless. Against Vault's 90s default the arithmetic is:

| Case | Async op | Read-back | Remaining | Probe gets |
| --- | --- | --- | --- | --- |
| Typical | ~2s | ~0.5s | ~87s | the full 50s |
| Worst case | 60s | 15s | 15s | 10s |

So `maxProbeTimeout` is a ceiling the probe reaches when the stages above it
were fast, not a duration it reserves. It can never push a request past Vault's
deadline, because it only ever spends what is actually left minus the margin.
The cost of the worst case is a shorter probe, never a killed request — which
matters because a request Vault kills after the key is minted leaves that key
with no lease, alive until its Temporal Cloud expiry of at least 24 hours.

An operator who wants the full 50s available even when the stages above run
long must raise Vault's `default_request_timeout` to at least 130s
(60 + 15 + 50 + 5). This belongs in the README next to the egress requirement.

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

- **did not confirm within Ns** — the budget elapsed while the namespace was
  still answering a retryable code. Propagation may be in flight, so retrying
  the connection is the right first response. This warning also carries the
  permanent-failure hypothesis: see below.
- **stopped early**, naming the gRPC status — the frontend answered something
  no amount of waiting clears. State the status and nothing more; the cause is
  not knowable from here.
- **skipped** — either the entry has no `namespace_access` to verify, or no
  budget remained.

Two namespace configurations reject an API key permanently rather than
transiently: one that only allows mTLS, and one running both mTLS and API key
auth, which is pre-release and does not support authenticating with an API key
to a namespace endpoint
([cloud/namespaces](https://docs.temporal.io/cloud/namespaces#access-namespaces)).

**Both surface as the timeout warning, not the stopped-early one.** An earlier
draft of this section attributed them to a fail-fast path, which contradicted
the table above it: such a namespace answers `PermissionDenied`, and
`PermissionDenied` is retryable precisely because it is indistinguishable from
an unpropagated key. So it is retried until the budget elapses, and lands in
the timeout branch. The mTLS hypothesis therefore belongs in the timeout
wording. The stopped-early warning is left for codes like `Unimplemented` and
`Internal`, where naming the status is the only honest thing to say.

The corollary is that this design cannot distinguish a slow cell from a
namespace that will never accept an API key — both look like a timeout. Telling
them apart needs the namespace's authentication setting, which the Cloud Ops
API does not expose through anything this engine already calls. Naming the
possibility in the warning is the available remedy.

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

1. **What is the actual propagation lag?** The 50s ceiling is chosen to be
   comfortably longer than the lag is believed to be, not measured against it.
   The live test should record how long the probe actually waits. Two outcomes
   change the design: if it routinely lands in single-digit seconds, the
   worst-case 10s floor in the table above is adequate and the README needs no
   `default_request_timeout` advice; if it routinely approaches 50s, then the
   `operationTimeout`/`confirmTimeout` split above the probe is what needs
   revisiting, because no probe ceiling fits under a 90s request otherwise.
2. **Is `DescribeNamespace` authorized for every `account_role` the engine
   permits?** A `metrics-read` service account may not carry namespace read
   permission, in which case its probe would report "refused" permanently. If
   so, those roles fall back to `GetSystemInfo` or are documented as
   unsupported for `verify_propagation`.
