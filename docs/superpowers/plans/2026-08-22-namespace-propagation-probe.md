# Namespace Propagation Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Before returning a freshly minted Temporal Cloud API key, optionally verify that every namespace the caller was granted actually accepts it, so a worker is not handed a key its cell has not received yet.

**Architecture:** A new stateless `client.ProbeNamespace` dials a namespace frontend once over gRPC, authenticates as the new key, and retries `DescribeNamespace` on that single connection until it succeeds or a deadline-derived budget elapses. `pathCredsRead` fans these out across `namespace_access` in parallel behind a per-entry opt-in flag, and attaches a Vault warning for each namespace that did not confirm. The credential is always returned; the probe never fails a request and never deletes a key.

**Tech Stack:** Go 1.26, `go.temporal.io/api/workflowservice/v1` (promoted from indirect to direct), `google.golang.org/grpc`, HashiCorp Vault SDK `framework`/`logical`.

**Spec:** `docs/superpowers/specs/2026-08-22-namespace-propagation-probe-design.md`

## Global Constraints

- **Advisory only.** The probe never returns an error from `pathCredsRead`, never deletes a minted key, and never prevents a lease from being created. Every failure path attaches a warning and continues.
- **Backward compatible by default.** `verify_propagation` defaults to `false`. With it unset, `pathCredsRead` must behave byte-for-byte as it does today and must make zero probe calls.
- **Budget constants:** `client.MaxProbeTimeout = 50 * time.Second` (exported), `probePollInterval = 2 * time.Second`, `probeSafetyMargin = 5 * time.Second`.
- **Budget is deadline-derived**, never a fixed reservation: `min(client.MaxProbeTimeout, timeUntil(ctx.Deadline()) - probeSafetyMargin)`. A context with no deadline yields `client.MaxProbeTimeout`. A budget under one second means skip-and-warn.
- **Dial once per namespace.** The retry loop lives inside `ProbeNamespace`, below the dial. Re-dialling per attempt is a defect, not a style choice.
- **Endpoint format:** `<namespace_access key> + ".tmprl.cloud:7233"`. The map keys are already `<namespace>.<account>`.
- **No new module.** `go.temporal.io/api` is already in `go.mod` as indirect; this promotes it to a direct require. Do not add `go.temporal.io/sdk`.
- **Existing code style:** comments explain *why*, not *what*. Sentinel errors in `client/` never leak `grpc/codes` to callers above the package.

---

### Task 1: Probe a namespace frontend

Creates the data-plane probe. Self-contained: no Vault types, no backend wiring.

**Files:**
- Create: `client/probe.go`
- Create: `client/probe_test.go`
- Modify: `go.mod` (promote `go.temporal.io/api` to a direct require)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `func ProbeNamespace(ctx context.Context, token, namespace string) error`
  - `func namespaceEndpoint(namespace string) string`
  - `func retryableProbeCode(code codes.Code) bool`
  - `const MaxProbeTimeout = 50 * time.Second` — exported; Task 2 and Task 5 both consume it
  - `const probePollInterval = 2 * time.Second` — unexported, used only inside `probe.go`

- [ ] **Step 1: Write the failing tests for endpoint construction and status classification**

These are the two pieces testable without a network. Create `client/probe_test.go`:

```go
package client

import (
	"testing"

	"google.golang.org/grpc/codes"
)

func TestNamespaceEndpoint(t *testing.T) {
	// The namespace_access map key is already <namespace>.<account>, which is
	// exactly what the Temporal Cloud namespace endpoint is built from.
	got := namespaceEndpoint("prod.acct1")
	want := "prod.acct1.tmprl.cloud:7233"
	if got != want {
		t.Fatalf("namespaceEndpoint(%q) = %q, want %q", "prod.acct1", got, want)
	}
}

// A key that has not propagated and a key that will never be accepted answer
// identically, so the classification is about whether waiting could plausibly
// help — not about whether the error looks permanent.
func TestRetryableProbeCode(t *testing.T) {
	tests := []struct {
		name string
		code codes.Code
		want bool
	}{
		{"not propagated yet", codes.Unauthenticated, true},
		{"grant not propagated yet", codes.PermissionDenied, true},
		{"namespace not visible yet", codes.NotFound, true},
		{"transient", codes.Unavailable, true},
		{"transient deadline", codes.DeadlineExceeded, true},
		{"malformed request", codes.InvalidArgument, false},
		{"broken invariant", codes.Internal, false},
		{"not supported", codes.Unimplemented, false},
		{"success is not a retry", codes.OK, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryableProbeCode(tc.code); got != tc.want {
				t.Fatalf("retryableProbeCode(%v) = %v, want %v", tc.code, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./client/ -run 'TestNamespaceEndpoint|TestRetryableProbeCode' -v`

Expected: FAIL to compile with `undefined: namespaceEndpoint` and `undefined: retryableProbeCode`.

- [ ] **Step 3: Write `client/probe.go`**

```go
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	workflowservicev1 "go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Creating an API key and having every Temporal Cloud cell accept it are
// different events. CreateAPIKey confirms the first by reading the key back
// from the Cloud Ops API; this file confirms the second by asking a namespace
// frontend directly, authenticating as the new key.
//
// The distinction matters because an unpropagated key does not degrade
// gracefully on the caller's side. Temporal SDKs treat Unauthenticated and
// PermissionDenied as non-retryable and fail eagerly on the first connection,
// so a worker handed a key its cell has not seen yet dies at startup rather
// than backing off and recovering.
const (
	// MaxProbeTimeout is the ceiling on how long one namespace is given to
	// accept a new key. It is a ceiling, not a reservation: the caller derives
	// the real budget from the remaining request deadline, so a slow
	// CreateAPIKey shortens the probe instead of pushing the request past
	// Vault's timeout.
	MaxProbeTimeout = 50 * time.Second

	// probePollInterval is how often the probe re-asks. It is deliberately
	// slower than confirmPollInterval: that one polls at 500ms because it
	// expects to succeed almost immediately against a 15s ceiling, whereas
	// cross-cell propagation is a slower phenomenon on a much longer budget,
	// and polling a namespace frontend four times a second is pointless
	// chatter.
	probePollInterval = 2 * time.Second
)

// namespaceEndpoint builds the gRPC address for a namespace.
//
// Temporal Cloud's namespace ID is already "<namespace>.<account>", which is
// exactly the form the keys of a service account's namespace_access map take,
// so no account lookup is needed. The namespace endpoint is preferred over a
// regional one because it routes to whichever region is currently active,
// so a namespace with High Availability enabled needs no special handling.
func namespaceEndpoint(namespace string) string {
	return namespace + ".tmprl.cloud:7233"
}

// retryableProbeCode reports whether waiting could plausibly change the answer.
//
// A key that has not propagated yet and a key that will never be accepted both
// answer Unauthenticated or PermissionDenied, and nothing in the response
// distinguishes them. Both are retried: the cost of waiting out the budget on
// a namespace that will never accept the key is a slower response and a
// warning, while the cost of giving up early on one that would have accepted
// it is the false alarm this whole feature exists to prevent.
func retryableProbeCode(code codes.Code) bool {
	switch code {
	case codes.Unauthenticated, codes.PermissionDenied, codes.NotFound:
		// The propagation window itself.
		return true
	case codes.Unavailable, codes.DeadlineExceeded:
		// Ordinary transient failure reaching the frontend.
		return true
	default:
		return false
	}
}

// ProbeNamespace reports whether a namespace frontend accepts token and
// honours the grant it carries.
//
// It returns nil once DescribeNamespace succeeds, and an error if the context
// ends first or the frontend answers with something no amount of waiting will
// clear. Callers treat the error as advisory: this never decides whether a
// credential is issued.
//
// DescribeNamespace is used rather than the cheaper GetSystemInfo because what
// propagates across cells is not only the key but the key's permission set.
// GetSystemInfo would prove the frontend accepts the token; DescribeNamespace
// proves it also carries the namespace grant the caller was promised, which is
// what a worker actually needs.
func ProbeNamespace(ctx context.Context, token, namespace string) error {
	// Dial once and retry the RPC on this connection. gRPC carries the bearer
	// token as per-RPC metadata, so an authentication rejection does not
	// poison the channel — re-dialling per attempt would mean a fresh TLS
	// handshake every probePollInterval for no benefit.
	conn, err := grpc.NewClient(
		namespaceEndpoint(namespace),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})),
	)
	if err != nil {
		return fmt.Errorf("%w: dialling %s: %s", ErrUnavailable, namespace, err)
	}
	defer func() {
		// Close errors are not actionable: the probe is advisory and the
		// connection is being discarded either way.
		_ = conn.Close()
	}()

	svc := workflowservicev1.NewWorkflowServiceClient(conn)
	authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)

	var lastErr error
	for {
		_, err := svc.DescribeNamespace(authCtx, &workflowservicev1.DescribeNamespaceRequest{
			Namespace: namespace,
		})
		if err == nil {
			return nil
		}
		lastErr = err

		if code := status.Code(err); !retryableProbeCode(code) {
			return fmt.Errorf("%w: %s refused the key: %s",
				ErrPermissionDenied, namespace, status.Convert(err).Message())
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %s did not accept the new api key in time; "+
				"the key may not have propagated to its cell yet (last response: %s)",
				ErrUnavailable, namespace, status.Convert(lastErr).Message())
		case <-time.After(probePollInterval):
		}
	}
}
```

- [ ] **Step 4: Promote the dependency and run the tests**

```bash
go get go.temporal.io/api@v1.44.1
go mod tidy
go test ./client/ -run 'TestNamespaceEndpoint|TestRetryableProbeCode' -v
```

Expected: both tests PASS. Confirm `go.temporal.io/api` has moved out of the `// indirect` block in `go.mod`.

- [ ] **Step 5: Verify the whole client package still builds and passes**

Run: `go test ./client/ -v`
Expected: PASS, no regressions.

- [ ] **Step 6: Commit**

```bash
git add client/probe.go client/probe_test.go go.mod go.sum
git commit -m "feat: probe a namespace frontend for a newly minted api key"
```

---

### Task 2: Derive the probe budget from the request deadline

Pure function, no network, no Vault types. Split from Task 1 because the arithmetic is where a subtle bug would strand a key, and it deserves its own review gate.

**Files:**
- Create: `probe_budget.go`
- Create: `probe_budget_test.go`

**Interfaces:**
- Consumes: `client.MaxProbeTimeout` (Task 1).
- Produces: `func probeBudget(ctx context.Context) (time.Duration, bool)` — returns the budget and whether a probe is worth attempting.

- [ ] **Step 1: Write the failing test**

Create `probe_budget_test.go`:

```go
package temporalcloud

import (
	"context"
	"testing"
	"time"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

func TestProbeBudget(t *testing.T) {
	tests := []struct {
		name      string
		deadlineLeft time.Duration // 0 means "no deadline on the context"
		wantOK    bool
		wantAtMost time.Duration
		wantAtLeast time.Duration
	}{
		{
			// Vault always sets a deadline, but tests driving the backend
			// directly do not. Without this branch every unit test would
			// silently skip the probe and pass while testing nothing.
			name:        "no deadline uses the ceiling",
			deadlineLeft:   0,
			wantOK:      true,
			wantAtLeast: client.MaxProbeTimeout,
			wantAtMost:  client.MaxProbeTimeout,
		},
		{
			// The common case: the stages above the probe were fast, so the
			// full ceiling is available.
			name:        "plenty of room yields the ceiling",
			deadlineLeft:   87 * time.Second,
			wantOK:      true,
			wantAtLeast: client.MaxProbeTimeout - time.Second,
			wantAtMost:  client.MaxProbeTimeout,
		},
		{
			// Worst case: a 60s async operation plus a 15s read-back leaves
			// 15s, of which the margin claims 5.
			name:        "little room yields what is left minus the margin",
			deadlineLeft:   15 * time.Second,
			wantOK:      true,
			wantAtLeast: 9 * time.Second,
			wantAtMost:  10 * time.Second,
		},
		{
			// The key is already minted. A request Vault kills underneath us
			// leaves it with no lease, alive until its Temporal Cloud expiry
			// of at least 24 hours — so skip rather than gamble.
			name:      "no room means do not probe",
			deadlineLeft: 3 * time.Second,
			wantOK:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.deadlineLeft > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.deadlineLeft)
				defer cancel()
			}

			got, ok := probeBudget(ctx)
			if ok != tc.wantOK {
				t.Fatalf("probeBudget ok = %v, want %v (budget %s)", ok, tc.wantOK, got)
			}
			if !tc.wantOK {
				return
			}
			if got < tc.wantAtLeast || got > tc.wantAtMost {
				t.Fatalf("probeBudget = %s, want between %s and %s",
					got, tc.wantAtLeast, tc.wantAtMost)
			}
		})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test . -run TestProbeBudget -v`
Expected: FAIL to compile with `undefined: probeBudget` and `undefined: client.MaxProbeTimeout`.

- [ ] **Step 3: Write `probe_budget.go`**

```go
package temporalcloud

import (
	"context"
	"time"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

const (
	// probeSafetyMargin is held back from the request deadline so the probe
	// finishes and its warnings reach the caller, rather than Vault timing out
	// the request mid-probe.
	probeSafetyMargin = 5 * time.Second

	// minUsefulProbeBudget is the point below which probing is not worth
	// starting: one DescribeNamespace round trip would consume it.
	minUsefulProbeBudget = time.Second
)

// probeBudget reports how long the namespace probes may run, and whether
// running them at all is worthwhile.
//
// The budget is derived from the live deadline rather than fixed, because by
// this point the request has already spent up to operationTimeout awaiting the
// async operation and up to confirmTimeout on the read-back — 75s of Vault's
// 90s default between them. A fixed reservation would spend headroom those
// stages may already have consumed, and a request Vault kills after the key is
// minted leaves that key with no lease, alive until its Temporal Cloud expiry
// of at least 24 hours. Deriving it means MaxProbeTimeout is a ceiling reached
// when the stages above ran fast, never a duration claimed up front.
func probeBudget(ctx context.Context) (time.Duration, bool) {
	deadline, ok := ctx.Deadline()
	if !ok {
		// Vault always sets a deadline; tests driving the backend directly do
		// not. Subtracting the margin from a zero deadline here would make
		// every such test skip the probe and pass without exercising it.
		return client.MaxProbeTimeout, true
	}

	budget := time.Until(deadline) - probeSafetyMargin
	if budget < minUsefulProbeBudget {
		return 0, false
	}
	if budget > client.MaxProbeTimeout {
		budget = client.MaxProbeTimeout
	}
	return budget, true
}
```

- [ ] **Step 4: Run the tests**

Run: `go test . -run TestProbeBudget -v && go test ./client/ -v`
Expected: PASS for both.

- [ ] **Step 5: Commit**

```bash
git add probe_budget.go probe_budget_test.go
git commit -m "feat: derive the namespace probe budget from the request deadline"
```

---

### Task 3: Add the `verify_propagation` field to service account entries

Storage and API surface only. No probing yet — this task ends with the flag persisted, merged correctly on update, and echoed on read.

**Files:**
- Modify: `path_service_accounts.go:32-51` (add the struct field), `path_service_accounts.go:60-98` (add the field schema), `path_service_accounts.go:155-225` (merge on update, set on the entry), `path_service_accounts.go:379-389` (echo on read)
- Test: `path_service_accounts_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `serviceAccountEntry.VerifyPropagation bool` with JSON tag `verify_propagation`.

- [ ] **Step 1: Write the failing test**

Append to `path_service_accounts_test.go`:

```go
// The flag defaults off so enabling the feature is always a deliberate act:
// an existing mount upgraded to this version must behave exactly as before.
func TestServiceAccount_VerifyPropagationDefaultsOff(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "developer",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read service account: err=%v resp=%v", err, resp)
	}

	if got := resp.Data["verify_propagation"]; got != false {
		t.Fatalf("verify_propagation = %v, want false", got)
	}
}

// Same merge rule as ttl, max_ttl, and description: an update that does not
// mention the field must not silently reset it. Without this, a write that
// only changes ttl would turn the probe off.
func TestServiceAccount_VerifyPropagationSurvivesUnrelatedUpdate(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role":       "developer",
		"verify_propagation": true,
	})
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "developer",
		"ttl":          "30m",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read service account: err=%v resp=%v", err, resp)
	}

	if got := resp.Data["verify_propagation"]; got != true {
		t.Fatalf("verify_propagation = %v after an unrelated update, want true", got)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test . -run 'TestServiceAccount_VerifyPropagation' -v`
Expected: FAIL — `verify_propagation = <nil>, want false`.

- [ ] **Step 3: Add the struct field**

In `path_service_accounts.go`, inside `serviceAccountEntry` after `Adopted`:

```go
	// VerifyPropagation makes creds/<name> wait for every namespace in
	// NamespaceAccess to accept a newly minted key before returning it.
	// Defaults off: it costs a round trip per namespace and needs egress from
	// the Vault node to the namespace frontends, which not every deployment
	// has.
	VerifyPropagation bool `json:"verify_propagation"`
```

- [ ] **Step 4: Add the field schema**

In the `Fields` map, after the `force` entry:

```go
			"verify_propagation": {
				Type: framework.TypeBool,
				Description: "Before returning a credential, verify that every namespace in " +
					"namespace_access accepts the newly minted key. Temporal Cloud distributes keys " +
					"asynchronously, so a key the Cloud Ops API reports as created is not yet accepted " +
					"everywhere; a worker handed one fails at startup rather than retrying. This adds a " +
					"round trip per namespace and requires egress from the Vault node to " +
					"<namespace>.tmprl.cloud:7233. On timeout the credential is still returned, with a " +
					"warning naming the namespace. Defaults to false.",
			},
```

- [ ] **Step 5: Merge on update and set on the entry**

In `pathServiceAccountWrite`, alongside the other `GetOk` checks near line 158:

```go
	_, verifyPropagationSet := d.GetOk("verify_propagation")
```

Then alongside the other merge blocks, before `entry := &serviceAccountEntry{`:

```go
	// Same merge rule as ttl and description: an update that does not mention
	// the field leaves it alone, so changing ttl cannot silently disable the
	// probe.
	verifyPropagation := d.Get("verify_propagation").(bool)
	if existing != nil && !verifyPropagationSet {
		verifyPropagation = existing.VerifyPropagation
	}
```

And add the field to the literal:

```go
	entry := &serviceAccountEntry{
		AccountRole:       accountRole,
		NamespaceAccess:   namespaceAccess,
		Description:       description,
		TTL:               ttl,
		MaxTTL:            maxTTL,
		VerifyPropagation: verifyPropagation,
	}
```

- [ ] **Step 6: Echo it on read**

In `pathServiceAccountRead`'s response `Data` map:

```go
			"verify_propagation": entry.VerifyPropagation,
```

- [ ] **Step 7: Run the tests**

Run: `go test . -run 'TestServiceAccount' -v`
Expected: PASS, including the pre-existing service account tests.

- [ ] **Step 8: Commit**

```bash
git add path_service_accounts.go path_service_accounts_test.go
git commit -m "feat: add verify_propagation to service account entries"
```

---

### Task 4: Fan out the probes and warn from creds/<name>

Wires Tasks 1–3 together. This is the task that changes observable behaviour.

**Files:**
- Modify: `backend.go:41-51` (add the injected field), `backend.go:64-70` (wire the default)
- Modify: `path_creds.go:117-145` (call the fan-out, attach warnings)
- Create: `path_creds_probe.go` (the fan-out and warning wording)
- Test: `path_creds_test.go`

**Interfaces:**
- Consumes: `client.ProbeNamespace`, `probeBudget`, `serviceAccountEntry.VerifyPropagation`.
- Produces: `func (b *backend) verifyPropagation(ctx context.Context, entry *serviceAccountEntry, token string) []string` — returns warning strings, empty when everything confirmed.

- [ ] **Step 1: Write the failing tests**

Append to `path_creds_test.go`:

```go
// The flag is off by default, and an existing mount must not start making
// network calls to namespace frontends because it upgraded.
func TestCreds_NoProbeWhenFlagOff(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	stub.createAPIKeyFn = func(context.Context, client.APIKeySpec) (*client.APIKey, error) {
		return &client.APIKey{ID: "key-1", Token: "tmprl_sk_minted"}, nil
	}
	withStubClient(b, stub)

	probed := 0
	b.probeNamespace = func(context.Context, string, string) error {
		probed++
		return nil
	}

	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role":     "developer",
		"namespace_access": "prod.acct1=write",
	})

	resp := mustReadCreds(t, b, storage, "prod-workers")

	if probed != 0 {
		t.Fatalf("probed %d times with the flag off, want 0", probed)
	}
	if len(resp.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", resp.Warnings)
	}
}

// Every granted namespace is probed, not a representative sample: a key can
// reach one cell and not another.
func TestCreds_ProbesEveryGrantedNamespace(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	stub.createAPIKeyFn = func(context.Context, client.APIKeySpec) (*client.APIKey, error) {
		return &client.APIKey{ID: "key-1", Token: "tmprl_sk_minted"}, nil
	}
	withStubClient(b, stub)

	var mu sync.Mutex
	seen := map[string]string{}
	b.probeNamespace = func(_ context.Context, token, namespace string) error {
		mu.Lock()
		defer mu.Unlock()
		seen[namespace] = token
		return nil
	}

	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role":       "developer",
		"namespace_access":   "prod.acct1=write,staging.acct1=read",
		"verify_propagation": true,
	})

	resp := mustReadCreds(t, b, storage, "prod-workers")

	if len(seen) != 2 {
		t.Fatalf("probed %d namespaces, want 2: %v", len(seen), seen)
	}
	// The probe must authenticate as the key being handed out, not the root
	// credential — otherwise it proves nothing about this key.
	for ns, token := range seen {
		if token != "tmprl_sk_minted" {
			t.Errorf("probed %s with token %q, want the minted key", ns, token)
		}
	}
	if len(resp.Warnings) != 0 {
		t.Fatalf("unexpected warnings when every namespace confirmed: %v", resp.Warnings)
	}
}

// A namespace that does not confirm produces a warning naming it — and the
// credential is still returned, because the probe is advisory.
func TestCreds_WarnsPerUnconfirmedNamespaceAndStillReturnsKey(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	stub.createAPIKeyFn = func(context.Context, client.APIKeySpec) (*client.APIKey, error) {
		return &client.APIKey{ID: "key-1", Token: "tmprl_sk_minted"}, nil
	}
	withStubClient(b, stub)

	b.probeNamespace = func(_ context.Context, _, namespace string) error {
		if namespace == "staging.acct1" {
			return fmt.Errorf("%w: staging.acct1 did not accept the new api key in time",
				client.ErrUnavailable)
		}
		return nil
	}

	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role":       "developer",
		"namespace_access":   "prod.acct1=write,staging.acct1=read",
		"verify_propagation": true,
	})

	resp := mustReadCreds(t, b, storage, "prod-workers")

	if got := resp.Data["api_key"]; got != "tmprl_sk_minted" {
		t.Fatalf("api_key = %v, want the key to be returned despite the probe failure", got)
	}
	if len(resp.Warnings) != 1 {
		t.Fatalf("got %d warnings, want exactly 1: %v", len(resp.Warnings), resp.Warnings)
	}
	if !strings.Contains(resp.Warnings[0], "staging.acct1") {
		t.Errorf("warning does not name the namespace: %q", resp.Warnings[0])
	}
	if strings.Contains(resp.Warnings[0], "prod.acct1") {
		t.Errorf("warning names a namespace that confirmed: %q", resp.Warnings[0])
	}
}

// An entry whose reach comes from account_role alone has no namespace to probe.
// Saying so is more honest than silently reporting success.
func TestCreds_WarnsWhenThereIsNothingToProbe(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	stub.createAPIKeyFn = func(context.Context, client.APIKeySpec) (*client.APIKey, error) {
		return &client.APIKey{ID: "key-1", Token: "tmprl_sk_minted"}, nil
	}
	withStubClient(b, stub)

	probed := 0
	b.probeNamespace = func(context.Context, string, string) error {
		probed++
		return nil
	}

	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "admins", map[string]interface{}{
		"account_role":       "admin",
		"verify_propagation": true,
	})

	resp := mustReadCreds(t, b, storage, "admins")

	if probed != 0 {
		t.Fatalf("probed %d times with no namespace_access, want 0", probed)
	}
	if len(resp.Warnings) != 1 {
		t.Fatalf("got %d warnings, want exactly 1: %v", len(resp.Warnings), resp.Warnings)
	}
	if !strings.Contains(resp.Warnings[0], "namespace_access") {
		t.Errorf("warning should explain there was nothing to verify: %q", resp.Warnings[0])
	}
}
```

`mustReadCreds` does not exist in the repo — add it to the same file:

```go
func mustReadCreds(t *testing.T, b *backend, storage logical.Storage, name string) *logical.Response {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + name,
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read creds/%s: err=%v resp=%v", name, err, resp)
	}
	return resp
}
```

`path_creds_test.go` already imports `context`, `fmt`, `strings`, `testing`, `time`, `logical`, and `client`. Add `sync` — it is the only one missing.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test . -run 'TestCreds_NoProbe|TestCreds_Probes|TestCreds_Warns' -v`
Expected: FAIL to compile with `b.probeNamespace undefined`.

- [ ] **Step 3: Add the injected field to the backend**

In `backend.go`, after the `newClient` field:

```go
	// probeNamespace verifies that a freshly minted API key is accepted by a
	// namespace's frontend. A field rather than a direct call to
	// client.ProbeNamespace so tests can substitute one without dialling
	// Temporal Cloud.
	//
	// It is deliberately not a method on CloudOps: that interface wraps the
	// Cloud Ops API and its client is built from the root credential and
	// shared across requests, whereas this authenticates as the key being
	// handed out — a different credential on every request.
	probeNamespace func(ctx context.Context, token, namespace string) error
```

And in `Backend()`, beside `b.newClient = client.NewGRPC`:

```go
	b.probeNamespace = client.ProbeNamespace
```

- [ ] **Step 4: Write `path_creds_probe.go`**

```go
package temporalcloud

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// verifyPropagation waits for every namespace the entry grants to accept the
// newly minted key, and reports what did not confirm.
//
// It returns warnings rather than an error on purpose. A key that has not
// reached a cell yet is not a bad key, so failing the request would turn a slow
// cell into an outage for the whole entry and would have to delete a perfectly
// good credential to avoid orphaning it. The value of this check is in the
// waiting, which usually succeeds; the warning is what is left when it does not.
func (b *backend) verifyPropagation(ctx context.Context, entry *serviceAccountEntry, token string) []string {
	if len(entry.NamespaceAccess) == 0 {
		// An entry whose reach comes from account_role alone has nothing to
		// probe. Reporting that is more honest than returning silently, which
		// would read as "verified".
		return []string{
			"verify_propagation is enabled but this entry grants no namespace_access, " +
				"so nothing was verified. Account-level roles reach namespaces that are not " +
				"listed here, and this engine has no way to enumerate them.",
		}
	}

	budget, ok := probeBudget(ctx)
	if !ok {
		return []string{
			"verify_propagation is enabled but too little of the request deadline remained " +
				"to check anything, so the key was returned unverified. Raise Vault's " +
				"default_request_timeout if this recurs.",
		}
	}

	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var (
		mu       sync.Mutex
		warnings []string
		wg       sync.WaitGroup
	)

	for namespace := range entry.NamespaceAccess {
		wg.Add(1)
		go func(namespace string) {
			defer wg.Done()

			if err := b.probeNamespace(ctx, token, namespace); err != nil {
				mu.Lock()
				warnings = append(warnings, fmt.Sprintf(
					"namespace %s did not confirm the new API key: %s. The key was still "+
						"returned; a worker using it may be rejected until Temporal Cloud "+
						"finishes distributing it.", namespace, err))
				mu.Unlock()
			}
		}(namespace)
	}

	// Every namespace is waited on rather than cancelling at the first
	// failure: they are already running concurrently, and an operator needs
	// the full list of which cells are behind, not whichever failed first.
	wg.Wait()

	sort.Strings(warnings) // stable output regardless of goroutine scheduling
	return warnings
}
```

- [ ] **Step 5: Call it from `pathCredsRead`**

In `path_creds.go`, immediately after the `resp := b.Secret(...).Response(...)` block and before `resp.Secret.TTL = entry.TTL`:

```go
	// Verify after the key exists but before it is handed over: Temporal Cloud
	// distributes keys asynchronously, and the control-plane read-back inside
	// CreateAPIKey proves only that the key was recorded, not that any cell
	// will accept it.
	if entry.VerifyPropagation {
		for _, warning := range b.verifyPropagation(ctx, entry, key.Token) {
			resp.AddWarning(warning)
		}
	}
```

- [ ] **Step 6: Run the tests**

Run: `go test . -run 'TestCreds' -v`
Expected: PASS, including all pre-existing creds tests.

- [ ] **Step 7: Run the whole suite**

Run: `go test ./... && golangci-lint run`
Expected: PASS with no lint findings.

- [ ] **Step 8: Commit**

```bash
git add backend.go path_creds.go path_creds_probe.go path_creds_test.go
git commit -m "feat: verify namespace propagation before returning a credential"
```

---

### Task 5: Live acceptance test

The only test that can catch a wrong auth metadata key, which fails identically to an unpropagated namespace and would pass every mock-based test above.

**Files:**
- Modify: `acceptance_test.go`

**Interfaces:**
- Consumes: `client.ProbeNamespace`, `client.NewGRPC`, `client.APIKeySpec`.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the live test**

Append to `acceptance_test.go`:

```go
// A wrong bearer-token metadata key produces exactly the Unauthenticated a
// namespace that has not received the key produces, so every mock-based test
// would pass against a probe that can never succeed. This is the only test
// that distinguishes them, which makes it load-bearing rather than optional.
//
// It also measures the real propagation lag, which nothing else does: the
// 50s ceiling was chosen to be comfortably longer than the lag is believed to
// be, not measured against it.
func TestLive_ProbePropagation(t *testing.T) {
	apiKey := os.Getenv("TEMPORAL_CLOUD_API_KEY")
	adminSAID := os.Getenv("TEMPORAL_CLOUD_ADMIN_SA_ID")
	namespace := os.Getenv("TEMPORAL_CLOUD_TEST_NAMESPACE")
	if apiKey == "" || adminSAID == "" || namespace == "" {
		t.Skip("set TEMPORAL_CLOUD_API_KEY, TEMPORAL_CLOUD_ADMIN_SA_ID, and " +
			"TEMPORAL_CLOUD_TEST_NAMESPACE (e.g. prod.acct1) to run this")
	}

	ctx := context.Background()

	c, err := client.NewGRPC(client.Config{
		APIKey:   apiKey,
		HostPort: os.Getenv("TEMPORAL_CLOUD_ADDRESS"),
	})
	if err != nil {
		t.Fatalf("connect to temporal cloud: %v", err)
	}
	defer func() { _ = c.Close() }()

	key, err := c.CreateAPIKey(ctx, client.APIKeySpec{
		ServiceAccountID: adminSAID,
		DisplayName:      fmt.Sprintf("vault-probe-test-%d", time.Now().UnixNano()),
		Description:      "Transient key for TestLive_ProbePropagation",
		ExpiryTime:       time.Now().Add(client.MinAPIKeyExpiry + time.Hour),
	})
	if err != nil {
		t.Fatalf("mint a key to probe with: %v", err)
	}
	t.Cleanup(func() {
		if err := c.DeleteAPIKey(context.Background(), key.ID); err != nil {
			t.Errorf("could not delete the probe test key %s; delete it by hand: %v",
				key.ID, err)
		}
	})

	probeCtx, cancel := context.WithTimeout(ctx, client.MaxProbeTimeout)
	defer cancel()

	start := time.Now()
	if err := client.ProbeNamespace(probeCtx, key.Token, namespace); err != nil {
		t.Fatalf("probing %s with a freshly minted key failed after %s: %v\n\n"+
			"If this says the namespace refused the key, check that it has "+
			"'Allow API key authentication' enabled, and that the bearer-token "+
			"metadata this probe sends is what the frontend expects.",
			namespace, time.Since(start), err)
	}

	t.Logf("namespace %s accepted a freshly minted key after %s "+
		"(ceiling is %s)", namespace, time.Since(start), client.MaxProbeTimeout)
}
```

Ensure `acceptance_test.go` imports `fmt` and `time`.

- [ ] **Step 2: Verify it skips cleanly without the new variable**

`acceptance_test.go` carries a `//go:build acceptance` tag, so the tag is required or the file is not compiled at all and `go test` reports "no tests to run" — which looks like a pass but verifies nothing.

Run: `go test -tags acceptance . -run TestLive_ProbePropagation -v`
Expected: SKIP with the message naming all three variables. It must not fail when `TEMPORAL_CLOUD_TEST_NAMESPACE` is unset, matching how `TestLive_RotateRoot` gates itself. Confirm the output says `--- SKIP`, not `no tests to run`.

- [ ] **Step 3: Run it live**

```bash
set -a && source .env && set +a
TEMPORAL_CLOUD_TEST_NAMESPACE=<your namespace, e.g. prod.acct1> \
  go test -tags acceptance . -run TestLive_ProbePropagation -v
```

Expected: PASS, with a log line reporting the measured lag.

**If it fails with "refused the key":** the namespace may not allow API key authentication, or the bearer-token metadata is wrong. Check the namespace setting first — it is the cheaper explanation. If the namespace does allow API keys, the metadata key in `ProbeNamespace` is the bug, and no mock test will tell you.

**Record the measured lag.** It resolves open risk 1 in the spec: single-digit seconds means the 10s worst-case floor is adequate and the README needs no `default_request_timeout` advice; anything approaching 50s means the `operationTimeout`/`confirmTimeout` split above the probe has to be revisited.

- [ ] **Step 4: Resolve open risk 2 — restricted roles**

Step 3 probes with a Global Admin key, which proves the wiring but says nothing about spec risk 2: whether `DescribeNamespace` is authorized for the weaker `account_role` values this engine accepts. A `metrics-read` service account may not carry namespace read permission, in which case its probe returns `PermissionDenied` forever and `verify_propagation` produces a permanent false warning on every read.

Check it directly against the roles you intend to support:

```bash
set -a && source .env && set +a

for role in developer read metrics-read; do
  vault write temporalcloud/service-accounts/probe-check-$role \
      account_role=$role \
      namespace_access=$TEMPORAL_CLOUD_TEST_NAMESPACE=read \
      verify_propagation=true
  echo "=== $role ==="
  vault read temporalcloud/creds/probe-check-$role
  vault delete temporalcloud/service-accounts/probe-check-$role
done
```

A role whose read comes back with a "refused the key" warning cannot support `verify_propagation`. Record which roles fail, then take one of the two paths the spec names: fall back to `GetSystemInfo` for those roles, or document them as unsupported for the flag in Task 6. Note that `namespace_access` with a `finance-admin` or `owner` role may be rejected at write time for unrelated reasons — that is a different failure and not what this check is about.

If every role passes, say so in the PR description and close the risk.

- [ ] **Step 5: Commit**

```bash
git add acceptance_test.go
git commit -m "test: live check that a fresh key is accepted by a namespace"
```

---

### Task 6: Document the feature

**Files:**
- Modify: `README.md` (the `service-accounts/<name>` field table around line 471, and the credential lifecycle table around line 292)

**Interfaces:**
- Consumes: the behaviour built in Tasks 1–5.
- Produces: nothing.

- [ ] **Step 1: Load the documentation style skill**

The reader-facing docs in this repo were deliberately brought under the Google developer documentation style guide in commit `eef5211`. Invoke the `google-dev-style` skill before writing, so this section does not regress that.

- [ ] **Step 2: Add the field to the service account field table**

In the `service-accounts/<name>` field table in `README.md`, after the `max_ttl` row:

```markdown
| `verify_propagation` | Before returning a credential, wait for every namespace in `namespace_access` to accept the new key. Default `false`. See [Verifying key propagation](#verifying-key-propagation). |
```

- [ ] **Step 3: Add the explanatory section**

Add after the credential lifecycle table:

```markdown
### Verifying key propagation

Temporal Cloud distributes API keys asynchronously. A key the Cloud Ops API
reports as created is not yet accepted by every namespace frontend, because the
key and its permissions have to reach the cells first.

That gap is not one a worker rides out. Temporal SDKs treat `Unauthenticated`
and `PermissionDenied` as non-retryable and fail eagerly on the first
connection, so a worker handed a key its cell has not received yet exits at
startup instead of reconnecting.

Set `verify_propagation=true` on a service account entry to close the gap:

```bash
vault write temporalcloud/service-accounts/prod-workers \
    account_role=developer \
    namespace_access=prod.acct1=write \
    verify_propagation=true
```

Each `creds/prod-workers` read then connects to every namespace in
`namespace_access` as the new key and waits until each one accepts it. Requests
usually clear this in well under a second.

Three things to know before enabling it:

- **It needs egress to the namespace frontends.** The Vault node must reach
  `<namespace>.tmprl.cloud:7233`, which is a different destination from the
  `saas-api.tmprl.cloud:443` this engine otherwise uses.
- **The namespace must allow API key authentication.** A namespace configured
  for mTLS only rejects the probe permanently, which shows up as a warning on
  every credential request rather than as a propagation delay.
- **A timeout warns; it never fails.** If a namespace does not confirm in time,
  Vault returns the credential anyway with a warning naming that namespace. The
  credential is valid and the lease is normal — the warning means Vault could
  not confirm the key had arrived, not that anything is broken.

An entry that grants access through `account_role` alone has no namespaces to
check, and reads from it warn that nothing was verified.

The wait is bounded by whatever is left of the Vault request timeout, up to 50
seconds. Minting a key can itself take most of Vault's 90-second default, in
which case the check gets whatever remains. To keep the full window available,
raise `default_request_timeout` on the Vault listener to at least 130 seconds.
```

- [ ] **Step 4: Verify the docs**

```bash
markdownlint-cli2 README.md
prettier --check README.md
```

Expected: no findings. Re-read the new section against the style guide: imperative headings, second person, no future tense where present tense works.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: document verify_propagation on service account entries"
```

---

## Verification

Before opening a PR:

```bash
go build ./... && go vet ./... && go test ./... && golangci-lint run
```

Then confirm by hand:

1. `git diff main --stat` shows changes only in: `client/probe.go`, `client/probe_test.go`, `probe_budget.go`, `probe_budget_test.go`, `path_creds_probe.go`, `path_creds.go`, `path_service_accounts.go`, `backend.go`, the three test files, `README.md`, `go.mod`, `go.sum`.
2. `go.mod` lists `go.temporal.io/api` as a direct require, and `go.temporal.io/sdk` appears nowhere.
3. `grep -c 'grpc.NewClient' client/probe.go` returns 1 — the dial is outside the retry loop.
4. The live test has been run against a real namespace at least once and its measured lag recorded in the PR description.
