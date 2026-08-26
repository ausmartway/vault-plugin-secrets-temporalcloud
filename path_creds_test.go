package temporalcloud

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

// The cap check is where a confusing failure would otherwise surface, so it is
// tested directly at its boundaries.
func TestCheckAPIKeyCapacity(t *testing.T) {
	tests := []struct {
		name    string
		count   int
		wantErr bool
	}{
		{"well under the cap", 0, false},
		{"one below the cap", 19, false},
		{"at the cap", 20, true},
		{"above the cap", 21, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAPIKeyCapacity("prod-workers", tc.count, time.Hour)

			if tc.wantErr && err == nil {
				t.Fatalf("expected an error at count %d", tc.count)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error at count %d: %v", tc.count, err)
			}
		})
	}
}

// The message must be actionable: it has to name the service account, the cap,
// the current TTL, and what the operator can do about it.
func TestCheckAPIKeyCapacity_MessageIsActionable(t *testing.T) {
	err := checkAPIKeyCapacity("prod-workers", 20, time.Hour)
	if err == nil {
		t.Fatal("expected an error")
	}

	for _, want := range []string{"prod-workers", "20", "1h", "Revoke", "service account"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected the message to mention %q, got: %v", want, err)
		}
	}
}

func TestCreds_MintsKeyAndIssuesLease(t *testing.T) {
	b, storage := newTestBackend(t)

	var gotSpec client.APIKeySpec
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	stub.createAPIKeyFn = func(_ context.Context, spec client.APIKeySpec) (*client.APIKey, error) {
		gotSpec = spec
		return &client.APIKey{ID: "key-1", Token: "tmprl_sk_minted"}, nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "developer",
		"ttl":          "1h",
		"max_ttl":      "48h",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read creds: err=%v resp=%v", err, resp)
	}

	if resp.Data["api_key"] != "tmprl_sk_minted" {
		t.Errorf("expected the minted token, got %v", resp.Data["api_key"])
	}
	if resp.Data["api_key_id"] != "key-1" {
		t.Errorf("expected key-1, got %v", resp.Data["api_key_id"])
	}
	if resp.Data["service_account_id"] != "sa-1" {
		t.Errorf("expected sa-1, got %v", resp.Data["service_account_id"])
	}

	if resp.Secret == nil {
		t.Fatal("expected a lease")
	}
	if resp.Secret.TTL != time.Hour {
		t.Errorf("expected a 1h lease, got %v", resp.Secret.TTL)
	}
	if resp.Secret.MaxTTL != 48*time.Hour {
		t.Errorf("expected a 48h max TTL, got %v", resp.Secret.MaxTTL)
	}

	// The key ID must be in internal data so revocation can find it, and the
	// token must not be, because Vault never persists it.
	if resp.Secret.InternalData["api_key_id"] != "key-1" {
		t.Errorf("expected api_key_id in internal data, got %v", resp.Secret.InternalData)
	}
	if _, present := resp.Secret.InternalData["api_key"]; present {
		t.Error("the token must never be stored in lease internal data")
	}

	// max_ttl (48h) is already above the 24h floor, so the Temporal Cloud
	// expiry must cover max_ttl plus grace unclamped, not just ttl: otherwise
	// a renewed lease would outlive its own key.
	wantExpiry := time.Now().Add(48*time.Hour + apiKeyExpiryGrace)
	if delta := gotSpec.ExpiryTime.Sub(wantExpiry); delta > time.Minute || delta < -time.Minute {
		t.Errorf("expected an expiry near %v (max_ttl + grace), got %v", wantExpiry, gotSpec.ExpiryTime)
	}
	if gotSpec.ServiceAccountID != "sa-1" {
		t.Errorf("expected the key to be minted on sa-1, got %q", gotSpec.ServiceAccountID)
	}
}

// TestCreds_ShortMaxTTLFloorsExpiryAtMinimum verifies that a max_ttl below
// Temporal Cloud's undocumented 24-hour minimum still produces a mintable
// expiry: the engine floors it at 24h+grace instead of sending max_ttl+grace
// (~1h10m) and having Temporal Cloud reject it.
func TestCreds_ShortMaxTTLFloorsExpiryAtMinimum(t *testing.T) {
	b, storage := newTestBackend(t)

	var gotSpec client.APIKeySpec
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	stub.createAPIKeyFn = func(_ context.Context, spec client.APIKeySpec) (*client.APIKey, error) {
		gotSpec = spec
		return &client.APIKey{ID: "key-1", Token: "tmprl_sk_minted"}, nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "developer",
		"ttl":          "30m",
		"max_ttl":      "1h",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read creds: err=%v resp=%v", err, resp)
	}

	// Expect ~24h10m out (client.MinAPIKeyExpiry + grace), NOT ~1h10m
	// (max_ttl + grace).
	wantExpiry := time.Now().Add(client.MinAPIKeyExpiry + apiKeyExpiryGrace)
	if delta := gotSpec.ExpiryTime.Sub(wantExpiry); delta > time.Minute || delta < -time.Minute {
		t.Errorf("expected the expiry floored near %v (24h10m out), got %v", wantExpiry, gotSpec.ExpiryTime)
	}

	// The lease itself must still honor the operator's short max_ttl: the
	// floor only affects the Temporal Cloud expiry sent to CreateAPIKey.
	if resp.Secret.MaxTTL != time.Hour {
		t.Errorf("expected the lease's max TTL to stay at the configured 1h, got %v", resp.Secret.MaxTTL)
	}
}

// TestCreds_LongMaxTTLIsNotClamped verifies that the floor only raises
// expiries that would otherwise fall under the minimum — a max_ttl already
// above it passes through unchanged (max_ttl + grace), matching
// TestCreds_MintsKeyAndIssuesLease's assertion but stated as its own
// boundary case.
func TestCreds_LongMaxTTLIsNotClamped(t *testing.T) {
	b, storage := newTestBackend(t)

	var gotSpec client.APIKeySpec
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	stub.createAPIKeyFn = func(_ context.Context, spec client.APIKeySpec) (*client.APIKey, error) {
		gotSpec = spec
		return &client.APIKey{ID: "key-1", Token: "tmprl_sk_minted"}, nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "developer",
		"ttl":          "1h",
		"max_ttl":      "48h",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read creds: err=%v resp=%v", err, resp)
	}

	wantExpiry := time.Now().Add(48*time.Hour + apiKeyExpiryGrace)
	if delta := gotSpec.ExpiryTime.Sub(wantExpiry); delta > time.Minute || delta < -time.Minute {
		t.Errorf("expected the floor to leave a 48h max_ttl unclamped, near %v, got %v", wantExpiry, gotSpec.ExpiryTime)
	}
}

func TestCreds_FailsAtCapacity(t *testing.T) {
	b, storage := newTestBackend(t)

	minted := 0
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	stub.countAPIKeysFn = func(context.Context, string) (int, error) {
		return client.MaxAPIKeysPerServiceAccount, nil
	}
	stub.createAPIKeyFn = func(context.Context, client.APIKeySpec) (*client.APIKey, error) {
		minted++
		return &client.APIKey{ID: "key-x", Token: "tok"}, nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{"account_role": "read"})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected the read to fail at the key cap")
	}
	if minted != 0 {
		t.Error("no key should be minted once the cap is reached")
	}
}

// An expired or under-privileged root key is an operator-fixable credential
// problem, so it must read as one. Returning a Go error would render it as
// "500 Internal Server Error", which reads as a plugin crash and sends the
// operator looking in the wrong place entirely.
func TestCreds_PermissionDeniedIsAnActionableErrorNotA500(t *testing.T) {
	for _, tc := range []struct {
		name string
		stub *stubCloudOps
	}{
		{
			name: "counting keys",
			stub: &stubCloudOps{
				countAPIKeysFn: func(context.Context, string) (int, error) {
					return 0, fmt.Errorf("%w: request unauthenticated", client.ErrPermissionDenied)
				},
			},
		},
		{
			name: "minting the key",
			stub: &stubCloudOps{
				createAPIKeyFn: func(context.Context, client.APIKeySpec) (*client.APIKey, error) {
					return nil, fmt.Errorf("%w: request unauthenticated", client.ErrPermissionDenied)
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := newTestBackend(t)
			withStubClient(b, tc.stub)
			mustWriteConfig(t, b, storage)
			mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{"account_role": "read"})

			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "creds/prod-workers",
				Storage:   storage,
			})
			if err != nil {
				t.Fatalf("expected an error response, not a 500: %v", err)
			}
			if resp == nil || !resp.IsError() {
				t.Fatal("expected the read to be refused")
			}

			msg := resp.Error().Error()
			// It must still say what was being attempted, and point at the
			// root credential as the likely cause.
			if !strings.Contains(msg, "prod-workers") {
				t.Errorf("expected the message to name the entry, got: %s", msg)
			}
			if !strings.Contains(msg, "rotate-root") {
				t.Errorf("expected the message to suggest rotating the root key, got: %s", msg)
			}
		})
	}
}

// ErrUnavailable is the opposite case: a genuine infrastructure failure, worth
// retrying, and correctly a 500.
func TestCreds_UnavailableStaysAGoError(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{
		createAPIKeyFn: func(context.Context, client.APIKeySpec) (*client.APIKey, error) {
			return nil, fmt.Errorf("%w: try again", client.ErrUnavailable)
		},
	})
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{"account_role": "read"})

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
	}); err == nil {
		t.Fatal("expected an unavailable Temporal Cloud to surface as a retryable error")
	}
}

// A mint that fails after Temporal Cloud already accepted the create leaves a
// real key behind — CreateAPIKey returns it alongside the error for exactly
// this reason. No lease is issued, so nothing will ever revoke it: the handler
// must delete it, or it sits unusable in one of the service account's twenty
// slots until its expiry, which the 24-hour floor puts at least a day out.
func TestCreds_DeletesKeyWhenMintDoesNotComplete(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{
		createAPIKeyFn: func(context.Context, client.APIKeySpec) (*client.APIKey, error) {
			return &client.APIKey{ID: "key-orphan", Token: "tmprl_sk_real"},
				fmt.Errorf("%w: operation failed", client.ErrInvalidArgument)
		},
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{"account_role": "read"})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected an error response, got %v", resp)
	}
	if resp.Secret != nil {
		t.Error("expected no lease for a mint that did not complete")
	}

	if len(stub.deletedAPIKeys) != 1 || stub.deletedAPIKeys[0] != "key-orphan" {
		t.Errorf("expected the orphaned key to be deleted, got %v", stub.deletedAPIKeys)
	}
}

func TestCreds_UnknownServiceAccount(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/does-not-exist",
		Storage:   storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected an error for an unknown service account")
	}
	if resp != nil && !strings.Contains(resp.Error().Error(), "does-not-exist") {
		t.Errorf("expected the message to name the entry, got %v", resp.Error())
	}
}

func TestRevoke_DeletesKey(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"api_key_id":  "key-to-revoke",
				"secret_type": secretTypeAPIKey,
			},
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("revoke: err=%v resp=%v", err, resp)
	}

	if len(stub.deletedAPIKeys) != 1 || stub.deletedAPIKeys[0] != "key-to-revoke" {
		t.Errorf("expected key-to-revoke to be deleted, got %v", stub.deletedAPIKeys)
	}
}

// A key that is already gone means revocation has nothing left to do. Failing
// here would leave the lease stuck forever.
func TestRevoke_TreatsNotFoundAsSuccess(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{
		deleteAPIKeyFn: func(context.Context, string) error { return client.ErrNotFound },
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"api_key_id":  "already-gone",
				"secret_type": secretTypeAPIKey,
			},
		},
	})
	if err != nil {
		t.Fatalf("revoking an already-deleted key must succeed, got: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("revoking an already-deleted key must succeed, got: %v", resp.Error())
	}
}

func TestRenew_ExtendsWithoutCloudCall(t *testing.T) {
	b, storage := newTestBackend(t)

	minted := 0
	stub := &stubCloudOps{}
	stub.createAPIKeyFn = func(context.Context, client.APIKeySpec) (*client.APIKey, error) {
		minted++
		return &client.APIKey{ID: "k", Token: "t"}, nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "read",
		"ttl":          "1h",
		"max_ttl":      "8h",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"api_key_id":           "key-1",
				"service_account_name": "prod-workers",
				"secret_type":          secretTypeAPIKey,
			},
			LeaseOptions: logical.LeaseOptions{TTL: time.Hour, IssueTime: time.Now()},
		},
	})
	if err != nil || resp == nil {
		t.Fatalf("renew: err=%v resp=%v", err, resp)
	}

	if resp.Secret.TTL != time.Hour {
		t.Errorf("expected the entry's ttl of 1h, got %v", resp.Secret.TTL)
	}
	// Renewal must not touch Temporal Cloud: the key already expires at
	// max_ttl + grace, so extending the lease needs no API call.
	if minted != 0 || len(stub.deletedAPIKeys) != 0 {
		t.Error("renewal must make no Temporal Cloud calls")
	}
}

// TestRenew_ClampsMaxTTLToTheKeysCloudExpiry covers raising max_ttl on an
// entry that already has a live lease. A minted key's Temporal Cloud expiry is
// immutable — there is no extend call — so the lease must stay inside the
// window the key was minted with, not the window the entry now advertises.
// Without the clamp Vault would keep renewing a lease whose credential had
// already expired in Temporal Cloud.
func TestRenew_ClampsMaxTTLToTheKeysCloudExpiry(t *testing.T) {
	b, storage := newTestBackend(t)

	var gotSpec client.APIKeySpec
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	stub.createAPIKeyFn = func(_ context.Context, spec client.APIKeySpec) (*client.APIKey, error) {
		gotSpec = spec
		return &client.APIKey{ID: "key-1", Token: "tmprl_sk_minted"}, nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "developer",
		"ttl":          "1h",
		"max_ttl":      "8h",
	})

	issueTime := time.Now()
	minted, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
	})
	if err != nil || minted == nil || minted.IsError() {
		t.Fatalf("read creds: err=%v resp=%v", err, minted)
	}

	// The clamp needs the key's own expiry, so the mint must record it on the
	// lease. Nothing else can recover it: Temporal Cloud's expiry is fixed at
	// create time and max_ttl is free to move afterward.
	stamped, ok := minted.Secret.InternalData["api_key_expires_at"].(string)
	if !ok {
		t.Fatalf("expected api_key_expires_at in internal data, got %v", minted.Secret.InternalData)
	}
	if want := gotSpec.ExpiryTime.Format(time.RFC3339); stamped != want {
		t.Errorf("expected the stamp to match the minted expiry %s, got %s", want, stamped)
	}

	// The operator raises max_ttl well past the live key's expiry.
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
		Data:      map[string]interface{}{"max_ttl": "720h"},
	}); err != nil {
		t.Fatalf("raise max_ttl: %v", err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
		Secret: &logical.Secret{
			InternalData: minted.Secret.InternalData,
			LeaseOptions: logical.LeaseOptions{TTL: time.Hour, IssueTime: issueTime},
		},
	})
	if err != nil || resp == nil {
		t.Fatalf("renew: err=%v resp=%v", err, resp)
	}

	// Vault caps renewals at IssueTime + Secret.MaxTTL, so the returned
	// max TTL must leave the grace margin intact ahead of the key's expiry —
	// here the original 8h, not the entry's new 720h. The stamp carries
	// second precision, so allow a small delta rather than exactly 8h.
	if delta := resp.Secret.MaxTTL - 8*time.Hour; delta > time.Minute || delta < -time.Minute {
		t.Errorf("expected the max TTL clamped to the key's 8h window, got %v", resp.Secret.MaxTTL)
	}
	if resp.Secret.TTL != time.Hour {
		t.Errorf("expected the entry's ttl of 1h, got %v", resp.Secret.TTL)
	}
}

// TestRenew_ShortMaxTTLIsNotWidenedByTheFlooredExpiry covers the other
// direction of the clamp. A max_ttl under the 24-hour floor produces a key
// whose expiry is far beyond max_ttl, and the key's expiry is a ceiling on the
// lease, never a target: the lease must stay on the operator's short max_ttl.
func TestRenew_ShortMaxTTLIsNotWidenedByTheFlooredExpiry(t *testing.T) {
	b, storage := newTestBackend(t)

	withStubClient(b, &stubCloudOps{})
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "developer",
		"ttl":          "15m",
		"max_ttl":      "1h",
	})

	// What the mint records for a 1h max_ttl: floored to 24h, plus grace.
	expiresAt := time.Now().Add(client.MinAPIKeyExpiry + apiKeyExpiryGrace)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"api_key_id":           "key-1",
				"api_key_expires_at":   expiresAt.Format(time.RFC3339),
				"service_account_name": "prod-workers",
				"secret_type":          secretTypeAPIKey,
			},
			LeaseOptions: logical.LeaseOptions{TTL: 15 * time.Minute, IssueTime: time.Now()},
		},
	})
	if err != nil || resp == nil {
		t.Fatalf("renew: err=%v resp=%v", err, resp)
	}
	if resp.Secret.MaxTTL != time.Hour {
		t.Errorf("expected the entry's max_ttl of 1h, got %v", resp.Secret.MaxTTL)
	}
}

// TestRenew_RefusedOnceTheKeysWindowIsExhausted covers a lease that has
// already been renewed past its key's usable window — possible for leases
// issued before the clamp existed. Renewal must fail rather than hand back a
// non-positive max TTL, which Vault would read as "no backend limit".
func TestRenew_RefusedOnceTheKeysWindowIsExhausted(t *testing.T) {
	b, storage := newTestBackend(t)

	withStubClient(b, &stubCloudOps{})
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "developer",
		"ttl":          "1h",
		"max_ttl":      "8h",
	})

	// Inside the grace margin, so the key is effectively spent.
	expiresAt := time.Now().Add(5 * time.Minute)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"api_key_id":           "key-1",
				"api_key_expires_at":   expiresAt.Format(time.RFC3339),
				"service_account_name": "prod-workers",
				"secret_type":          secretTypeAPIKey,
			},
			LeaseOptions: logical.LeaseOptions{TTL: time.Hour, IssueTime: time.Now()},
		},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatalf("expected renewal to be refused, got resp=%v", resp)
	}

	msg := errorMessage(err, resp)
	if !strings.Contains(msg, "expiry") {
		t.Errorf("expected the error to explain the key's expiry, got: %s", msg)
	}
}

// TestRenew_LeaseWithoutAnExpiryStampStillRenews covers leases issued before
// the mint began recording api_key_expires_at. There is nothing to clamp
// against, so they must keep renewing on the entry's max_ttl rather than
// becoming unrenewable on upgrade.
func TestRenew_LeaseWithoutAnExpiryStampStillRenews(t *testing.T) {
	b, storage := newTestBackend(t)

	withStubClient(b, &stubCloudOps{})
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "developer",
		"ttl":          "1h",
		"max_ttl":      "8h",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"api_key_id":           "key-1",
				"service_account_name": "prod-workers",
				"secret_type":          secretTypeAPIKey,
			},
			LeaseOptions: logical.LeaseOptions{TTL: time.Hour, IssueTime: time.Now()},
		},
	})
	if err != nil || resp == nil {
		t.Fatalf("renew: err=%v resp=%v", err, resp)
	}
	if resp.Secret.MaxTTL != 8*time.Hour {
		t.Errorf("expected the entry's max_ttl of 8h, got %v", resp.Secret.MaxTTL)
	}
}

// errorMessage reads the message off whichever channel a handler used to
// report the failure — a Go error or a logical error response.
func errorMessage(err error, resp *logical.Response) string {
	if err != nil {
		return err.Error()
	}
	if resp != nil && resp.IsError() {
		return resp.Error().Error()
	}
	return ""
}

// mustWriteServiceAccount creates a service-accounts/<name> entry.
func mustWriteServiceAccount(t *testing.T, b *backend, storage logical.Storage, name string, data map[string]interface{}) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/" + name,
		Storage:   storage,
		Data:      data,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write service account %s: err=%v resp=%v", name, err, resp)
	}
}

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
	b.probeNamespace = func(context.Context, string, string, client.ProbeSettings) error {
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
	b.probeNamespace = func(_ context.Context, token, namespace string, _ client.ProbeSettings) error {
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

func TestCreds_UsesMountProbeConfig(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	stub.createAPIKeyFn = func(context.Context, client.APIKeySpec) (*client.APIKey, error) {
		return &client.APIKey{ID: "key-1", Token: "tmprl_sk_minted"}, nil
	}
	withStubClient(b, stub)

	var got client.ProbeSettings
	b.probeNamespace = func(_ context.Context, _, _ string, settings client.ProbeSettings) error {
		got = settings
		return nil
	}

	mustWriteConfig(t, b, storage)
	writeProbeConfig(t, b, storage, map[string]interface{}{
		"interval":              "275ms",
		"consecutive_successes": 9,
	})
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role":       "developer",
		"namespace_access":   "prod.acct1=write",
		"verify_propagation": true,
	})

	resp := mustReadCreds(t, b, storage, "prod-workers")
	if len(resp.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", resp.Warnings)
	}
	if got.Interval != 275*time.Millisecond || got.ConsecutiveSuccesses != 9 {
		t.Fatalf("probe settings = %+v, want interval=275ms consecutive_successes=9", got)
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

	b.probeNamespace = func(_ context.Context, _, namespace string, _ client.ProbeSettings) error {
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
	b.probeNamespace = func(context.Context, string, string, client.ProbeSettings) error {
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
