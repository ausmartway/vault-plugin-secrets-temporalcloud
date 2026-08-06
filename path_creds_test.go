package temporalcloud

import (
	"context"
	"strings"
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
