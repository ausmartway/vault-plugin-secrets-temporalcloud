package temporalcloud

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

func TestRotateRoot_ReplacesCredential(t *testing.T) {
	b, storage := newTestBackend(t)

	stub := &stubCloudOps{
		createAPIKeyFn: func(_ context.Context, spec client.APIKeySpec) (*client.APIKey, error) {
			if spec.ServiceAccountID != "sa-123" {
				t.Errorf("expected the key to be minted on sa-123, got %q", spec.ServiceAccountID)
			}
			if spec.ExpiryTime.IsZero() {
				t.Error("expected a non-zero expiry")
			}
			return &client.APIKey{ID: "key-new", Token: "tmprl_sk_new"}, nil
		},
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage) // stores api_key_id "key-bootstrap"

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate-root: err=%v resp=%v", err, resp)
	}

	cfg, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	if cfg.APIKey != "tmprl_sk_new" {
		t.Errorf("expected the stored key to be the new one, got %q", cfg.APIKey)
	}
	if cfg.APIKeyID != "key-new" {
		t.Errorf("expected the stored key ID to be key-new, got %q", cfg.APIKeyID)
	}

	// The key it replaced must be deleted.
	if len(stub.deletedAPIKeys) != 1 || stub.deletedAPIKeys[0] != "key-bootstrap" {
		t.Errorf("expected key-bootstrap to be deleted, got %v", stub.deletedAPIKeys)
	}
}

// Without a known api_key_id there is nothing to delete. Rotation must still
// succeed, and must warn so the operator cleans up by hand.
func TestRotateRoot_WarnsWhenOldKeyIDUnknown(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	withStubClient(b, stub)

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  "tmprl_sk_bootstrap",
			"admin_service_account_id": "sa-123",
			// api_key_id deliberately omitted
		},
	}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate-root: err=%v resp=%v", err, resp)
	}

	if len(resp.Warnings) == 0 {
		t.Fatal("expected a warning that the previous key could not be deleted")
	}
	if !strings.Contains(strings.Join(resp.Warnings, " "), "manually") {
		t.Errorf("expected the warning to tell the operator to delete it manually, got %v", resp.Warnings)
	}
	if len(stub.deletedAPIKeys) != 0 {
		t.Errorf("expected no deletion attempt, got %v", stub.deletedAPIKeys)
	}
}

// If the new key does not work, the old configuration must survive untouched.
// Storing an unverified credential would brick the mount.
func TestRotateRoot_KeepsOldConfigWhenNewKeyFailsVerification(t *testing.T) {
	b, storage := newTestBackend(t)

	calls := 0
	stub := &stubCloudOps{
		getServiceAccountFn: func(context.Context, string) (*client.ServiceAccount, error) {
			calls++
			// First call is the config write's validation and must succeed.
			// The second is rotate-root verifying the new key; fail that.
			if calls > 1 {
				return nil, client.ErrPermissionDenied
			}
			return &client.ServiceAccount{ID: "sa-123"}, nil
		},
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected rotation to fail when the new key does not verify")
	}

	cfg, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	if cfg.APIKey != "tmprl_sk_test" {
		t.Errorf("expected the original key to survive, got %q", cfg.APIKey)
	}
	if cfg.APIKeyID != "key-bootstrap" {
		t.Errorf("expected the original key ID to survive, got %q", cfg.APIKeyID)
	}
}

func TestRotateRoot_FailsWhenUnconfigured(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected rotate-root to fail when the engine is not configured")
	}
}

// The new key's expiry must come from root_key_ttl.
func TestRotateRoot_UsesRootKeyTTL(t *testing.T) {
	b, storage := newTestBackend(t)

	var gotExpiry time.Time
	withStubClient(b, &stubCloudOps{
		createAPIKeyFn: func(_ context.Context, spec client.APIKeySpec) (*client.APIKey, error) {
			gotExpiry = spec.ExpiryTime
			return &client.APIKey{ID: "key-new", Token: "tmprl_sk_new"}, nil
		},
	})

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  "tmprl_sk_test",
			"admin_service_account_id": "sa-123",
			"root_key_ttl":             "720h", // 30 days
		},
	}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
	}); err != nil {
		t.Fatalf("rotate-root: %v", err)
	}

	want := time.Now().Add(720 * time.Hour)
	if delta := gotExpiry.Sub(want); delta > time.Minute || delta < -time.Minute {
		t.Errorf("expected an expiry near %v, got %v", want, gotExpiry)
	}
}
