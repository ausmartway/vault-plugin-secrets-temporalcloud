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
//
// The config path no longer produces this state — it rejects any key whose ID
// it cannot read — so the only way to reach it is stored config written by an
// earlier build, which is what this seeds directly. The branch stays because
// bricking rotation on an upgraded mount would be a far worse outcome than
// warning about one key.
func TestRotateRoot_WarnsWhenOldKeyIDUnknown(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	withStubClient(b, stub)

	legacy := &config{
		APIKey:                "tmprl_sk_bootstrap_not_a_jwt",
		AdminServiceAccountID: "sa-123",
		Address:               defaultAddress,
		RootKeyTTL:            defaultRootKeyTTL,
		// APIKeyID deliberately empty, as an older build could leave it.
	}
	entry, err := logical.StorageEntryJSON(configStoragePath, legacy)
	if err != nil {
		t.Fatalf("seed legacy config: %v", err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatalf("seed legacy config: %v", err)
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
			return &client.ServiceAccount{
				ID: "sa-123",
				Spec: client.ServiceAccountSpec{
					AccountRole: "admin",
				},
			}, nil
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
	if cfg.APIKey != testAPIKey("key-bootstrap") {
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

// Vault does not serialise requests to a path, so two rotations can overlap —
// a duplicated cron entry or a retried request is enough. Unserialised, both
// would mint a Global Admin key and both would store, and the loser's key
// would survive for root_key_ttl as a working credential Vault no longer
// records anywhere. Every key minted here except the one now in config must
// therefore have been deleted.
func TestRotateRoot_ConcurrentRotationsLeaveNoOrphanedKey(t *testing.T) {
	b, storage := newTestBackend(t)

	var mu sync.Mutex
	minted := make([]string, 0, 2)

	stub := &stubCloudOps{
		createAPIKeyFn: func(context.Context, client.APIKeySpec) (*client.APIKey, error) {
			mu.Lock()
			defer mu.Unlock()
			id := fmt.Sprintf("key-%d", len(minted)+1)
			minted = append(minted, id)
			return &client.APIKey{ID: id, Token: "tmprl_sk_" + id}, nil
		},
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage) // stores api_key_id "key-bootstrap"

	const rotations = 2
	var wg sync.WaitGroup
	wg.Add(rotations)
	for i := 0; i < rotations; i++ {
		go func() {
			defer wg.Done()
			if _, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config/rotate-root",
				Storage:   storage,
			}); err != nil {
				t.Errorf("rotate-root: %v", err)
			}
		}()
	}
	wg.Wait()

	cfg, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("get config: %v", err)
	}

	if len(minted) != rotations {
		t.Fatalf("expected %d keys to be minted, got %v", rotations, minted)
	}

	// Exactly one minted key survives, and it is the one config now names.
	deleted := make(map[string]bool, len(stub.deletedAPIKeys))
	for _, id := range stub.deletedAPIKeys {
		deleted[id] = true
	}
	for _, id := range minted {
		if id == cfg.APIKeyID {
			if deleted[id] {
				t.Errorf("the stored root key %q was deleted", id)
			}
			continue
		}
		if !deleted[id] {
			t.Errorf("key %q was minted, is not the stored credential, and was never "+
				"deleted — it is an orphaned Global Admin credential", id)
		}
	}
	if !deleted["key-bootstrap"] {
		t.Error("expected the bootstrap key to be deleted")
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
			"api_key":                  testAPIKey("key-bootstrap"),
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
