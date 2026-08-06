//go:build acceptance

package temporalcloud

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

// acctestPrefix names every resource these tests create, so anything left
// behind by a crashed run is identifiable and sweepable.
const acctestPrefix = "vault-acctest-"

// liveBackend builds a backend wired to the real Cloud Ops API and configured
// from the environment.
func liveBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()

	apiKey := os.Getenv("TEMPORAL_CLOUD_API_KEY")
	adminSAID := os.Getenv("TEMPORAL_CLOUD_ADMIN_SA_ID")
	if apiKey == "" || adminSAID == "" {
		t.Skip("set TEMPORAL_CLOUD_API_KEY and TEMPORAL_CLOUD_ADMIN_SA_ID to run live tests")
	}

	conf := logical.TestBackendConfig()
	conf.StorageView = &logical.InmemStorage{}
	storage := conf.StorageView

	b := Backend()
	if err := b.Setup(context.Background(), conf); err != nil {
		t.Fatalf("backend setup: %v", err)
	}

	data := map[string]interface{}{
		"api_key":                  apiKey,
		"admin_service_account_id": adminSAID,
	}
	if id := os.Getenv("TEMPORAL_CLOUD_API_KEY_ID"); id != "" {
		data["api_key_id"] = id
	}
	if addr := os.Getenv("TEMPORAL_CLOUD_ADDRESS"); addr != "" {
		data["address"] = addr
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("configuring against the live account failed: err=%v resp=%v", err, resp)
	}

	t.Cleanup(func() { b.resetClient() })

	return b, storage
}

// acctestName produces a unique, identifiable resource name.
func acctestName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s%d", acctestPrefix, time.Now().UnixNano())
}

// createServiceAccount creates one and registers its deletion immediately, so
// a later assertion failure cannot leak it.
func createServiceAccount(t *testing.T, b *backend, storage logical.Storage, name string, data map[string]interface{}) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/" + name,
		Storage:   storage,
		Data:      data,
	})

	// Register cleanup before checking the result: a partial failure may still
	// have created the cloud-side account.
	t.Cleanup(func() {
		_, _ = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "service-accounts/" + name,
			Storage:   storage,
		})
	})

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create service account %s: err=%v resp=%v", name, err, resp)
	}
}

// TestLive_ConfigValidatesCredential proves the write-time validation actually
// talks to Temporal Cloud.
func TestLive_ConfigValidatesCredential(t *testing.T) {
	b, storage := liveBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read config: err=%v resp=%v", err, resp)
	}
	if _, present := resp.Data["api_key"]; present {
		t.Error("api_key must never be returned")
	}
}

func TestLive_ConfigRejectsBadServiceAccountID(t *testing.T) {
	b, _ := liveBackend(t)

	storage := &logical.InmemStorage{}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  os.Getenv("TEMPORAL_CLOUD_API_KEY"),
			"admin_service_account_id": "definitely-not-a-real-service-account-id",
		},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected a nonexistent admin_service_account_id to be rejected")
	}
}

// TestLive_ServiceAccountLifecycle exercises create, read, update, and delete
// against the real API, including the async operation polling.
func TestLive_ServiceAccountLifecycle(t *testing.T) {
	b, storage := liveBackend(t)
	name := acctestName(t)

	createServiceAccount(t, b, storage, name, map[string]interface{}{
		"account_role": "read",
		"ttl":          "10m",
		"max_ttl":      "1h",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/" + name,
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read: err=%v resp=%v", err, resp)
	}

	saID, _ := resp.Data["service_account_id"].(string)
	if saID == "" {
		t.Fatal("expected a Temporal Cloud service account ID")
	}
	t.Logf("created service account %s (%s)", name, saID)

	// Update the role — this must reach Temporal Cloud and complete its async
	// operation.
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "service-accounts/" + name,
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "developer"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	c, err := b.getClient(context.Background(), storage)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	sa, err := c.GetServiceAccount(context.Background(), saID)
	if err != nil {
		t.Fatalf("fetching the updated service account: %v", err)
	}
	if sa.Spec.AccountRole != "developer" {
		t.Errorf("expected the role change to reach Temporal Cloud, got %q", sa.Spec.AccountRole)
	}
}

// TestLive_CredentialLifecycle is the test that matters: a minted key must
// actually authenticate, and must stop working once revoked.
func TestLive_CredentialLifecycle(t *testing.T) {
	b, storage := liveBackend(t)
	name := acctestName(t)

	createServiceAccount(t, b, storage, name, map[string]interface{}{
		"account_role": "read",
		"ttl":          "10m",
		"max_ttl":      "1h",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + name,
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read creds: err=%v resp=%v", err, resp)
	}

	token, _ := resp.Data["api_key"].(string)
	keyID, _ := resp.Data["api_key_id"].(string)
	if token == "" || keyID == "" {
		t.Fatalf("expected a token and key ID, got %v", resp.Data)
	}

	// Clean up the key even if the assertions below fail.
	t.Cleanup(func() {
		c, err := b.getClient(context.Background(), storage)
		if err != nil {
			return
		}
		_ = c.DeleteAPIKey(context.Background(), keyID)
	})

	// The minted key must authenticate. Building a client with it and reading
	// the admin service account is the cheapest proof.
	minted, err := client.NewGRPC(client.Config{
		APIKey:   token,
		HostPort: os.Getenv("TEMPORAL_CLOUD_ADDRESS"),
	})
	if err != nil {
		t.Fatalf("building a client with the minted key: %v", err)
	}
	defer func() { _ = minted.Close() }()

	saID, _ := resp.Data["service_account_id"].(string)
	if _, err := minted.GetServiceAccount(context.Background(), saID); err != nil {
		t.Fatalf("the minted key failed to authenticate: %v", err)
	}
	t.Logf("minted key %s authenticated", keyID)

	// Revoke, then prove the key is gone.
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/" + name,
		Storage:   storage,
		Secret:    resp.Secret,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Temporal Cloud may take a moment to propagate the deletion, so retry
	// briefly rather than asserting once and flaking.
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, err := minted.GetServiceAccount(context.Background(), saID)
		if err != nil {
			t.Logf("revoked key correctly rejected: %v", err)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the revoked key still authenticates after 30s")
		}
		time.Sleep(2 * time.Second)
	}
}

// TestLive_RotateRoot rotates the root credential and rotates it back, leaving
// the account as it was found.
func TestLive_RotateRoot(t *testing.T) {
	if os.Getenv("TEMPORAL_CLOUD_ALLOW_ROOT_ROTATION") == "" {
		t.Skip("set TEMPORAL_CLOUD_ALLOW_ROOT_ROTATION=1 to run this; it replaces the configured root key")
	}

	b, storage := liveBackend(t)

	before, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("get config: %v", err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate-root: err=%v resp=%v", err, resp)
	}
	for _, w := range resp.Warnings {
		t.Logf("warning: %s", w)
	}

	after, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	if after.APIKey == before.APIKey {
		t.Fatal("expected the stored root key to change")
	}

	// The new key must work.
	c, err := b.getClient(context.Background(), storage)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if _, err := c.GetServiceAccount(context.Background(), after.AdminServiceAccountID); err != nil {
		t.Fatalf("the rotated root key does not work: %v", err)
	}

	t.Logf("root rotated: %s -> %s. The key in your environment is now DELETED; "+
		"update TEMPORAL_CLOUD_API_KEY before the next run.", before.APIKeyID, after.APIKeyID)
}

// TestLive_KeyCapacity proves the ceiling is real and our error fires first.
// It is slow and consumes all 20 slots, so it is opt-in.
func TestLive_KeyCapacity(t *testing.T) {
	if os.Getenv("TEMPORAL_CLOUD_RUN_CAPACITY_TEST") == "" {
		t.Skip("set TEMPORAL_CLOUD_RUN_CAPACITY_TEST=1 to run this; it mints 20 API keys")
	}

	b, storage := liveBackend(t)
	name := acctestName(t)

	createServiceAccount(t, b, storage, name, map[string]interface{}{
		"account_role": "read",
		"ttl":          "10m",
		"max_ttl":      "1h",
	})

	for i := 0; i < client.MaxAPIKeysPerServiceAccount; i++ {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   storage,
		})
		if err != nil || resp == nil || resp.IsError() {
			t.Fatalf("mint %d: err=%v resp=%v", i, err, resp)
		}

		keyID, _ := resp.Data["api_key_id"].(string)
		t.Cleanup(func() {
			c, err := b.getClient(context.Background(), storage)
			if err != nil {
				return
			}
			_ = c.DeleteAPIKey(context.Background(), keyID)
		})
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + name,
		Storage:   storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected the 21st mint to be refused")
	}
	if !strings.Contains(resp.Error().Error(), "20 of 20") {
		t.Errorf("expected our capacity message, got: %v", resp.Error())
	}
}

// TestLive_CountExcludesExpiredKeys was meant to settle the assumption behind
// CountAPIKeys (see the comment there): that Temporal Cloud's GetApiKeys
// response omits keys that no longer occupy one of the 20 slots, so counting
// every returned key without filtering is correct rather than an ever-growing
// overcount.
//
// It cannot do that anymore. The original approach minted a key with a
// 2-minute expiry (bypassing creds/<name>, straight against the client, so
// the expiry would not be clamped to the service account's max_ttl) and
// polled CountAPIKeys until that expiry passed. Live testing found Temporal
// Cloud rejects any expiry less than 24 hours from now (see
// client.MinAPIKeyExpiry) — undocumented, discovered by this project's own
// task-7 mint failures. A 2-minute expiry is no longer mintable at all, and
// waiting out a real 24-hour expiry is not something a test suite should do
// (this run has a 20-minute timeout).
//
// So the question CountAPIKeys' no-filter design depends on — does
// GetApiKeys omit keys that have expired but not yet been deleted? — is
// still open. It cannot be settled within a reasonable test run now that the
// minimum expiry is a day. Skip rather than fabricate a pass.
func TestLive_CountExcludesExpiredKeys(t *testing.T) {
	t.Skip("cannot settle whether GetApiKeys excludes expired-but-undeleted keys: " +
		"Temporal Cloud's undocumented 24-hour minimum expiry (client.MinAPIKeyExpiry) " +
		"means a key can no longer be minted short-lived enough to expire within a " +
		"reasonable test timeout. The question CountAPIKeys' no-filter design relies on " +
		"remains open; see the comment on CountAPIKeys and on this test.")
}
