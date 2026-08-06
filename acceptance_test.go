//go:build acceptance

package temporalcloud

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	cloudservicev1 "go.temporal.io/cloud-sdk/api/cloudservice/v1"
	identityv1 "go.temporal.io/cloud-sdk/api/identity/v1"
	operationv1 "go.temporal.io/cloud-sdk/api/operation/v1"
	"go.temporal.io/cloud-sdk/cloudclient"

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

// responseFields lists the field names in a response, sorted, so a failing
// assertion can say what came back without printing the values. Credential
// responses carry a live Temporal Cloud API token, which must never reach
// test output.
func responseFields(resp *logical.Response) []string {
	if resp == nil {
		return nil
	}
	fields := make([]string, 0, len(resp.Data))
	for name := range resp.Data {
		fields = append(fields, name)
	}
	sort.Strings(fields)
	return fields
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

	c, releaseClient, err := b.getClient(context.Background(), storage)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	t.Cleanup(releaseClient)
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

	// account_role=admin, not read: the probe below (GetServiceAccount) is an
	// identity-management call, and Temporal Cloud restricts identity
	// management to admin-role service accounts. A read-role key would fail
	// this call with "permission denied" even though it authenticated fine —
	// that is a property of the probe, not of what roles this engine
	// supports. This says nothing about read-role keys in general; it is
	// only about which Cloud Ops calls a read-role key may make. Do not
	// "tidy" this back down to read.
	createServiceAccount(t, b, storage, name, map[string]interface{}{
		"account_role": "admin",
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
		// Never print resp.Data: it holds a live Temporal Cloud API token, and
		// test output ends up in CI logs. The field names are enough to see
		// what the response was missing.
		t.Fatalf("expected a token and key ID, got fields %v", responseFields(resp))
	}

	// Clean up the key even if the assertions below fail.
	t.Cleanup(func() {
		c, release, err := b.getClient(context.Background(), storage)
		if err != nil {
			return
		}
		defer release()
		_ = c.DeleteAPIKey(context.Background(), keyID)
	})

	// The minted key must authenticate. Building a client with it and reading
	// its own service account is the cheapest proof (identity management is
	// admin-only, which is why the service account above was given
	// account_role=admin).
	minted, err := client.NewGRPC(client.Config{
		APIKey:   token,
		HostPort: os.Getenv("TEMPORAL_CLOUD_ADDRESS"),
	})
	if err != nil {
		t.Fatalf("building a client with the minted key: %v", err)
	}
	defer func() { _ = minted.Close() }()

	saID, _ := resp.Data["service_account_id"].(string)

	// Temporal Cloud may take a moment to propagate a freshly minted key to
	// its auth layer — live testing observed the first call right after
	// CreateApiKey's async operation completes fail with "request not
	// authenticated" (Unauthenticated), not a permission error. Retry
	// briefly rather than asserting once and flaking on propagation lag.
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, err := minted.GetServiceAccount(context.Background(), saID)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the minted key failed to authenticate: %v", err)
		}
		time.Sleep(2 * time.Second)
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
	revokeDeadline := time.Now().Add(30 * time.Second)
	for {
		_, err := minted.GetServiceAccount(context.Background(), saID)
		if err != nil {
			t.Logf("revoked key correctly rejected: %v", err)
			break
		}
		if time.Now().After(revokeDeadline) {
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
	c, releaseClient, err := b.getClient(context.Background(), storage)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	t.Cleanup(releaseClient)
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
			c, release, err := b.getClient(context.Background(), storage)
			if err != nil {
				return
			}
			defer release()
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
	// A refusal that arrives as a Go error rather than an error response has
	// no resp to inspect — assert on it and move on, rather than dereferencing
	// nil.
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the ceiling to be reported as an error response, got err=%v", err)
	}
	if !strings.Contains(resp.Error().Error(), "20 of 20") {
		t.Errorf("expected our capacity message, got: %v", resp.Error())
	}
}

// TestLive_CountDisabledKey proves the dangerous direction of CountAPIKeys'
// no-filter design (see the comment there) does not happen: a DISABLED key
// still occupies one of the 20 slots, and CountAPIKeys must still count it.
//
// An earlier version of this test tried to settle the other direction —
// whether GetApiKeys omits keys that have merely expired but not yet been
// deleted — by minting a short-lived key and waiting for it to expire. That
// is no longer possible to test in seconds: Temporal Cloud rejects any
// expiry less than 24 hours from now (see client.MinAPIKeyExpiry),
// undocumented, discovered by this project's own live mint failures. That
// question is instead settled by reasoning in the CountAPIKeys comment: an
// unfiltered count can only overcount if expired-but-undeleted keys are
// returned, and overcounting just fails a mint early against our own
// ceiling message — safe. This test covers the direction that IS testable
// live and IS dangerous if wrong: filtering to RESOURCE_STATE_ACTIVE would
// undercount, because a disabled key is not ACTIVE but still holds a slot.
func TestLive_CountDisabledKey(t *testing.T) {
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

	keyID, _ := resp.Data["api_key_id"].(string)
	saID, _ := resp.Data["service_account_id"].(string)
	if keyID == "" || saID == "" {
		// resp.Data holds a live API token; print only the field names.
		t.Fatalf("expected a key ID and service account ID, got fields %v", responseFields(resp))
	}

	// Delete the key immediately, not just at the end of the test: nothing
	// below needs it to survive, so keep the cloud-side cleanup window as
	// short as possible even if an assertion fails.
	c, releaseClient, err := b.getClient(context.Background(), storage)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	t.Cleanup(releaseClient)
	t.Cleanup(func() { _ = c.DeleteAPIKey(context.Background(), keyID) })

	// Disabling isn't exposed on the CloudOps interface — the engine has no
	// need for it — so reach the raw Cloud Ops API the same way the engine's
	// own root credential does, using the admin API key from the
	// environment.
	raw, err := cloudclient.New(cloudclient.Options{
		APIKey:   os.Getenv("TEMPORAL_CLOUD_API_KEY"),
		HostPort: os.Getenv("TEMPORAL_CLOUD_ADDRESS"),
	})
	if err != nil {
		t.Fatalf("building a raw cloudclient: %v", err)
	}
	defer func() { _ = raw.Close() }()
	svc := raw.CloudService()

	got, err := svc.GetApiKey(context.Background(), &cloudservicev1.GetApiKeyRequest{KeyId: keyID})
	if err != nil {
		t.Fatalf("get api key: %v", err)
	}
	spec := got.GetApiKey().GetSpec()

	// UpdateApiKey replaces the whole spec, so carry every existing field
	// forward and flip only Disabled.
	updResp, err := svc.UpdateApiKey(context.Background(), &cloudservicev1.UpdateApiKeyRequest{
		KeyId: keyID,
		Spec: &identityv1.ApiKeySpec{
			OwnerId:     spec.GetOwnerId(),
			OwnerType:   spec.GetOwnerType(),
			DisplayName: spec.GetDisplayName(),
			Description: spec.GetDescription(),
			ExpiryTime:  spec.GetExpiryTime(),
			Disabled:    true,
		},
		ResourceVersion: got.GetApiKey().GetResourceVersion(),
	})
	if err != nil {
		t.Fatalf("disable api key: %v", err)
	}

	// Wait for the disable to actually take effect before asserting on it.
	deadline := time.Now().Add(30 * time.Second)
	for {
		op, err := svc.GetAsyncOperation(context.Background(), &cloudservicev1.GetAsyncOperationRequest{
			AsyncOperationId: updResp.GetAsyncOperation().GetId(),
		})
		if err != nil {
			t.Fatalf("poll disable operation: %v", err)
		}
		state := op.GetAsyncOperation().GetState()
		if state == operationv1.AsyncOperation_STATE_FULFILLED {
			break
		}
		if state == operationv1.AsyncOperation_STATE_FAILED ||
			state == operationv1.AsyncOperation_STATE_CANCELLED ||
			state == operationv1.AsyncOperation_STATE_REJECTED {
			t.Fatalf("disable operation did not succeed: %s: %s", state, op.GetAsyncOperation().GetFailureReason())
		}
		if time.Now().After(deadline) {
			t.Fatal("disabling the key did not complete within 30s")
		}
		time.Sleep(2 * time.Second)
	}

	after, err := svc.GetApiKey(context.Background(), &cloudservicev1.GetApiKeyRequest{KeyId: keyID})
	if err != nil {
		t.Fatalf("get api key after disable: %v", err)
	}
	if !after.GetApiKey().GetSpec().GetDisabled() {
		t.Fatalf("expected the key to be disabled, spec=%v", after.GetApiKey().GetSpec())
	}
	t.Logf("key %s confirmed disabled, state=%s", keyID, after.GetApiKey().GetState())

	// The point of this test: a disabled key is not expired, so it must
	// still be counted toward the 20-key ceiling.
	count, err := c.CountAPIKeys(context.Background(), saID)
	if err != nil {
		t.Fatalf("count api keys: %v", err)
	}
	if count != 1 {
		t.Errorf("expected the disabled key to still be counted (count=1), got %d", count)
	}
}
