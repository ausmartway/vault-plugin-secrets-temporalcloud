package temporalcloud

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

// stubCloudOps records calls and returns canned responses. Later tasks extend
// it; keep the zero value usable so tests only set what they care about.
type stubCloudOps struct {
	getServiceAccountFn        func(ctx context.Context, id string) (*client.ServiceAccount, error)
	createServiceAccountFn     func(ctx context.Context, spec client.ServiceAccountSpec) (string, error)
	updateServiceAccountFn     func(ctx context.Context, id string, spec client.ServiceAccountSpec) error
	deleteServiceAccountFn     func(ctx context.Context, id string) error
	createAPIKeyFn             func(ctx context.Context, spec client.APIKeySpec) (*client.APIKey, error)
	getAPIKeyFn                func(ctx context.Context, id string) (*client.APIKeyMetadata, error)
	deleteAPIKeyFn             func(ctx context.Context, id string) error
	countAPIKeysFn             func(ctx context.Context, saID string) (int, error)
	findServiceAccountByNameFn func(ctx context.Context, name string) (*client.ServiceAccount, error)

	deletedAPIKeys []string
	closed         bool
}

func (s *stubCloudOps) CreateServiceAccount(ctx context.Context, spec client.ServiceAccountSpec) (string, error) {
	if s.createServiceAccountFn != nil {
		return s.createServiceAccountFn(ctx, spec)
	}
	return "sa-stub", nil
}

func (s *stubCloudOps) GetServiceAccount(ctx context.Context, id string) (*client.ServiceAccount, error) {
	if s.getServiceAccountFn != nil {
		return s.getServiceAccountFn(ctx, id)
	}
	return &client.ServiceAccount{
		ID: id,
		Spec: client.ServiceAccountSpec{
			AccountRole: "admin",
		},
	}, nil
}

func (s *stubCloudOps) UpdateServiceAccount(ctx context.Context, id string, spec client.ServiceAccountSpec) error {
	if s.updateServiceAccountFn != nil {
		return s.updateServiceAccountFn(ctx, id, spec)
	}
	return nil
}

func (s *stubCloudOps) DeleteServiceAccount(ctx context.Context, id string) error {
	if s.deleteServiceAccountFn != nil {
		return s.deleteServiceAccountFn(ctx, id)
	}
	return nil
}

func (s *stubCloudOps) CreateAPIKey(ctx context.Context, spec client.APIKeySpec) (*client.APIKey, error) {
	if s.createAPIKeyFn != nil {
		return s.createAPIKeyFn(ctx, spec)
	}
	return &client.APIKey{ID: "key-stub", Token: "tmprl_sk_stub"}, nil
}

func (s *stubCloudOps) GetAPIKey(ctx context.Context, id string) (*client.APIKeyMetadata, error) {
	if s.getAPIKeyFn != nil {
		return s.getAPIKeyFn(ctx, id)
	}
	return &client.APIKeyMetadata{
		ID:        id,
		OwnerID:   "sa-123",
		OwnerType: client.APIKeyOwnerServiceAccount,
	}, nil
}

func (s *stubCloudOps) DeleteAPIKey(ctx context.Context, id string) error {
	s.deletedAPIKeys = append(s.deletedAPIKeys, id)
	if s.deleteAPIKeyFn != nil {
		return s.deleteAPIKeyFn(ctx, id)
	}
	return nil
}

func (s *stubCloudOps) CountAPIKeys(ctx context.Context, saID string) (int, error) {
	if s.countAPIKeysFn != nil {
		return s.countAPIKeysFn(ctx, saID)
	}
	return 0, nil
}

// FindServiceAccountByName defaults to ErrNotFound when no hook is set, so
// every test written before this hook existed keeps taking the ordinary
// create path unchanged.
func (s *stubCloudOps) FindServiceAccountByName(ctx context.Context, name string) (*client.ServiceAccount, error) {
	if s.findServiceAccountByNameFn != nil {
		return s.findServiceAccountByNameFn(ctx, name)
	}
	return nil, client.ErrNotFound
}

func (s *stubCloudOps) Close() error {
	s.closed = true
	return nil
}

// withStubClient makes the backend use the given stub instead of dialling
// Temporal Cloud.
func withStubClient(b *backend, stub client.CloudOps) {
	b.newClient = func(client.Config) (client.CloudOps, error) { return stub, nil }
}

// Updating config must not silently reset fields the operator did not mention.
// Both address and root_key_ttl carry framework defaults, so d.Get returns the
// default for an absent field — without merging, a write that changes only the
// credential reverts a PrivateLink address to the public endpoint and a tuned
// root_key_ttl to 90 days, neither of which the operator asked for.
func TestConfig_UpdateMergesAddressAndRootKeyTTL(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})

	write := func(data map[string]interface{}) {
		t.Helper()
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data:      data,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("write config: err=%v resp=%v", err, resp)
		}
	}

	write(map[string]interface{}{
		"api_key":                  testAPIKey("key-first"),
		"admin_service_account_id": "sa-123",
		"address":                  "privatelink.example.com:443",
		"root_key_ttl":             "720h",
	})

	// A credential swap that mentions neither field.
	write(map[string]interface{}{
		"api_key":                  testAPIKey("key-second"),
		"admin_service_account_id": "sa-123",
	})

	cfg, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	if cfg.Address != "privatelink.example.com:443" {
		t.Errorf("expected the address to survive an unrelated update, got %q", cfg.Address)
	}
	if cfg.RootKeyTTL != 720*time.Hour {
		t.Errorf("expected root_key_ttl to survive, got %s", cfg.RootKeyTTL)
	}
	if cfg.APIKey != testAPIKey("key-second") {
		t.Errorf("expected the credential to be replaced, got %q", cfg.APIKey)
	}

	// Passing them explicitly still changes them.
	write(map[string]interface{}{
		"api_key":                  testAPIKey("key-second"),
		"admin_service_account_id": "sa-123",
		"address":                  "saas-api.tmprl.cloud:443",
	})
	cfg, _ = b.getConfig(context.Background(), storage)
	if cfg.Address != "saas-api.tmprl.cloud:443" {
		t.Errorf("expected an explicit address to take effect, got %q", cfg.Address)
	}
}

// api_key_id is read-only. Accepting one would mean trusting a value nothing
// can verify: no Cloud Ops call maps a token back to its ID, and rotate-root
// deletes whatever this ID names. A write that sets it must be rejected
// outright rather than silently ignored, so an operator who believes they are
// configuring cleanup finds out that they are not.
func TestConfig_APIKeyIDIsRejectedAsInput(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  testAPIKey("key-1"),
			"admin_service_account_id": "sa-123",
			"api_key_id":               "apikey-supplied",
		},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected a write setting api_key_id to be rejected")
	}

	msg := ""
	if resp != nil && resp.IsError() {
		msg = resp.Error().Error()
	} else if err != nil {
		msg = err.Error()
	}
	if !strings.Contains(msg, "api_key_id") {
		t.Errorf("expected the error to name the offending field, got: %s", msg)
	}
}

// The stored ID is read out of the key itself, so it always describes the key
// actually in use. This is what lets rotate-root delete the key it replaces
// even on the very first rotation, including for a key an operator pasted in
// by hand — the case that previously had no answer at all.
func TestConfig_APIKeyIDIsDerivedFromTheKey(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})

	write := func(data map[string]interface{}) {
		t.Helper()
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data:      data,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("write config: err=%v resp=%v", err, resp)
		}
	}

	write(map[string]interface{}{
		"api_key":                  testAPIKey("apikey-first"),
		"admin_service_account_id": "sa-123",
	})
	cfg, _ := b.getConfig(context.Background(), storage)
	if cfg.APIKeyID != "apikey-first" {
		t.Fatalf("expected the ID to be read from the key, got %q", cfg.APIKeyID)
	}

	// A different key means a different ID, tracked automatically. Nothing
	// carries over, so the stored ID can never name the previous key.
	write(map[string]interface{}{
		"api_key":                  testAPIKey("apikey-second"),
		"admin_service_account_id": "sa-123",
	})
	cfg, _ = b.getConfig(context.Background(), storage)
	if cfg.APIKeyID != "apikey-second" {
		t.Errorf("expected the ID to follow the new key, got %q", cfg.APIKeyID)
	}

	// And it is what a read reports.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if resp.Data["api_key_id"] != "apikey-second" {
		t.Errorf("expected the read to report apikey-second, got %v", resp.Data["api_key_id"])
	}
}

// A key whose ID cannot be read is rejected, and nothing is stored. Accepting
// it would produce a mount that works right up until it has to rotate, and then
// strands the key it was supposed to replace — a failure deferred to the least
// convenient moment. Every real Temporal Cloud API key parses, so in practice
// this fires on a truncated paste or the wrong string entirely, which is
// exactly when an operator wants to hear about it.
func TestConfig_RejectsKeyWhoseIDCannotBeRead(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	withStubClient(b, stub)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  "tmprl_sk_not_a_jwt",
			"admin_service_account_id": "sa-123",
		},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected a key with no readable ID to be rejected")
	}
	if !strings.Contains(resp.Error().Error(), "api_key") {
		t.Errorf("expected the error to name the offending field, got: %v", resp.Error())
	}

	// Nothing may be persisted by a rejected write.
	cfg, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected no config to be stored, got %+v", cfg)
	}
}

func TestConfig_WriteAndRead(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	withStubClient(b, stub)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  testAPIKey("key-1"),
			"admin_service_account_id": "sa-123",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write config: err=%v resp=%v", err, resp)
	}

	// The validation client is throwaway: it must be closed on the success
	// path too, or a successful write leaks a gRPC connection.
	if !stub.closed {
		t.Error("expected the validation client to be closed after a successful write")
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read config: err=%v resp=%v", err, resp)
	}

	if got := resp.Data["admin_service_account_id"]; got != "sa-123" {
		t.Errorf("expected sa-123, got %v", got)
	}
	// Defaults must be applied and visible.
	if got := resp.Data["address"]; got != "saas-api.tmprl.cloud:443" {
		t.Errorf("expected the default address, got %v", got)
	}
	if got := resp.Data["root_key_ttl"]; got != int64((2160 * time.Hour).Seconds()) {
		t.Errorf("expected the default root_key_ttl, got %v", got)
	}
}

// The root API key must never be readable back out of Vault.
func TestConfig_ReadNeverReturnsAPIKey(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})

	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	if _, present := resp.Data["api_key"]; present {
		t.Fatal("api_key must never be returned from a config read")
	}
}

// Writing config validates the credential by calling GetServiceAccount. A
// credential that does not work must be rejected at write time, not at first
// use, so the operator finds out immediately.
func TestConfig_WriteRejectsBadCredential(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{
		getServiceAccountFn: func(context.Context, string) (*client.ServiceAccount, error) {
			return nil, client.ErrPermissionDenied
		},
	}
	withStubClient(b, stub)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  testAPIKey("key-bad"),
			"admin_service_account_id": "sa-123",
		},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected writing an invalid credential to fail")
	}

	// The validation client must be closed even when validation fails, or a
	// rejected config write leaks a gRPC connection.
	if !stub.closed {
		t.Error("expected the validation client to be closed after a rejected write")
	}

	// Nothing may be persisted when validation fails.
	entry, err := storage.Get(context.Background(), configStoragePath)
	if err != nil {
		t.Fatalf("storage get: %v", err)
	}
	if entry != nil {
		t.Fatal("config must not be persisted when validation fails")
	}
}

// The credential a write validates must be the credential that write is
// storing — otherwise "validated before saved" is not true of the key actually
// being saved.
//
// This is a real refactor hazard rather than a hypothetical: the backend
// already has a cached client (b.getClient), and reaching for it here instead
// of building one from the config under construction would validate whatever
// credential the mount is *currently* using. Every test above would still
// pass, and the mount would accept any key at all on update, discovering the
// bad one at the next creds/ read.
func TestConfig_ValidatesTheKeyBeingWritten(t *testing.T) {
	b, storage := newTestBackend(t)

	var gotConfigs []client.Config
	b.newClient = func(cfg client.Config) (client.CloudOps, error) {
		gotConfigs = append(gotConfigs, cfg)
		return &stubCloudOps{}, nil
	}

	write := func(op logical.Operation, key, address string) {
		t.Helper()
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: op,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"api_key":                  key,
				"admin_service_account_id": "sa-123",
				"address":                  address,
			},
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("write config: err=%v resp=%v", err, resp)
		}
	}

	firstKey := testAPIKey("key-first")
	write(logical.CreateOperation, firstKey, "privatelink.example.com:443")

	if len(gotConfigs) != 1 {
		t.Fatalf("expected exactly one client built for validation, got %d", len(gotConfigs))
	}
	if gotConfigs[0].APIKey != firstKey {
		t.Error("validation used a different credential than the one being written")
	}
	if gotConfigs[0].HostPort != "privatelink.example.com:443" {
		t.Errorf("validation dialled %q, not the address being written", gotConfigs[0].HostPort)
	}

	// The update case is the one that matters, and the only one that can catch
	// a validation that reaches for the mount's current credential: on create
	// there is no previous config to reach for, so both behave identically.
	secondKey := testAPIKey("key-second")
	write(logical.UpdateOperation, secondKey, "other.example.com:443")

	if len(gotConfigs) != 2 {
		t.Fatalf("expected a second client built for the update, got %d", len(gotConfigs))
	}
	if gotConfigs[1].APIKey == firstKey {
		t.Fatal("the update validated the previously stored credential, not the new one — " +
			"any key would be accepted on update")
	}
	if gotConfigs[1].APIKey != secondKey {
		t.Error("validation used a different credential than the one being written")
	}
	if gotConfigs[1].HostPort != "other.example.com:443" {
		t.Errorf("validation dialled %q, not the address being written", gotConfigs[1].HostPort)
	}
}

// A rejected update must leave the previous configuration exactly as it was.
// This is the damaging direction: a mount that is working, handed a bad key,
// must keep working rather than be left holding a credential that was never
// proven — and the operator gets an error either way, so the only difference
// is whether the mount survives it.
func TestConfig_FailedUpdateLeavesExistingConfigIntact(t *testing.T) {
	b, storage := newTestBackend(t)

	// A first write that validates cleanly.
	good := &stubCloudOps{}
	withStubClient(b, good)
	if resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  testAPIKey("key-good"),
			"admin_service_account_id": "sa-123",
			"address":                  "privatelink.example.com:443",
			"root_key_ttl":             "720h",
		},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("first write: err=%v resp=%v", err, resp)
	}

	before, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}

	// Now an update whose credential Temporal Cloud rejects.
	withStubClient(b, &stubCloudOps{
		getServiceAccountFn: func(context.Context, string) (*client.ServiceAccount, error) {
			return nil, client.ErrPermissionDenied
		},
	})
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  testAPIKey("key-rejected"),
			"admin_service_account_id": "sa-123",
		},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected the update to be rejected")
	}

	after, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	if *after != *before {
		t.Errorf("a rejected update changed the stored config:\n before %+v\n after  %+v", before, after)
	}
}

func TestConfig_DerivesServiceAccountOwner(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{
		getAPIKeyFn: func(_ context.Context, id string) (*client.APIKeyMetadata, error) {
			return &client.APIKeyMetadata{
				ID: id, OwnerID: "sa-derived", OwnerType: client.APIKeyOwnerServiceAccount,
			}, nil
		},
		getServiceAccountFn: func(_ context.Context, id string) (*client.ServiceAccount, error) {
			if id != "sa-derived" {
				t.Fatalf("validated service account %q, want derived owner", id)
			}
			return &client.ServiceAccount{
				ID: id,
				Spec: client.ServiceAccountSpec{
					AccountRole: "admin",
				},
			}, nil
		},
	}
	withStubClient(b, stub)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]interface{}{"api_key": testAPIKey("key-1")},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write config without admin_service_account_id: err=%v resp=%v", err, resp)
	}

	cfg, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminServiceAccountID != "sa-derived" {
		t.Fatalf("admin service account = %q, want sa-derived", cfg.AdminServiceAccountID)
	}
}

func TestConfig_AcceptsAccountOwnerWithWarning(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{
		getServiceAccountFn: func(_ context.Context, id string) (*client.ServiceAccount, error) {
			return &client.ServiceAccount{
				ID: id,
				Spec: client.ServiceAccountSpec{
					AccountRole: "owner",
				},
			}, nil
		},
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]interface{}{"api_key": testAPIKey("key-owner")},
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("write Account Owner config: err=%v resp=%v", err, resp)
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "Global Admin is recommended") {
		t.Fatalf("warnings = %v, want Global Admin recommendation", resp.Warnings)
	}
	if cfg, err := b.getConfig(context.Background(), storage); err != nil || cfg == nil {
		t.Fatalf("Account Owner config was not stored: cfg=%v err=%v", cfg, err)
	}
}

func TestConfig_RejectsInsufficientAccountRole(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{
		getServiceAccountFn: func(_ context.Context, id string) (*client.ServiceAccount, error) {
			return &client.ServiceAccount{
				ID: id,
				Spec: client.ServiceAccountSpec{
					AccountRole: "read",
				},
			}, nil
		},
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]interface{}{"api_key": testAPIKey("key-read")},
	})
	if err != nil || resp == nil || !resp.IsError() {
		t.Fatalf("expected Read-Only root rejection: err=%v resp=%v", err, resp)
	}
	msg := resp.Error().Error()
	if !strings.Contains(msg, `account role "read"`) || !strings.Contains(msg, "requires the Global Admin role") {
		t.Fatalf("unclear role error: %s", msg)
	}
	if entry, _ := storage.Get(context.Background(), configStoragePath); entry != nil {
		t.Fatal("insufficiently privileged root key must not be stored")
	}
}

func TestConfig_RejectsUserOwnedAPIKey(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{
		getAPIKeyFn: func(_ context.Context, id string) (*client.APIKeyMetadata, error) {
			return &client.APIKeyMetadata{
				ID: id, OwnerID: "user-123", OwnerType: client.APIKeyOwnerUser,
			}, nil
		},
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]interface{}{"api_key": testAPIKey("key-user")},
	})
	if err != nil || resp == nil || !resp.IsError() {
		t.Fatalf("expected user-owned key rejection: err=%v resp=%v", err, resp)
	}
	msg := resp.Error().Error()
	if !strings.Contains(msg, "owned by a Temporal Cloud user") || !strings.Contains(msg, "service-account-owned") {
		t.Fatalf("unclear user-key error: %s", msg)
	}
	if entry, _ := storage.Get(context.Background(), configStoragePath); entry != nil {
		t.Fatal("user-owned key must not be stored")
	}
}

func TestConfig_RejectsMismatchedCompatibilityOwnerID(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  testAPIKey("key-1"),
			"admin_service_account_id": "sa-wrong",
		},
	})
	if err != nil || resp == nil || !resp.IsError() {
		t.Fatalf("expected mismatched owner rejection: err=%v resp=%v", err, resp)
	}
	msg := resp.Error().Error()
	if !strings.Contains(msg, "sa-wrong") || !strings.Contains(msg, "sa-123") {
		t.Fatalf("owner mismatch error = %s", msg)
	}
}

func TestConfig_RejectsMissingDerivedServiceAccount(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{
		getAPIKeyFn: func(_ context.Context, id string) (*client.APIKeyMetadata, error) {
			return &client.APIKeyMetadata{
				ID: id, OwnerID: "sa-missing", OwnerType: client.APIKeyOwnerServiceAccount,
			}, nil
		},
		getServiceAccountFn: func(context.Context, string) (*client.ServiceAccount, error) {
			return nil, client.ErrNotFound
		},
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]interface{}{"api_key": testAPIKey("key-1")},
	})
	if err != nil || resp == nil || !resp.IsError() {
		t.Fatalf("expected missing owner rejection: err=%v resp=%v", err, resp)
	}
	if msg := resp.Error().Error(); !strings.Contains(msg, "sa-missing") {
		t.Fatalf("error does not name derived owner: %s", msg)
	}
}

func TestConfig_RequiredFields(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
	}{
		{"missing api_key", map[string]interface{}{}},
		{"empty api_key", map[string]interface{}{"api_key": ""}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := newTestBackend(t)
			withStubClient(b, &stubCloudOps{})

			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "config",
				Storage:   storage,
				Data:      tc.data,
			})
			if err == nil && (resp == nil || !resp.IsError()) {
				t.Fatal("expected an error")
			}
		})
	}
}

// root_key_ttl beyond Temporal Cloud's two-year maximum must be rejected here
// rather than by Temporal Cloud at rotation time.
func TestConfig_RejectsRootKeyTTLOverTwoYears(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  testAPIKey("key-1"),
			"admin_service_account_id": "sa-123",
			"root_key_ttl":             "20000h", // well over 2 years
		},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected root_key_ttl over two years to be rejected")
	}
}

// Temporal Cloud also enforces an undocumented 24-hour minimum expiry, so a
// root_key_ttl below it must be refused here. Accepting it would leave
// rotate-root failing later with Temporal Cloud's own raw message, and the
// operator with no idea the value they set was the cause.
func TestConfig_RejectsRootKeyTTLUnderTheMinimum(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  testAPIKey("key-1"),
			"admin_service_account_id": "sa-123",
			"root_key_ttl":             "1h", // the "let me demo rotation quickly" value
		},
	})
	if err != nil {
		t.Fatalf("expected an error response, not a 500: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected root_key_ttl under 24h to be rejected")
	}

	// The message must name the minimum, or the operator has to guess what
	// value would be accepted.
	msg := resp.Error().Error()
	if !strings.Contains(msg, client.MinAPIKeyExpiry.String()) {
		t.Errorf("expected the error to name the %s minimum, got: %s", client.MinAPIKeyExpiry, msg)
	}

	entry, err := storage.Get(context.Background(), configStoragePath)
	if err != nil {
		t.Fatalf("storage get: %v", err)
	}
	if entry != nil {
		t.Fatal("config must not be persisted when root_key_ttl is rejected")
	}
}

func TestConfig_Delete(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})
	mustWriteConfig(t, b, storage)

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   storage,
	}); err != nil {
		t.Fatalf("delete config: %v", err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("read after delete: %v", err)
	}
	if resp != nil && len(resp.Data) > 0 {
		t.Fatal("expected no config after delete")
	}
}

// testAPIKey builds a token shaped like a real Temporal Cloud API key, whose
// payload names the given key ID. The engine derives api_key_id from the token
// itself, so tests that care about that ID hand it a key that actually carries
// one, rather than reaching behind the path to seed storage.
//
// The header and signature are filler: nothing verifies them, and a real key
// as a fixture would put a live credential in the repository.
func testAPIKey(keyID string) string {
	enc := func(s string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	}
	return strings.Join([]string{
		enc(`{"alg":"ES256","kid":"example"}`),
		enc(fmt.Sprintf(
			`{"account_id":"acct1","aud":["temporal.io"],"iss":"temporal.io",`+
				`"jti":%q,"key_id":%q,"sub":"sa-123"}`, keyID, keyID)),
		enc("signature"),
	}, ".")
}

// mustWriteConfig writes a valid config, failing the test if it does not take.
// The key it writes carries the ID "key-bootstrap", which is therefore what
// the engine derives and stores.
func mustWriteConfig(t *testing.T, b *backend, storage logical.Storage) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  testAPIKey("key-bootstrap"),
			"admin_service_account_id": "sa-123",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write config: err=%v resp=%v", err, resp)
	}
}
