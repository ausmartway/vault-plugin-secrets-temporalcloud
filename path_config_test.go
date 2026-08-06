package temporalcloud

import (
	"context"
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
	return &client.ServiceAccount{ID: id}, nil
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

func TestConfig_WriteAndRead(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	withStubClient(b, stub)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  "tmprl_sk_test",
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
			"api_key":                  "tmprl_sk_bad",
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

// Writing config with an admin_service_account_id that does not exist in the
// Temporal Cloud account must be rejected with a message distinct from the
// bad-credential case, so an operator who fat-fingered the ID is pointed at
// admin_service_account_id rather than told to check their api_key.
func TestConfig_WriteRejectsUnknownServiceAccount(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{
		getServiceAccountFn: func(context.Context, string) (*client.ServiceAccount, error) {
			return nil, client.ErrNotFound
		},
	}
	withStubClient(b, stub)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  "tmprl_sk_test",
			"admin_service_account_id": "sa-does-not-exist",
		},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected writing config with an unknown admin_service_account_id to fail")
	}

	// The message must name the offending ID and point at
	// admin_service_account_id, so it reads differently from the
	// bad-credential (ErrPermissionDenied) message.
	msg := resp.Error().Error()
	if !strings.Contains(msg, "sa-does-not-exist") {
		t.Errorf("expected error to name the service account ID, got: %s", msg)
	}
	if !strings.Contains(msg, "admin_service_account_id") {
		t.Errorf("expected error to mention admin_service_account_id, got: %s", msg)
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

func TestConfig_RequiredFields(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
	}{
		{"missing api_key", map[string]interface{}{"admin_service_account_id": "sa-1"}},
		{"missing admin_service_account_id", map[string]interface{}{"api_key": "tmprl_sk_x"}},
		{"empty api_key", map[string]interface{}{"api_key": "", "admin_service_account_id": "sa-1"}},
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
			"api_key":                  "tmprl_sk_test",
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
			"api_key":                  "tmprl_sk_test",
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

// mustWriteConfig writes a valid config, failing the test if it does not take.
func mustWriteConfig(t *testing.T, b *backend, storage logical.Storage) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  "tmprl_sk_test",
			"api_key_id":               "key-bootstrap",
			"admin_service_account_id": "sa-123",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write config: err=%v resp=%v", err, resp)
	}
}
