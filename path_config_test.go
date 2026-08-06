package temporalcloud

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

// stubCloudOps records calls and returns canned responses. Later tasks extend
// it; keep the zero value usable so tests only set what they care about.
type stubCloudOps struct {
	getServiceAccountFn func(ctx context.Context, id string) (*client.ServiceAccount, error)
	createAPIKeyFn      func(ctx context.Context, spec client.APIKeySpec) (*client.APIKey, error)
	deleteAPIKeyFn      func(ctx context.Context, id string) error
	countAPIKeysFn      func(ctx context.Context, saID string) (int, error)

	deletedAPIKeys []string
	closed         bool
}

func (s *stubCloudOps) CreateServiceAccount(context.Context, client.ServiceAccountSpec) (string, error) {
	return "", errors.New("not implemented in this stub")
}

func (s *stubCloudOps) GetServiceAccount(ctx context.Context, id string) (*client.ServiceAccount, error) {
	if s.getServiceAccountFn != nil {
		return s.getServiceAccountFn(ctx, id)
	}
	return &client.ServiceAccount{ID: id}, nil
}

func (s *stubCloudOps) UpdateServiceAccount(context.Context, string, client.ServiceAccountSpec) error {
	return errors.New("not implemented in this stub")
}

func (s *stubCloudOps) DeleteServiceAccount(context.Context, string) error {
	return errors.New("not implemented in this stub")
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
	withStubClient(b, &stubCloudOps{})

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
	withStubClient(b, &stubCloudOps{
		getServiceAccountFn: func(context.Context, string) (*client.ServiceAccount, error) {
			return nil, client.ErrPermissionDenied
		},
	})

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
