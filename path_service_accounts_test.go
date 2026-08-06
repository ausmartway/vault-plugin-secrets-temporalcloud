package temporalcloud

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

func TestParseNamespaceAccess(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    map[string]string
		wantErr string
	}{
		{
			name: "single pair",
			in:   []string{"prod.acct1=write"},
			want: map[string]string{"prod.acct1": "write"},
		},
		{
			name: "several pairs",
			in:   []string{"prod.acct1=write", "staging.acct1=read", "dev.acct1=admin"},
			want: map[string]string{"prod.acct1": "write", "staging.acct1": "read", "dev.acct1": "admin"},
		},
		{
			name: "surrounding whitespace is tolerated",
			in:   []string{"  prod.acct1 = write  "},
			want: map[string]string{"prod.acct1": "write"},
		},
		{
			name: "empty input yields no access",
			in:   nil,
			want: map[string]string{},
		},
		{
			name:    "missing equals sign",
			in:      []string{"prod.acct1"},
			wantErr: "namespace=permission",
		},
		{
			name:    "empty namespace",
			in:      []string{"=write"},
			wantErr: "namespace",
		},
		{
			name:    "empty permission",
			in:      []string{"prod.acct1="},
			wantErr: "permission",
		},
		{
			name:    "unknown permission",
			in:      []string{"prod.acct1=sudo"},
			wantErr: "sudo",
		},
		{
			name:    "duplicate namespace",
			in:      []string{"prod.acct1=write", "prod.acct1=read"},
			wantErr: "duplicate",
		},
		{
			name:    "more than one equals sign",
			in:      []string{"prod.acct1=write=read"},
			wantErr: "namespace=permission",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseNamespaceAccess(tc.in)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got %v", tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected the error to mention %q, got: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestServiceAccounts_CreateReadDelete(t *testing.T) {
	b, storage := newTestBackend(t)

	var createdSpec client.ServiceAccountSpec
	deleted := ""
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(_ context.Context, spec client.ServiceAccountSpec) (string, error) {
		createdSpec = spec
		return "sa-created", nil
	}
	stub.deleteServiceAccountFn = func(_ context.Context, id string) error {
		deleted = id
		return nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_role":     "developer",
			"namespace_access": []string{"prod.acct1=write"},
			"description":      "vault managed",
			"ttl":              "1h",
			"max_ttl":          "8h",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create: err=%v resp=%v", err, resp)
	}

	// The name in the path becomes the Temporal Cloud service account name.
	if createdSpec.Name != "prod-workers" {
		t.Errorf("expected the SA to be named prod-workers, got %q", createdSpec.Name)
	}
	if createdSpec.AccountRole != "developer" {
		t.Errorf("expected role developer, got %q", createdSpec.AccountRole)
	}
	if createdSpec.NamespaceAccess["prod.acct1"] != "write" {
		t.Errorf("expected write on prod.acct1, got %v", createdSpec.NamespaceAccess)
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read: err=%v resp=%v", err, resp)
	}
	if resp.Data["service_account_id"] != "sa-created" {
		t.Errorf("expected sa-created, got %v", resp.Data["service_account_id"])
	}
	if resp.Data["account_role"] != "developer" {
		t.Errorf("expected developer, got %v", resp.Data["account_role"])
	}
	if resp.Data["ttl"] != int64(3600) {
		t.Errorf("expected ttl 3600, got %v", resp.Data["ttl"])
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if deleted != "sa-created" {
		t.Errorf("expected the Temporal Cloud SA to be deleted, got %q", deleted)
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("read after delete: %v", err)
	}
	if resp != nil && len(resp.Data) > 0 {
		t.Fatal("expected the entry to be gone after delete")
	}
}

// If Temporal Cloud creates the account but Vault cannot persist it, the
// orphaned account must be cleaned up rather than silently leaked.
func TestServiceAccounts_CompensatesWhenStorageFails(t *testing.T) {
	b, _ := newTestBackend(t)

	deleted := ""
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-orphan", nil
	}
	stub.deleteServiceAccountFn = func(_ context.Context, id string) error {
		deleted = id
		return nil
	}
	withStubClient(b, stub)

	// A storage view that accepts the config write but fails the service
	// account write, so we exercise exactly the compensation path.
	storage := &failingStorage{
		Storage:      &logical.InmemStorage{},
		failOnPrefix: "service-account/",
	}
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/doomed",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "read"},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected the create to fail when storage fails")
	}
	if deleted != "sa-orphan" {
		t.Errorf("expected the orphaned service account to be deleted, got %q", deleted)
	}
}

func TestServiceAccounts_List(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-x", nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	for _, name := range []string{"alpha", "beta"} {
		if _, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "service-accounts/" + name,
			Storage:   storage,
			Data:      map[string]interface{}{"account_role": "read"},
		}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "service-accounts/",
		Storage:   storage,
	})
	if err != nil || resp == nil {
		t.Fatalf("list: err=%v resp=%v", err, resp)
	}

	keys, _ := resp.Data["keys"].([]string)
	if len(keys) != 2 {
		t.Fatalf("expected 2 entries, got %v", keys)
	}
}

// Changing only TTLs must not call Temporal Cloud: nothing about the cloud-side
// resource changed.
func TestServiceAccounts_TTLOnlyUpdateSkipsCloudCall(t *testing.T) {
	b, storage := newTestBackend(t)

	updates := 0
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	stub.updateServiceAccountFn = func(context.Context, string, client.ServiceAccountSpec) error {
		updates++
		return nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	base := map[string]interface{}{"account_role": "read", "ttl": "1h"}
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data:      base,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "read", "ttl": "2h"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	if updates != 0 {
		t.Errorf("expected no UpdateServiceAccount call for a TTL-only change, got %d", updates)
	}
}

// Changing the role must reach Temporal Cloud.
func TestServiceAccounts_RoleChangeCallsCloud(t *testing.T) {
	b, storage := newTestBackend(t)

	updates := 0
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	stub.updateServiceAccountFn = func(context.Context, string, client.ServiceAccountSpec) error {
		updates++
		return nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "read"},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "developer"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	if updates != 1 {
		t.Errorf("expected exactly one UpdateServiceAccount call, got %d", updates)
	}
}

func TestServiceAccounts_Validation(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
	}{
		{"missing account_role", map[string]interface{}{}},
		{"bad account_role", map[string]interface{}{"account_role": "wizard"}},
		{"bad namespace_access", map[string]interface{}{"account_role": "read", "namespace_access": []string{"oops"}}},
		{"ttl greater than max_ttl", map[string]interface{}{"account_role": "read", "ttl": "10h", "max_ttl": "1h"}},
		{"max_ttl beyond two years", map[string]interface{}{"account_role": "read", "max_ttl": "20000h"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := newTestBackend(t)
			withStubClient(b, &stubCloudOps{})
			mustWriteConfig(t, b, storage)

			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "service-accounts/x",
				Storage:   storage,
				Data:      tc.data,
			})
			if err == nil && (resp == nil || !resp.IsError()) {
				t.Fatal("expected an error")
			}
		})
	}
}

// failingStorage fails writes under a given prefix, to exercise compensation.
type failingStorage struct {
	logical.Storage
	failOnPrefix string
}

func (s *failingStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if strings.HasPrefix(entry.Key, s.failOnPrefix) {
		return errors.New("simulated storage failure")
	}
	return s.Storage.Put(ctx, entry)
}
