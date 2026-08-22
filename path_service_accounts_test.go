package temporalcloud

import (
	"context"
	"errors"
	"fmt"
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

// If adoption succeeds (Temporal Cloud already updated) but the Vault storage
// write then fails, the compensating delete must NOT run: Vault did not
// create this account, so it has no right to delete it just because its own
// storage write failed. This is the guard that distinguishes the adopted
// branch from the created branch above.
func TestServiceAccounts_DoesNotCompensateWhenAdoptedAndStorageFails(t *testing.T) {
	b, _ := newTestBackend(t)

	deleteCalled := false
	stub := &stubCloudOps{}
	stub.findServiceAccountByNameFn = func(_ context.Context, name string) (*client.ServiceAccount, error) {
		return &client.ServiceAccount{ID: "sa-existing"}, nil
	}
	stub.deleteServiceAccountFn = func(_ context.Context, id string) error {
		deleteCalled = true
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
		Data: map[string]interface{}{
			"account_role": "read",
			"force":        true,
		},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected the adopt to fail when storage fails")
	}
	if deleteCalled {
		t.Error("expected DeleteServiceAccount not to be called for an adopted account")
	}
}

// Temporal Cloud requires service-account names to be unique. Creating a name
// that already exists there must be refused, name the colliding account's ID,
// and never call CreateServiceAccount or persist anything.
func TestServiceAccounts_CollisionRefusedByDefault(t *testing.T) {
	b, storage := newTestBackend(t)

	createCalled := false
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		createCalled = true
		return "sa-new", nil
	}
	stub.findServiceAccountByNameFn = func(_ context.Context, name string) (*client.ServiceAccount, error) {
		return &client.ServiceAccount{ID: "sa-existing"}, nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "developer"},
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected an error response, got %v", resp)
	}
	if !strings.Contains(resp.Error().Error(), "sa-existing") {
		t.Errorf("expected the error to name the colliding account's ID, got: %v", resp.Error())
	}
	if !strings.Contains(resp.Error().Error(), "already exists") {
		t.Errorf("expected the error to say the name is already in use, got: %v", resp.Error())
	}
	if !strings.Contains(resp.Error().Error(), "force=true") {
		t.Errorf("expected the error to mention force=true as an option, got: %v", resp.Error())
	}
	if createCalled {
		t.Error("expected CreateServiceAccount not to be called on a collision")
	}

	entry, err := storage.Get(context.Background(), serviceAccountStoragePath("prod-workers"))
	if err != nil {
		t.Fatalf("storage get: %v", err)
	}
	if entry != nil {
		t.Fatal("expected nothing to be persisted when the create is refused")
	}
}

// force=true on a colliding name adopts the existing account: it resets that
// account's permissions to the requested spec via UpdateServiceAccount rather
// than creating a new one, and the stored entry remembers it was adopted.
func TestServiceAccounts_CollisionAdoptedWithForce(t *testing.T) {
	b, storage := newTestBackend(t)

	createCalled := false
	var updatedID string
	var updatedSpec client.ServiceAccountSpec
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		createCalled = true
		return "sa-new", nil
	}
	stub.findServiceAccountByNameFn = func(_ context.Context, name string) (*client.ServiceAccount, error) {
		return &client.ServiceAccount{ID: "sa-existing"}, nil
	}
	stub.updateServiceAccountFn = func(_ context.Context, id string, spec client.ServiceAccountSpec) error {
		updatedID = id
		updatedSpec = spec
		return nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_role": "developer",
			"force":        true,
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("adopt: err=%v resp=%v", err, resp)
	}
	if createCalled {
		t.Error("expected CreateServiceAccount not to be called when adopting")
	}
	if updatedID != "sa-existing" {
		t.Errorf("expected UpdateServiceAccount to target sa-existing, got %q", updatedID)
	}
	if updatedSpec.AccountRole != "developer" {
		t.Errorf("expected the adoption update to carry the requested spec, got %v", updatedSpec)
	}

	entry, err := b.getServiceAccount(context.Background(), storage, "prod-workers")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if entry == nil {
		t.Fatal("expected an entry to be stored")
	}
	if entry.ServiceAccountID != "sa-existing" {
		t.Errorf("expected the stored entry to carry the existing account's ID, got %q", entry.ServiceAccountID)
	}
	if !entry.Adopted {
		t.Error("expected the stored entry to be marked Adopted")
	}
}

// Adoption is a property of how the binding came to exist, so it must survive
// ordinary updates. entry is rebuilt from the request on every write and force
// is read fresh, so without carrying Adopted forward a later write silently
// clears it — and Adopted is the only thing telling an operator that Vault
// manages an account it did not create, and that deleting this entry destroys
// it anyway.
func TestServiceAccounts_AdoptedSurvivesUpdate(t *testing.T) {
	b, storage := newTestBackend(t)

	stub := &stubCloudOps{}
	stub.findServiceAccountByNameFn = func(context.Context, string) (*client.ServiceAccount, error) {
		return &client.ServiceAccount{ID: "sa-existing"}, nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "developer", "force": true},
	}); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	// An ordinary update touching only the role.
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "admin"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	entry, err := b.getServiceAccount(context.Background(), storage, "prod-workers")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !entry.Adopted {
		t.Error("expected Adopted to survive an unrelated update")
	}

	// And what the operator actually sees, which is the point of the field.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.Data["adopted"] != true {
		t.Errorf("expected vault read to still report adopted=true, got %v", resp.Data["adopted"])
	}
}

// A create whose Temporal Cloud operation fails can still leave a service
// account behind: CreateServiceAccount returns the id precisely so the caller
// can clean it up. A leaked account holds the name, so every retry of this
// write would then collide with something the operator never asked for.
func TestServiceAccounts_DeletesAccountWhenCreateFails(t *testing.T) {
	b, storage := newTestBackend(t)

	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		// The shape CreateServiceAccount returns when the create was accepted
		// but the wait for the async operation failed.
		return "sa-halfmade", fmt.Errorf("%w: operation failed", client.ErrInvalidArgument)
	}
	var deleted []string
	stub.deleteServiceAccountFn = func(_ context.Context, id string) error {
		deleted = append(deleted, id)
		return nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "developer"},
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected an error response, got %v", resp)
	}

	if len(deleted) != 1 || deleted[0] != "sa-halfmade" {
		t.Errorf("expected the half-created account to be deleted, got %v", deleted)
	}

	// And nothing should be stored for a write that failed.
	entry, err := b.getServiceAccount(context.Background(), storage, "prod-workers")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if entry != nil {
		t.Error("expected no stored entry after a failed create")
	}
}

// With no collision, force=true behaves exactly like an ordinary create: it
// means "adopt if it exists," not "require that it exists."
func TestServiceAccounts_NoCollisionForceStillCreates(t *testing.T) {
	b, storage := newTestBackend(t)

	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-created", nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_role": "developer",
			"force":        true,
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create: err=%v resp=%v", err, resp)
	}

	entry, err := b.getServiceAccount(context.Background(), storage, "prod-workers")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if entry == nil {
		t.Fatal("expected an entry to be stored")
	}
	if entry.ServiceAccountID != "sa-created" {
		t.Errorf("expected the created account's ID, got %q", entry.ServiceAccountID)
	}
	if entry.Adopted {
		t.Error("expected Adopted to be false when there was no collision")
	}
}

// force is ignored on update: an entry Vault already manages takes the
// ordinary merge path, and no name lookup happens because the
// binding already exists.
func TestServiceAccounts_ForceIgnoredOnUpdate(t *testing.T) {
	b, storage := newTestBackend(t)

	lookupCalled := false
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-created", nil
	}
	stub.findServiceAccountByNameFn = func(context.Context, string) (*client.ServiceAccount, error) {
		lookupCalled = true
		return nil, client.ErrNotFound
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "developer"},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	lookupCalled = false // reset: the create above legitimately looked it up

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_role": "admin",
			"force":        true,
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("update: err=%v resp=%v", err, resp)
	}
	if lookupCalled {
		t.Error("expected FindServiceAccountByName not to be called on update")
	}
}

// The read handler must surface whether an entry was adopted, in both
// directions.
func TestServiceAccounts_ReadSurfacesAdopted(t *testing.T) {
	b, storage := newTestBackend(t)

	stub := &stubCloudOps{}
	stub.findServiceAccountByNameFn = func(_ context.Context, name string) (*client.ServiceAccount, error) {
		return &client.ServiceAccount{ID: "sa-existing"}, nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	// Adopted case.
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/adopted-sa",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_role": "developer",
			"force":        true,
		},
	}); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/adopted-sa",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read: err=%v resp=%v", err, resp)
	}
	if resp.Data["adopted"] != true {
		t.Errorf("expected adopted=true, got %v", resp.Data["adopted"])
	}

	// Non-adopted case.
	stub.findServiceAccountByNameFn = func(context.Context, string) (*client.ServiceAccount, error) {
		return nil, client.ErrNotFound
	}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-created", nil
	}
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/created-sa",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "developer"},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/created-sa",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read: err=%v resp=%v", err, resp)
	}
	if resp.Data["adopted"] != false {
		t.Errorf("expected adopted=false, got %v", resp.Data["adopted"])
	}
}

// A lookup failure that is not ErrNotFound must fail the write outright. We do
// not know whether the name is free, so falling through to create would risk
// creating the very duplicate this check exists to prevent.
func TestServiceAccounts_LookupFailureDoesNotFallThroughToCreate(t *testing.T) {
	b, storage := newTestBackend(t)

	createCalled := false
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		createCalled = true
		return "sa-new", nil
	}
	stub.findServiceAccountByNameFn = func(context.Context, string) (*client.ServiceAccount, error) {
		return nil, client.ErrUnavailable
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "developer"},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected the write to fail when the collision lookup fails")
	}
	if createCalled {
		t.Error("expected CreateServiceAccount not to be called after a lookup failure")
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

// This is the regression test for the defect: a partial update (only
// account_role supplied) must not touch namespace_access, ttl, or max_ttl, and
// because nothing Temporal Cloud knows about actually changed, it must not call
// UpdateServiceAccount at all. Before the fix, d.Get("namespace_access")
// returned the zero value ([]string{}) on this request, which cleared the
// stored permission and triggered an unwanted UpdateServiceAccount call that
// would have revoked it in Temporal Cloud.
func TestServiceAccounts_PartialUpdatePreservesOmittedFields(t *testing.T) {
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
	updates = 0 // mustWriteConfig's own validation call does not count.

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_role":     "developer",
			"namespace_access": []string{"prod.acct1=write"},
			"ttl":              "1h",
			"max_ttl":          "8h",
		},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// account_role is supplied unchanged (still required on every write).
	// namespace_access, ttl, and max_ttl are omitted entirely, not set to
	// empty. Since nothing cloud-visible actually changes, this must be a
	// pure Vault-side no-op as far as Temporal Cloud is concerned.
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "developer"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	if updates != 0 {
		t.Errorf("expected no UpdateServiceAccount call when nothing cloud-visible changed, got %d", updates)
	}

	entry, err := b.getServiceAccount(context.Background(), storage, "svc")
	if err != nil || entry == nil {
		t.Fatalf("getServiceAccount: err=%v entry=%v", err, entry)
	}
	if entry.AccountRole != "developer" {
		t.Errorf("expected role to remain developer, got %q", entry.AccountRole)
	}
	if entry.NamespaceAccess["prod.acct1"] != "write" {
		t.Errorf("expected namespace_access to be preserved, got %v", entry.NamespaceAccess)
	}
	if entry.TTL.String() != "1h0m0s" {
		t.Errorf("expected ttl to be preserved at 1h, got %v", entry.TTL)
	}
	if entry.MaxTTL.String() != "8h0m0s" {
		t.Errorf("expected max_ttl to be preserved at 8h, got %v", entry.MaxTTL)
	}
}

// Explicitly passing namespace_access="" is how an operator deliberately
// clears every namespace permission. Unlike an omitted field, this must reach
// Temporal Cloud.
func TestServiceAccounts_ExplicitEmptyNamespaceAccessClearsAndCallsCloud(t *testing.T) {
	b, storage := newTestBackend(t)

	updates := 0
	var lastSpec client.ServiceAccountSpec
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	stub.updateServiceAccountFn = func(_ context.Context, _ string, spec client.ServiceAccountSpec) error {
		updates++
		lastSpec = spec
		return nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)
	updates = 0

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_role":     "developer",
			"namespace_access": []string{"prod.acct1=write"},
		},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_role":     "admin",
			"namespace_access": "",
		},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	if updates != 1 {
		t.Fatalf("expected exactly one UpdateServiceAccount call, got %d", updates)
	}
	if len(lastSpec.NamespaceAccess) != 0 {
		t.Errorf("expected namespace_access sent to Temporal Cloud to be empty, got %v", lastSpec.NamespaceAccess)
	}

	entry, err := b.getServiceAccount(context.Background(), storage, "svc")
	if err != nil || entry == nil {
		t.Fatalf("getServiceAccount: err=%v entry=%v", err, entry)
	}
	if len(entry.NamespaceAccess) != 0 {
		t.Errorf("expected namespace_access to be cleared, got %v", entry.NamespaceAccess)
	}
}

// Supplying a new namespace_access on update replaces the stored value
// entirely and calls UpdateServiceAccount.
func TestServiceAccounts_NewNamespaceAccessReplacesAndCallsCloud(t *testing.T) {
	b, storage := newTestBackend(t)

	updates := 0
	var lastSpec client.ServiceAccountSpec
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	stub.updateServiceAccountFn = func(_ context.Context, _ string, spec client.ServiceAccountSpec) error {
		updates++
		lastSpec = spec
		return nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)
	updates = 0

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_role":     "developer",
			"namespace_access": []string{"prod.acct1=write"},
		},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_role":     "admin",
			"namespace_access": []string{"staging.acct1=read"},
		},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	if updates != 1 {
		t.Fatalf("expected exactly one UpdateServiceAccount call, got %d", updates)
	}
	if lastSpec.NamespaceAccess["staging.acct1"] != "read" {
		t.Errorf("expected staging.acct1=read sent to Temporal Cloud, got %v", lastSpec.NamespaceAccess)
	}
	if _, stillThere := lastSpec.NamespaceAccess["prod.acct1"]; stillThere {
		t.Errorf("expected prod.acct1 to be gone after replacement, got %v", lastSpec.NamespaceAccess)
	}

	entry, err := b.getServiceAccount(context.Background(), storage, "svc")
	if err != nil || entry == nil {
		t.Fatalf("getServiceAccount: err=%v entry=%v", err, entry)
	}
	if entry.NamespaceAccess["staging.acct1"] != "read" {
		t.Errorf("expected stored namespace_access to be replaced, got %v", entry.NamespaceAccess)
	}
}

// Create is unaffected by the merge logic: there is nothing to merge against,
// so an omitted field takes its default exactly as before.
func TestServiceAccounts_CreateOmittedFieldsTakeDefaults(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
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

	entry, err := b.getServiceAccount(context.Background(), storage, "svc")
	if err != nil || entry == nil {
		t.Fatalf("getServiceAccount: err=%v entry=%v", err, entry)
	}
	if entry.TTL != defaultServiceAccountTTL {
		t.Errorf("expected default ttl %v, got %v", defaultServiceAccountTTL, entry.TTL)
	}
	if entry.MaxTTL != defaultServiceAccountMaxTTL {
		t.Errorf("expected default max_ttl %v, got %v", defaultServiceAccountMaxTTL, entry.MaxTTL)
	}
	if len(entry.NamespaceAccess) != 0 {
		t.Errorf("expected no namespace_access, got %v", entry.NamespaceAccess)
	}
}

// Validation must apply to the merged result, not just to whatever was
// supplied on the request. A stored max_ttl of 8h combined with a
// newly-supplied ttl of 10h violates ttl <= max_ttl even though neither value
// looks invalid in isolation.
func TestServiceAccounts_ValidationAppliesToMergedResult(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_role": "read",
			"ttl":          "1h",
			"max_ttl":      "8h",
		},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// max_ttl is omitted here, so it merges in from storage as 8h. A ttl of
	// 10h alone should not pass the ttl <= max_ttl check.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_role": "read",
			"ttl":          "10h",
		},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected the merged ttl > max_ttl to be rejected")
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

// The flag defaults off so enabling the feature is always a deliberate act:
// an existing mount upgraded to this version must behave exactly as before.
func TestServiceAccount_VerifyPropagationDefaultsOff(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "developer",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read service account: err=%v resp=%v", err, resp)
	}

	if got := resp.Data["verify_propagation"]; got != false {
		t.Fatalf("verify_propagation = %v, want false", got)
	}
}

// Same merge rule as ttl, max_ttl, and description: an update that does not
// mention the field must not silently reset it. Without this, a write that
// only changes ttl would turn the probe off.
func TestServiceAccount_VerifyPropagationSurvivesUnrelatedUpdate(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role":       "developer",
		"verify_propagation": true,
	})
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "developer",
		"ttl":          "30m",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read service account: err=%v resp=%v", err, resp)
	}

	if got := resp.Data["verify_propagation"]; got != true {
		t.Fatalf("verify_propagation = %v after an unrelated update, want true", got)
	}
}

// An explicit verify_propagation=false is indistinguishable from an omitted
// field unless GetOk reports presence rather than non-zero-ness. The other
// two tests cannot catch a regression here: one never sets the field, and the
// other sets it to a non-zero value. This is the one case where turning the
// probe back off would silently stop working.
func TestServiceAccount_VerifyPropagationExplicitFalseDisablesIt(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role":       "developer",
		"verify_propagation": true,
	})
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role":       "developer",
		"verify_propagation": false,
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read service account: err=%v resp=%v", err, resp)
	}

	if got := resp.Data["verify_propagation"]; got != false {
		t.Fatalf("verify_propagation = %v after an explicit false, want false", got)
	}
}
