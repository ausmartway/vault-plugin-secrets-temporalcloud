package temporalcloud

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// newTestBackend builds a backend against in-memory storage. Tests drive it
// through b.HandleRequest, exactly as Vault does, so no Vault binary is needed.
func newTestBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()

	// TestBackendConfig supplies a logger and system view already; we only
	// need to attach storage.
	conf := logical.TestBackendConfig()
	conf.StorageView = &logical.InmemStorage{}

	b := Backend()
	if err := b.Setup(context.Background(), conf); err != nil {
		t.Fatalf("backend setup: %v", err)
	}
	return b, conf.StorageView
}

func TestBackend_Constructs(t *testing.T) {
	b, _ := newTestBackend(t)

	if b.Backend == nil {
		t.Fatal("expected embedded framework.Backend to be set")
	}
	if b.BackendType != logical.TypeLogical {
		t.Fatalf("expected TypeLogical, got %v", b.BackendType)
	}
}
