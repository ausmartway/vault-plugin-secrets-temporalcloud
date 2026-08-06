package temporalcloud

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
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

// countingClient wraps a stubCloudOps so Close() can be observed without
// racing with the underlying stub's own closed field.
type countingClient struct {
	*stubCloudOps
}

// withCountingClient installs a newClient constructor that counts how many
// times it is invoked and records every client it builds, so tests can prove
// getClient caches rather than rebuilding a gRPC connection per request.
func withCountingClient(b *backend) (calls *int32, clients *[]*countingClient) {
	calls = new(int32)
	built := make([]*countingClient, 0)
	clients = &built

	b.newClient = func(client.Config) (client.CloudOps, error) {
		atomic.AddInt32(calls, 1)
		c := &countingClient{stubCloudOps: &stubCloudOps{}}
		*clients = append(*clients, c)
		return c, nil
	}
	return calls, clients
}

// (a) Unconfigured: getClient must fail with errBackendNotConfigured rather
// than panicking or dialling with an empty config.
func TestGetClient_Unconfigured(t *testing.T) {
	b, storage := newTestBackend(t)

	_, err := b.getClient(context.Background(), storage)
	if err != errBackendNotConfigured {
		t.Fatalf("expected errBackendNotConfigured, got %v", err)
	}
}

// (b) Cache reuse: two successive getClient calls after config is written
// must return the same client instance, and the constructor must run exactly
// once. If this regresses, every request would dial a fresh gRPC connection.
func TestGetClient_CachesAcrossCalls(t *testing.T) {
	b, storage := newTestBackend(t)
	calls, _ := withCountingClient(b)
	mustWriteConfig(t, b, storage)

	// mustWriteConfig's own validation call also uses newClient; only calls
	// made by getClient itself are under test here.
	atomic.StoreInt32(calls, 0)

	c1, err := b.getClient(context.Background(), storage)
	if err != nil {
		t.Fatalf("first getClient: %v", err)
	}
	c2, err := b.getClient(context.Background(), storage)
	if err != nil {
		t.Fatalf("second getClient: %v", err)
	}

	if c1 != c2 {
		t.Fatal("expected getClient to return the same cached instance")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("expected newClient to be called exactly once, got %d", got)
	}
}

// (c) Invalidation: resetClient (as mustWriteConfig triggers on a second
// write) must force the next getClient to build a fresh client, and the old
// client must have been closed. A missed Close here is a leaked connection.
func TestGetClient_InvalidationBuildsFreshClientAndClosesOld(t *testing.T) {
	b, storage := newTestBackend(t)
	calls, clients := withCountingClient(b)
	mustWriteConfig(t, b, storage)

	// mustWriteConfig's own validation call also uses newClient and builds a
	// client that is unrelated to the cache under test; reset the bookkeeping
	// so indices below refer only to clients getClient itself builds.
	atomic.StoreInt32(calls, 0)
	*clients = nil

	c1, err := b.getClient(context.Background(), storage)
	if err != nil {
		t.Fatalf("first getClient: %v", err)
	}

	// Explicit invalidation, as Vault performs on config change / unmount /
	// seal, without requiring a second config write.
	b.resetClient()

	c2, err := b.getClient(context.Background(), storage)
	if err != nil {
		t.Fatalf("getClient after reset: %v", err)
	}

	if got := atomic.LoadInt32(calls); got != 2 {
		t.Fatalf("expected newClient to be called twice after invalidation, got %d", got)
	}
	if c1 == c2 {
		t.Fatal("expected a fresh client after invalidation")
	}

	old := (*clients)[0].stubCloudOps
	if !old.closed {
		t.Fatal("expected the old client to have Close() called on invalidation")
	}
}

// (d) Concurrency: many goroutines calling getClient at once must still see
// the constructor run exactly once, and every caller must receive the same
// non-nil client. Run with -race: a data race here would mean concurrent
// requests could double-dial or hand back a half-built client.
func TestGetClient_ConcurrentCallsBuildOnce(t *testing.T) {
	b, storage := newTestBackend(t)
	calls, _ := withCountingClient(b)
	mustWriteConfig(t, b, storage)

	// mustWriteConfig's own validation call also uses newClient; only calls
	// made by getClient itself are under test here.
	atomic.StoreInt32(calls, 0)

	const n = 50
	results := make([]client.CloudOps, n)
	errs := make([]error, n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = b.getClient(context.Background(), storage)
		}(i)
	}
	wg.Wait()

	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("expected newClient to be called exactly once under concurrency, got %d", got)
	}

	first := results[0]
	if first == nil {
		t.Fatal("expected a non-nil client")
	}
	for i, c := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: getClient error: %v", i, errs[i])
		}
		if c != first {
			t.Fatalf("goroutine %d: expected the same cached client instance, got a different one", i)
		}
	}
}
