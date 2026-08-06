// Package temporalcloud implements a HashiCorp Vault secrets engine for
// Temporal Cloud. It provisions Temporal Cloud service accounts and issues
// short-lived API keys as Vault dynamic secrets, deleting each key when its
// Vault lease ends.
package temporalcloud

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

// configStoragePath is the storage key holding the engine's configuration.
const configStoragePath = "config"

// backend is the Temporal Cloud secrets engine.
type backend struct {
	*framework.Backend

	// clientMu guards the cached Cloud Ops client handle. The client owns a
	// gRPC connection, so we build it once and reuse it across requests
	// rather than dialling per request.
	clientMu sync.RWMutex
	handle   *clientHandle

	// rotateMu serialises config/rotate-root. Vault does not serialise
	// requests to a path, and rotation is a read-modify-write over a single
	// stored credential: two overlapping calls would both read the same
	// config, both mint a Global Admin key, and both store — last writer
	// wins. The loser's key is a working Global Admin credential that no
	// longer appears anywhere in Vault's config and survives for the whole
	// of root_key_ttl (90 days by default). A duplicated rotation cron or a
	// retried request is enough to trigger it, so the handler holds this for
	// its entire duration.
	rotateMu sync.Mutex

	// newClient builds a Cloud Ops client. It is a field rather than a direct
	// call to client.NewGRPC so tests can substitute a stub without dialling
	// Temporal Cloud.
	newClient func(cfg client.Config) (client.CloudOps, error)
}

// Factory is the entrypoint Vault calls to instantiate this plugin.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend constructs the engine without wiring it to Vault, so tests can
// drive it directly.
func Backend() *backend {
	var b backend

	b.newClient = client.NewGRPC

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			// The root API key lives here, so it must be seal-wrapped.
			SealWrapStorage: []string{configStoragePath},
		},
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathRotateRoot(),
			b.pathServiceAccounts(),
			b.pathServiceAccountsList(),
			b.pathCreds(),
		},
		Secrets: []*framework.Secret{
			b.secretAPIKey(),
		},
		Invalidate: b.invalidate,
		Clean:      b.clean,
	}

	return &b
}

// invalidate drops the cached client when config changes, so the next request
// rebuilds it with the new credential. Vault calls this on the active node and
// on replicas when storage under the given key changes.
func (b *backend) invalidate(_ context.Context, key string) {
	if key == configStoragePath {
		b.resetClient()
	}
}

// clean closes the gRPC connection when the mount is unmounted or sealed.
func (b *backend) clean(_ context.Context) {
	b.resetClient()
}

// resetClient drops the cached client so the next request builds a fresh one.
//
// It retires rather than closes: see clientHandle.
func (b *backend) resetClient() {
	b.clientMu.Lock()
	h := b.handle
	b.handle = nil
	b.clientMu.Unlock()

	if h != nil {
		h.retire()
	}
}

// clientHandle is a cached Cloud Ops client plus a count of the requests
// currently using it.
//
// The count exists because a client is shared, unlocked, across concurrent
// requests: getClient hands one out and the caller uses it long after the
// backend's lock is released. Closing it on invalidation — a config write, a
// delete, an Invalidate replayed from a replica, or rotate-root's own reset —
// would tear the gRPC connection out from under whatever is still mid-flight.
// The failure that causes is quiet and expensive: CreateApiKey succeeds
// server-side, the operation poll then hits a closing connection, the request
// fails without creating a lease, and the key it minted is orphaned until its
// Temporal Cloud expiry.
//
// Of the ways to fix that, reference counting is the one that is
// deterministic. Deferring the Close past a fixed grace period would have to
// guess a bound (client/async.go allows an operation 60s, so any guess must
// comfortably exceed that) and is untestable without sleeping; never closing
// until the mount is torn down would leak a connection per credential change.
// Counting costs one release call per acquisition — the tradeoff — and in
// exchange the connection closes at exactly the right moment: as soon as it is
// both retired and unused.
type clientHandle struct {
	c client.CloudOps

	mu      sync.Mutex
	refs    int
	retired bool
	closed  bool
}

// acquire registers one in-flight user and returns the release function that
// user must call exactly once when it is done with the client.
func (h *clientHandle) acquire() (client.CloudOps, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.refs++
	return h.c, h.release
}

func (h *clientHandle) release() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.refs--
	h.closeIfIdle()
}

// retire marks the client as superseded. It closes immediately if nothing is
// using it, and otherwise leaves the last release to do so.
func (h *clientHandle) retire() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.retired = true
	h.closeIfIdle()
}

// closeIfIdle closes the connection once it is both retired and unused. The
// caller must hold h.mu.
func (h *clientHandle) closeIfIdle() {
	if !h.retired || h.refs > 0 || h.closed {
		return
	}
	h.closed = true

	// Close errors are not actionable: we are discarding the client either
	// way, and there is no caller left to report them to.
	_ = h.c.Close()
}

// getClient returns the cached Cloud Ops client, building it from stored
// config on first use. The gRPC connection is expensive to establish, so it is
// shared across requests and rebuilt only when config changes.
//
// The returned release function must be called exactly once — defer it — so
// the connection can be closed after the last user of a superseded client
// finishes rather than underneath it.
func (b *backend) getClient(ctx context.Context, s logical.Storage) (client.CloudOps, func(), error) {
	// resetClient takes the write lock, so a handle read here cannot be
	// retired before it is acquired.
	b.clientMu.RLock()
	if b.handle != nil {
		c, release := b.handle.acquire()
		b.clientMu.RUnlock()
		return c, release, nil
	}
	b.clientMu.RUnlock()

	b.clientMu.Lock()
	defer b.clientMu.Unlock()

	// Another goroutine may have built it while we waited for the write lock.
	if b.handle != nil {
		c, release := b.handle.acquire()
		return c, release, nil
	}

	cfg, err := b.getConfig(ctx, s)
	if err != nil {
		return nil, nil, err
	}
	if cfg == nil {
		return nil, nil, errBackendNotConfigured
	}

	c, err := b.newClient(cfg.clientConfig())
	if err != nil {
		return nil, nil, err
	}

	b.handle = &clientHandle{c: c}
	cloudOps, release := b.handle.acquire()
	return cloudOps, release, nil
}

// respondCloudErr turns a failure from Temporal Cloud into the right kind of
// Vault response, so operators are told what to fix.
//
// The split is between problems an operator can act on and problems they can
// only wait out. A missing resource, a rejected credential, a malformed
// request, or an exhausted quota are all the operator's to resolve, so they
// come back as a 400-style error response naming what was being attempted. A
// returned Go error becomes a 500 Internal Server Error, which reads as "the
// plugin crashed" — reserve it for ErrUnavailable and anything unrecognised,
// which genuinely are infrastructure failures worth retrying.
//
// op is what was being attempted, e.g. `minting an API key for "prod-workers"`.
func respondCloudErr(op string, err error) (*logical.Response, error) {
	switch {
	case errors.Is(err, client.ErrPermissionDenied):
		// Overwhelmingly the most common cause is the engine's own root
		// credential, not the operator's request, so say so: an expired root
		// key otherwise reads as an unexplained failure of whichever path
		// happened to be called.
		return logical.ErrorResponse(
			"%s: %s. The configured root API key was rejected, or its service account "+
				"lacks the Global Admin role. If the root key has expired, write the "+
				"config path again with a fresh key; otherwise rotate it with "+
				"'vault write temporalcloud/config/rotate-root'.", op, err), nil

	case errors.Is(err, client.ErrNotFound),
		errors.Is(err, client.ErrInvalidArgument),
		errors.Is(err, client.ErrResourceExhausted):
		return logical.ErrorResponse("%s: %s", op, err), nil

	default:
		return nil, fmt.Errorf("%s: %w", op, err)
	}
}

// errBackendNotConfigured is returned when a path needs Temporal Cloud but the
// config path has not been written.
var errBackendNotConfigured = errors.New(
	"the Temporal Cloud secrets engine is not configured; write the config path first")

const backendHelp = `
The Temporal Cloud secrets engine provisions Temporal Cloud service accounts and
issues short-lived Temporal Cloud API keys bound to Vault leases.

Configure the engine with a Global Admin service account API key at the "config"
path, define service accounts under "service-accounts/", then read credentials
from "creds/<name>".
`
