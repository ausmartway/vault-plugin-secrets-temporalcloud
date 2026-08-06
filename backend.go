// Package temporalcloud implements a HashiCorp Vault secrets engine for
// Temporal Cloud. It provisions Temporal Cloud service accounts and issues
// short-lived API keys as Vault dynamic secrets, deleting each key when its
// Vault lease ends.
package temporalcloud

import (
	"context"
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

	// clientMu guards the cached Cloud Ops client. The client owns a gRPC
	// connection, so we build it once and reuse it across requests rather
	// than dialling per request.
	clientMu sync.RWMutex
	client   client.CloudOps
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

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			// The root API key lives here, so it must be seal-wrapped.
			SealWrapStorage: []string{configStoragePath},
		},
		// Paths and Secrets are appended by later tasks.
		Paths:      []*framework.Path{},
		Secrets:    []*framework.Secret{},
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

// resetClient closes and clears the cached client.
func (b *backend) resetClient() {
	b.clientMu.Lock()
	defer b.clientMu.Unlock()

	if b.client != nil {
		// Close errors are not actionable here: we are discarding the client
		// either way, and returning an error would block invalidation.
		_ = b.client.Close()
		b.client = nil
	}
}

const backendHelp = `
The Temporal Cloud secrets engine provisions Temporal Cloud service accounts and
issues short-lived Temporal Cloud API keys bound to Vault leases.

Configure the engine with a Global Admin service account API key at the "config"
path, define service accounts under "service-accounts/", then read credentials
from "creds/<name>".
`
