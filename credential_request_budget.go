package temporalcloud

import (
	"context"
	"time"
)

const (
	// credentialRequestTimeout bounds the entire creds/<name> handler below
	// the Vault API client's default 60-second HTTP timeout. The remaining five
	// seconds are delivery headroom for Vault to serialize the response and
	// return it through the plugin boundary before the caller gives up.
	credentialRequestTimeout = 55 * time.Second
)

// credentialRequestContext applies the plugin's end-to-end issuance ceiling
// while preserving a shorter deadline imposed by the caller or Vault.
func credentialRequestContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, credentialRequestTimeout)
}
