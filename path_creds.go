package temporalcloud

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

func (b *backend) pathCreds() *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the service-accounts/<name> entry to mint a key from.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathCredsRead},
		},
		HelpSynopsis:    "Mint a short-lived Temporal Cloud API key.",
		HelpDescription: pathCredsHelp,
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	entry, err := b.getServiceAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse(
			"no service account named %q is configured; create it with "+
				"'vault write %sservice-accounts/%s ...'", name, req.MountPoint, name), nil
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Check the ceiling before minting, so the operator gets an explanation
	// rather than a raw ResourceExhausted from Temporal Cloud.
	count, err := c.CountAPIKeys(ctx, entry.ServiceAccountID)
	if err != nil {
		return nil, fmt.Errorf("counting existing API keys for %q: %w", name, err)
	}
	if err := checkAPIKeyCapacity(name, count, entry.TTL); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// The Temporal Cloud expiry covers max_ttl plus a grace margin rather than
	// ttl. A key expiring at ttl would die under a renewed lease; covering
	// max_ttl means renewal never needs a Cloud Ops call, and a key orphaned
	// by a Vault failure still self-destructs within one maximum lifetime.
	expiry := time.Now().Add(entry.MaxTTL + apiKeyExpiryGrace)

	key, err := c.CreateAPIKey(ctx, client.APIKeySpec{
		ServiceAccountID: entry.ServiceAccountID,
		DisplayName:      apiKeyDisplayName(name),
		Description:      fmt.Sprintf("Issued by Vault mount %s for %s", req.MountPoint, name),
		ExpiryTime:       expiry,
	})
	if err != nil {
		return nil, fmt.Errorf("minting an API key for %q: %w", name, err)
	}

	resp := b.Secret(secretTypeAPIKey).Response(
		// Returned to the caller.
		map[string]interface{}{
			"api_key":              key.Token,
			"api_key_id":           key.ID,
			"service_account_id":   entry.ServiceAccountID,
			"service_account_name": name,
			"expires_at":           expiry.Format(time.RFC3339),
		},
		// Kept by Vault for renewal and revocation. The token is deliberately
		// absent: revocation needs only the key ID.
		map[string]interface{}{
			"api_key_id":           key.ID,
			"service_account_name": name,
		},
	)

	resp.Secret.TTL = entry.TTL
	resp.Secret.MaxTTL = entry.MaxTTL

	return resp, nil
}

// checkAPIKeyCapacity reports whether another key can be minted on a service
// account that already owns count non-expired keys.
func checkAPIKeyCapacity(name string, count int, ttl time.Duration) error {
	if count < client.MaxAPIKeysPerServiceAccount {
		return nil
	}

	return fmt.Errorf(
		"service account %q has %d of %d permitted API keys in use. Temporal Cloud "+
			"allows %d non-expired keys per service account. Revoke leases, lower ttl "+
			"(currently %s), or create an additional service account.",
		name, count, client.MaxAPIKeysPerServiceAccount,
		client.MaxAPIKeysPerServiceAccount, ttl)
}

// apiKeyDisplayName builds the name shown in the Temporal Cloud UI.
//
// It uses a random suffix rather than the lease ID because Vault assigns the
// lease ID only after this handler returns, so it does not exist yet. Keys are
// correlated back to leases through the key ID in lease internal data.
func apiKeyDisplayName(name string) string {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		// A collision in the display name is cosmetic, so fall back rather
		// than failing the credential request.
		return fmt.Sprintf("vault-%s", name)
	}
	return fmt.Sprintf("vault-%s-%s", name, hex.EncodeToString(suffix))
}

const pathCredsHelp = `
Mints a fresh Temporal Cloud API key owned by the named service account and
returns it under a Vault lease. The key is deleted when the lease is revoked or
expires.

The token is shown only in this response; Vault does not store it and cannot
return it again. Read this path again for a new one.

Temporal Cloud permits 20 non-expired API keys per service account, so at most
20 leases can be outstanding against one service-accounts/<name> entry at a
time. Revoking a lease frees a slot immediately.
`
