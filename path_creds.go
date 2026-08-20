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

	c, release, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	defer release()

	// Check the ceiling before minting, so the operator gets an explanation
	// rather than a raw ResourceExhausted from Temporal Cloud. This is a
	// nicer-error fast path, not enforcement: Temporal Cloud is the real
	// enforcer, and concurrent reads that all see count=19 can still race past
	// this check, in which case the losers get Temporal Cloud's own quota
	// error instead of the message below.
	count, err := c.CountAPIKeys(ctx, entry.ServiceAccountID)
	if err != nil {
		return respondCloudErr(fmt.Sprintf("counting existing API keys for %q", name), err)
	}
	if err := checkAPIKeyCapacity(name, count, entry.TTL); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// The Temporal Cloud expiry covers max_ttl plus a grace margin rather than
	// ttl. A key expiring at ttl would die under a renewed lease; covering
	// max_ttl means renewal never needs a Cloud Ops call, and a key orphaned
	// by a Vault failure still self-destructs within one maximum lifetime —
	// or, below, within client.MinAPIKeyExpiry.
	//
	// Temporal Cloud rejects any expiry less than client.MinAPIKeyExpiry from
	// now (undocumented; found by live testing), so a short max_ttl is
	// floored up to that minimum here rather than sent as-is and rejected.
	// This does not weaken credential lifetime: the key is deleted when its
	// lease ends regardless of its nominal Temporal Cloud expiry, so a
	// 15-minute max_ttl still means the key is gone in 15 minutes in the
	// normal case. What the floor actually widens is the fallback window —
	// the time an orphaned key (one Vault never got to revoke, because Vault
	// crashed, lost storage, or the mount was deleted) stays alive before it
	// self-destructs on its own. That window was one max_ttl; with the floor
	// it is now at least client.MinAPIKeyExpiry, i.e. at least a day.
	keyLifetime := entry.MaxTTL + apiKeyExpiryGrace
	if floor := client.MinAPIKeyExpiry + apiKeyExpiryGrace; keyLifetime < floor {
		keyLifetime = floor
	}
	expiry := time.Now().Add(keyLifetime)

	key, err := c.CreateAPIKey(ctx, client.APIKeySpec{
		ServiceAccountID: entry.ServiceAccountID,
		DisplayName:      apiKeyDisplayName(name),
		Description:      fmt.Sprintf("Issued by Vault mount %s for %s", req.MountPoint, name),
		ExpiryTime:       expiry,
	})
	if err != nil {
		// CreateAPIKey returns what it minted even when the wait for the async
		// operation failed, because Temporal Cloud may have completed the
		// create regardless. No lease is being issued, so nothing will ever
		// revoke that key: delete it here or it sits unusable in one of the
		// service account's twenty slots until its expiry, which the
		// MinAPIKeyExpiry floor puts at least a day out.
		if key != nil && key.ID != "" {
			if delErr := c.DeleteAPIKey(ctx, key.ID); delErr != nil {
				b.Logger().Error(
					"could not delete an API key whose creation did not complete; "+
						"delete it by hand",
					"api_key_id", key.ID, "service_account", name, "error", delErr)
			}
		}
		return respondCloudErr(fmt.Sprintf("minting an API key for %q", name), err)
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
		//
		// The expiry is recorded because renewal has to respect it and cannot
		// recompute it: Temporal Cloud fixes a key's expiry at create time and
		// offers no call to extend it, while max_ttl on the entry can be
		// changed afterward. See secretAPIKeyRenew.
		map[string]interface{}{
			"api_key_id":           key.ID,
			"api_key_expires_at":   expiry.Format(time.RFC3339),
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

Temporal Cloud will not accept an API key expiry less than 24 hours from now
(undocumented by Temporal Cloud). If the service account's max_ttl is shorter
than that, this engine automatically floors the key's Temporal Cloud expiry at
24 hours so the mint still succeeds — it does not require you to raise
max_ttl. This only widens the fallback: if Vault never gets to revoke the key
(a crash, lost storage, or a deleted mount), the key self-destructs at that
floored expiry instead of at max_ttl. In the normal case the key is still
deleted the moment its lease ends, so a short max_ttl still means a
short-lived credential.
`
