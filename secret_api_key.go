package temporalcloud

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

// secretTypeAPIKey identifies leases issued by this engine.
const secretTypeAPIKey = "temporalcloud_api_key"

func (b *backend) secretAPIKey() *framework.Secret {
	return &framework.Secret{
		Type: secretTypeAPIKey,
		Fields: map[string]*framework.FieldSchema{
			"api_key": {
				Type:        framework.TypeString,
				Description: "The Temporal Cloud API key. Shown once, at issue time.",
			},
			"api_key_id": {
				Type:        framework.TypeString,
				Description: "ID of the API key, used to revoke it.",
			},
		},
		Renew:  b.secretAPIKeyRenew,
		Revoke: b.secretAPIKeyRevoke,
	}
}

// secretAPIKeyRenew extends the lease. It makes no Temporal Cloud call: the key
// was minted with an expiry covering max_ttl plus grace, so it already outlives
// any extension Vault can grant.
func (b *backend) secretAPIKeyRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, err := internalString(req.Secret, "service_account_name")
	if err != nil {
		return nil, err
	}

	entry, err := b.getServiceAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		// The definition was deleted while the lease was live. Refusing to
		// renew lets the lease expire, which revokes the key.
		return nil, fmt.Errorf(
			"service account %q no longer exists, so this lease cannot be renewed", name)
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = entry.TTL
	resp.Secret.MaxTTL = entry.MaxTTL

	return resp, nil
}

// secretAPIKeyRevoke deletes the API key backing the lease.
func (b *backend) secretAPIKeyRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	keyID, err := internalString(req.Secret, "api_key_id")
	if err != nil {
		return nil, err
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if err := c.DeleteAPIKey(ctx, keyID); err != nil {
		// The key being gone is the outcome we wanted. It may have expired on
		// its own or been deleted out of band; either way the lease is done.
		// Returning an error would leave Vault retrying a lease forever.
		if errors.Is(err, client.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("deleting API key %q: %w", keyID, err)
	}

	return nil, nil
}

// internalString reads a string from lease internal data, with an error that
// says which field was missing rather than panicking on a type assertion.
func internalString(secret *logical.Secret, field string) (string, error) {
	if secret == nil {
		return "", errors.New("request has no lease attached")
	}

	raw, ok := secret.InternalData[field]
	if !ok {
		return "", fmt.Errorf("lease internal data is missing %q", field)
	}

	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("lease internal data field %q is %T, expected string", field, raw)
	}

	return value, nil
}
