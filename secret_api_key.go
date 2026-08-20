package temporalcloud

import (
	"context"
	"errors"
	"fmt"
	"time"

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
// any extension Vault can grant — and where max_ttl has since moved, the
// ceiling reported here holds the lease inside that expiry. See renewalCeiling.
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

	maxTTL, err := renewalCeiling(req.Secret, entry.MaxTTL)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = entry.TTL
	resp.Secret.MaxTTL = maxTTL

	return resp, nil
}

// renewalCeiling returns the max TTL to report for a lease, which is the
// entry's max_ttl held down to the window the lease's own key was minted with.
//
// The two can disagree because a key's Temporal Cloud expiry is fixed when the
// key is created — Temporal Cloud has no call to extend it — while max_ttl on
// the entry can be raised at any time. Reporting the raised value would let
// Vault keep renewing a lease whose credential had already expired in Temporal
// Cloud, so the key's own expiry wins.
//
// Vault caps renewals at the lease's issue time plus this value, and the mint
// left apiKeyExpiryGrace between max_ttl and the key's expiry, so the ceiling
// keeps that same margin.
func renewalCeiling(secret *logical.Secret, maxTTL time.Duration) (time.Duration, error) {
	expiry, err := keyExpiry(secret)
	if err != nil {
		return 0, err
	}
	if expiry.IsZero() {
		return maxTTL, nil
	}

	// A missing issue time would otherwise compute an unbounded window;
	// measuring from now instead only ever tightens the ceiling.
	start := secret.IssueTime
	if start.IsZero() {
		start = time.Now()
	}

	limit := expiry.Add(-apiKeyExpiryGrace).Sub(start)
	if limit >= maxTTL {
		return maxTTL, nil
	}
	if limit <= 0 {
		// Returning a non-positive max TTL would read to Vault as "no backend
		// limit", so refuse outright. The lease then expires on its own
		// schedule and revocation deletes whatever is left of the key.
		return 0, fmt.Errorf(
			"the API key behind this lease expires at %s, which the lease has already "+
				"reached; Temporal Cloud cannot extend an existing key's expiry, so this "+
				"lease cannot be renewed — request a new credential instead",
			expiry.Format(time.RFC3339))
	}

	return limit, nil
}

// keyExpiry reads the Temporal Cloud expiry recorded on a lease at mint time.
// A lease issued before the mint began recording it yields the zero time
// rather than an error, so those leases stay renewable on max_ttl alone.
func keyExpiry(secret *logical.Secret) (time.Time, error) {
	if secret == nil || secret.InternalData["api_key_expires_at"] == nil {
		return time.Time{}, nil
	}

	raw, err := internalString(secret, "api_key_expires_at")
	if err != nil {
		return time.Time{}, err
	}

	expiry, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"lease internal data field %q is not an RFC3339 time: %w", "api_key_expires_at", err)
	}

	return expiry, nil
}

// secretAPIKeyRevoke deletes the API key backing the lease.
func (b *backend) secretAPIKeyRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	keyID, err := internalString(req.Secret, "api_key_id")
	if err != nil {
		return nil, err
	}

	c, release, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	defer release()

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
