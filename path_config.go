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

const (
	// defaultAddress is Temporal Cloud's public Cloud Ops API endpoint.
	defaultAddress = "saas-api.tmprl.cloud:443"

	// defaultRootKeyTTL is 90 days, matching Temporal's own guidance on
	// rotating API keys at least quarterly.
	defaultRootKeyTTL = 2160 * time.Hour
)

// config is the engine's stored configuration.
type config struct {
	// APIKey is the root credential: a Temporal Cloud API key owned by a
	// service account with the Global Admin role. Never returned on read.
	APIKey string `json:"api_key"`

	// APIKeyID identifies APIKey so rotate-root can delete the key it
	// replaces. Read-only from an operator's point of view: it is derived
	// from APIKey, which carries its own ID (see client.APIKeyIDFromToken),
	// so it always describes the key actually stored. Empty only when a
	// token could not be parsed, which is warned about at write time.
	APIKeyID string `json:"api_key_id"`

	// AdminServiceAccountID owns APIKey. It is derived from the key's Cloud Ops
	// record during configuration so rotate-root can mint against that identity.
	AdminServiceAccountID string `json:"admin_service_account_id"`

	// Address is the Cloud Ops API host:port.
	Address string `json:"address"`

	// RootKeyTTL is the expiry applied to keys minted by rotate-root.
	RootKeyTTL time.Duration `json:"root_key_ttl"`
}

func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"api_key": {
				Type:        framework.TypeString,
				Description: "Temporal Cloud API key owned by a service account with the Global Admin role. Required. Never returned on read.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "API Key",
					Sensitive: true,
				},
			},
			// api_key_id is deliberately absent from this list: it is
			// read-only, returned on read but never accepted on write. The
			// engine reads it out of api_key itself — a Temporal Cloud API key
			// is a JWT carrying its own id in the key_id claim — so there is
			// nothing for an operator to supply, and a supplied value could
			// only ever disagree with the key it claims to name. Since
			// rotate-root deletes whatever this ID names, letting the two
			// disagree is a way to destroy an unrelated key by typo.
			"admin_service_account_id": {
				Type: framework.TypeString,
				Description: "Optional compatibility check. Vault derives the owning service account from api_key; " +
					"if supplied, this value must match that owner.",
			},
			"address": {
				Type:        framework.TypeString,
				Default:     defaultAddress,
				Description: "Cloud Ops API address. Override for PrivateLink or non-production endpoints.",
			},
			"root_key_ttl": {
				Type:        framework.TypeDurationSecond,
				Default:     int(defaultRootKeyTTL.Seconds()),
				Description: "Expiry applied to root API keys minted by rotate-root. Minimum 24 hours, maximum two years.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		ExistenceCheck:  b.configExists,
		HelpSynopsis:    "Configure the Temporal Cloud connection and root credential.",
		HelpDescription: pathConfigHelp,
	}
}

func (b *backend) configExists(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, configStoragePath)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	apiKey := d.Get("api_key").(string)
	if apiKey == "" {
		return logical.ErrorResponse("api_key is required"), nil
	}

	// api_key_id is read-only, and the framework will not police that for us:
	// FieldData.Validate skips fields absent from the schema rather than
	// rejecting them, so a supplied value would be dropped in silence — the
	// worst outcome, because the operator would believe they had configured
	// rotate-root's cleanup when they had not. Say so instead.
	if _, ok := d.Raw["api_key_id"]; ok {
		return logical.ErrorResponse(
			"api_key_id is read-only and cannot be set. Vault reads it from api_key " +
				"itself, which carries its own ID, so there is nothing to supply — and " +
				"a supplied value could only disagree with the key it names, which " +
				"matters because config/rotate-root deletes whatever it names. Remove " +
				"the field and write again; 'vault read' will show the ID Vault derived."), nil
	}

	suppliedAdminSAID := d.Get("admin_service_account_id").(string)

	existing, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// address and root_key_ttl merge against the stored config on update, the
	// same way service-accounts/<name> merges: omitting a field means "leave
	// it alone," not "reset it to the default." Both carry framework defaults,
	// so without this a write that changes only the credential would silently
	// revert a PrivateLink address to the public endpoint and a tuned
	// root_key_ttl to 90 days. d.GetOk reports whether the field was in the
	// request at all, which is the only way to tell absent from zero.
	_, addressSet := d.GetOk("address")
	_, rootKeyTTLSet := d.GetOk("root_key_ttl")

	var rootKeyTTL time.Duration
	if existing != nil && !rootKeyTTLSet {
		rootKeyTTL = existing.RootKeyTTL
	} else {
		rootKeyTTL = time.Duration(d.Get("root_key_ttl").(int)) * time.Second
	}
	if rootKeyTTL <= 0 {
		rootKeyTTL = defaultRootKeyTTL
	}
	if rootKeyTTL > client.MaxAPIKeyExpiry {
		return logical.ErrorResponse(
			"root_key_ttl of %s exceeds Temporal Cloud's maximum API key expiry of %s",
			rootKeyTTL, client.MaxAPIKeyExpiry), nil
	}
	// Rejected rather than floored, unlike the expiry on a minted credential
	// (see path_creds.go). root_key_ttl is a number the operator chose
	// deliberately and will plan the next rotation around, so silently
	// substituting a different one would mislead them; a short root_key_ttl
	// set to demo rotation quickly is exactly the case where they need to
	// hear that the value cannot be honoured, here rather than from a failed
	// rotate-root later.
	if rootKeyTTL < client.MinAPIKeyExpiry {
		return logical.ErrorResponse(
			"root_key_ttl of %s is below Temporal Cloud's minimum API key expiry of %s. "+
				"Temporal Cloud does not document this minimum, but it rejects any key "+
				"expiring sooner, so rotate-root could not honour this value",
			rootKeyTTL, client.MinAPIKeyExpiry), nil
	}

	address := d.Get("address").(string)
	if existing != nil && !addressSet {
		address = existing.Address
	}
	if address == "" {
		address = defaultAddress
	}

	// api_key_id is derived from the key itself, never supplied and never
	// carried over from a previous write. A Temporal Cloud API key is a JWT
	// whose payload names its own id, so the value is right by construction:
	// it came from the very token being stored, and cannot drift out of step
	// with it the way a remembered or hand-entered one could.
	//
	// A key this cannot parse is rejected rather than stored with an unknown
	// id. Storing it would produce a mount that works until the day it has to
	// rotate, and then strands the key it was supposed to replace — a failure
	// deferred to the least convenient moment, and one the operator would have
	// forgotten agreeing to. Every real Temporal Cloud API key parses, so the
	// realistic causes are a truncated paste or the wrong string entirely,
	// both of which the operator wants to hear about now.
	apiKeyID, err := client.APIKeyIDFromToken(apiKey)
	if err != nil {
		return logical.ErrorResponse(
			"api_key does not look like a Temporal Cloud API key: %s. A Temporal Cloud "+
				"API key is a JWT that carries its own key ID, which this engine reads so "+
				"config/rotate-root can delete the key it replaces. Check that the whole "+
				"key was pasted, and that it is an API key rather than a namespace "+
				"certificate or an account ID.", err), nil
	}

	cfg := &config{
		APIKey:     apiKey,
		APIKeyID:   apiKeyID,
		Address:    address,
		RootKeyTTL: rootKeyTTL,
	}

	// Validate before persisting. Built from cfg, not from the cached client and
	// not from `existing`: the credential under test must be the one this write
	// is about to store, or an update would validate whatever the mount is
	// already using and accept any key at all.
	//
	// GetAPIKey both authenticates the token and reports its owner. This removes
	// an operator-supplied identity from the trust boundary and lets us reject a
	// user-owned key now: rotate-root can create replacements only for service
	// accounts.
	c, err := b.newClient(cfg.clientConfig())
	if err != nil {
		return logical.ErrorResponse("could not build a Temporal Cloud client: %s", err), nil
	}
	defer func() {
		// This client is for validation only; the cached one is built lazily
		// on the next request.
		_ = c.Close()
	}()

	keyMetadata, err := c.GetAPIKey(ctx, apiKeyID)
	if err != nil {
		switch {
		case errors.Is(err, client.ErrNotFound), errors.Is(err, client.ErrPermissionDenied):
			return logical.ErrorResponse(
				"the supplied api_key was rejected, expired, or lacks permission to read its own " +
					"API key record; supply an active API key owned by a Global Admin service account"), nil
		default:
			return respondCloudErr("reading the supplied API key's owner", err)
		}
	}

	switch keyMetadata.OwnerType {
	case client.APIKeyOwnerUser:
		return logical.ErrorResponse(
			"the supplied api_key is owned by a Temporal Cloud user. Vault requires a " +
				"service-account-owned API key because config/rotate-root can mint a replacement " +
				"only for a service account"), nil
	case client.APIKeyOwnerServiceAccount:
		// Expected below.
	default:
		return logical.ErrorResponse(
			"the supplied api_key has unsupported owner type %q; Vault requires an API key "+
				"owned by a Temporal Cloud service account", keyMetadata.OwnerType), nil
	}
	if keyMetadata.OwnerID == "" {
		return logical.ErrorResponse(
			"Temporal Cloud returned no owner ID for the supplied api_key; Vault cannot " +
				"rotate a key whose service account cannot be identified"), nil
	}
	if suppliedAdminSAID != "" && suppliedAdminSAID != keyMetadata.OwnerID {
		return logical.ErrorResponse(
			"admin_service_account_id %q does not own the supplied api_key; Temporal Cloud "+
				"reports owner %q. Remove admin_service_account_id and let Vault derive it",
			suppliedAdminSAID, keyMetadata.OwnerID), nil
	}
	cfg.AdminServiceAccountID = keyMetadata.OwnerID

	// Reading the owner service account proves the key has the account-level
	// access issuance and rotation need; inspecting its own key alone would not
	// distinguish a restricted service account from a Global Admin.
	if _, err := c.GetServiceAccount(ctx, cfg.AdminServiceAccountID); err != nil {
		switch {
		case errors.Is(err, client.ErrNotFound):
			return logical.ErrorResponse(
				"Temporal Cloud reports service account %q as the api_key owner, but that "+
					"service account does not exist", cfg.AdminServiceAccountID), nil
		case errors.Is(err, client.ErrPermissionDenied):
			return logical.ErrorResponse(
				"the supplied api_key belongs to service account %q, but it lacks Global Admin "+
					"permission required to manage service accounts and API keys",
				cfg.AdminServiceAccountID), nil
		default:
			return respondCloudErr("validating the Temporal Cloud credential", err)
		}
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Drop any cached client so the next request picks up the new credential.
	b.resetClient()

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	// api_key is deliberately absent: Vault never hands the root credential
	// back out, only replaces it.
	return &logical.Response{
		Data: map[string]interface{}{
			"admin_service_account_id": cfg.AdminServiceAccountID,
			"api_key_id":               cfg.APIKeyID,
			"address":                  cfg.Address,
			"root_key_ttl":             int64(cfg.RootKeyTTL.Seconds()),
		},
	}, nil
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}
	b.resetClient()
	return nil, nil
}

// clientConfig converts the stored configuration into what the client package
// needs, keeping Vault's field names out of the client package.
func (c *config) clientConfig() client.Config {
	return client.Config{APIKey: c.APIKey, HostPort: c.Address}
}

// getConfig loads the stored configuration, returning nil if unconfigured.
func (b *backend) getConfig(ctx context.Context, s logical.Storage) (*config, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	cfg := &config{}
	if err := entry.DecodeJSON(cfg); err != nil {
		return nil, fmt.Errorf("decoding stored config: %w", err)
	}
	return cfg, nil
}

const pathConfigHelp = `
Configures how the engine reaches Temporal Cloud.

The root credential must be an API key owned by a service account with the
Global Admin or Account Owner role, because only those roles can manage service
accounts and their API keys. It must be a service-account key rather than a user
key: Temporal Cloud's CreateApiKey supports service-account owners only, so a
user-owned key could not be rotated by this engine.

Updating merges against what is already stored: address and root_key_ttl keep
their current values when omitted, so a write that only swaps the credential
does not quietly revert them to defaults. api_key is required on every write.
admin_service_account_id is optional and retained only as a compatibility
check; when supplied, it must match the owner Temporal Cloud reports.

Nothing is stored until the credential has been proven to work. The key is
parsed first, then used to read its own Cloud Ops record. Vault rejects a
user-owned key and derives a service-account-owned key's owner ID from that
record. A GetServiceAccount call on the derived owner then proves the key has
the account-level access issuance and rotation require. A key that fails any
step is rejected and nothing is persisted.

api_key_id is read-only: returned by a read, rejected on a write. A Temporal
Cloud API key is a JWT that names its own ID, so Vault reads the ID out of
api_key rather than asking for it. That means it always describes the key
actually in use, and rotate-root can always delete the key it replaces —
including a key an operator pasted in by hand. A key whose ID cannot be read is
rejected rather than stored: it would give you a mount that works until the day
it has to rotate, and then strands the key it was meant to replace.

After writing this path, run "config/rotate-root" so Vault replaces the
bootstrap key with one that has never existed outside Vault. The pasted key is
deleted as part of that.
`
