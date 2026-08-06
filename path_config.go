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
	// replaces. Optional, because the bootstrap key's ID cannot be derived
	// from its token.
	APIKeyID string `json:"api_key_id"`

	// AdminServiceAccountID owns APIKey. Required because the Cloud Ops API
	// has no whoami call: given only a token, we cannot discover which
	// identity it belongs to, and rotate-root must mint against that identity.
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
			"api_key_id": {
				Type:        framework.TypeString,
				Description: "ID of the API key given in api_key. Optional; lets rotate-root delete the key it replaces.",
			},
			"admin_service_account_id": {
				Type:        framework.TypeString,
				Description: "ID of the service account that owns api_key. Required: the Cloud Ops API cannot report a token's owner.",
			},
			"address": {
				Type:        framework.TypeString,
				Default:     defaultAddress,
				Description: "Cloud Ops API address. Override for PrivateLink or non-production endpoints.",
			},
			"root_key_ttl": {
				Type:        framework.TypeDurationSecond,
				Default:     int(defaultRootKeyTTL.Seconds()),
				Description: "Expiry applied to root API keys minted by rotate-root. Maximum two years.",
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

	adminSAID := d.Get("admin_service_account_id").(string)
	if adminSAID == "" {
		return logical.ErrorResponse(
			"admin_service_account_id is required: the Cloud Ops API cannot report which " +
				"identity owns an API key, and rotate-root must mint against that identity"), nil
	}

	rootKeyTTL := time.Duration(d.Get("root_key_ttl").(int)) * time.Second
	if rootKeyTTL <= 0 {
		rootKeyTTL = defaultRootKeyTTL
	}
	if rootKeyTTL > client.MaxAPIKeyExpiry {
		return logical.ErrorResponse(
			"root_key_ttl of %s exceeds Temporal Cloud's maximum API key expiry of %s",
			rootKeyTTL, client.MaxAPIKeyExpiry), nil
	}

	cfg := &config{
		APIKey:                apiKey,
		APIKeyID:              d.Get("api_key_id").(string),
		AdminServiceAccountID: adminSAID,
		Address:               d.Get("address").(string),
		RootKeyTTL:            rootKeyTTL,
	}
	if cfg.Address == "" {
		cfg.Address = defaultAddress
	}

	// Validate before persisting. One GetServiceAccount call proves both that
	// the key authenticates and that admin_service_account_id is correct, so
	// the operator learns about a mistake now rather than at first use.
	c, err := b.newClient(cfg.clientConfig())
	if err != nil {
		return logical.ErrorResponse("could not build a Temporal Cloud client: %s", err), nil
	}
	defer func() {
		// This client is for validation only; the cached one is built lazily
		// on the next request.
		_ = c.Close()
	}()

	if _, err := c.GetServiceAccount(ctx, adminSAID); err != nil {
		switch {
		case errors.Is(err, client.ErrNotFound):
			return logical.ErrorResponse(
				"no service account %q exists in this Temporal Cloud account; "+
					"check admin_service_account_id", adminSAID), nil
		case errors.Is(err, client.ErrPermissionDenied):
			return logical.ErrorResponse(
				"the supplied api_key was rejected, or its service account lacks "+
					"permission to read %q: %s", adminSAID, err), nil
		default:
			return nil, fmt.Errorf("validating the Temporal Cloud credential: %w", err)
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

After writing this path, run "config/rotate-root" so Vault replaces the
bootstrap key with one only it holds.
`
