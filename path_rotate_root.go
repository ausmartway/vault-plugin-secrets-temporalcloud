package temporalcloud

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

func (b *backend) pathRotateRoot() *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRotateRootWrite,
				// Rotation is not idempotent and mutates the credential, so
				// it must not be replicated as a read.
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis:    "Replace the root API key with a newly minted one.",
		HelpDescription: pathRotateRootHelp,
	}
}

// pathRotateRootWrite mints a fresh API key on the configured admin service
// account, verifies it, stores it, then deletes the key it replaced.
//
// The ordering is deliberate. Verifying before storing means a key that does
// not work never becomes the stored credential; storing before deleting means
// a failure at the last step leaves two working keys rather than none. Every
// intermediate failure leaves the mount usable.
func (b *backend) pathRotateRootWrite(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse(errBackendNotConfigured.Error()), nil
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// 1. Mint the replacement.
	newKey, err := c.CreateAPIKey(ctx, client.APIKeySpec{
		ServiceAccountID: cfg.AdminServiceAccountID,
		DisplayName:      fmt.Sprintf("vault-root-%d", time.Now().Unix()),
		Description:      "Vault root credential for the Temporal Cloud secrets engine",
		ExpiryTime:       time.Now().Add(cfg.RootKeyTTL),
	})
	if err != nil {
		return nil, fmt.Errorf("minting a replacement root API key: %w", err)
	}

	// 2. Verify it before trusting it. A key that cannot read the admin
	//    service account would leave the mount unable to do anything.
	newCfg := *cfg
	newCfg.APIKey = newKey.Token
	newCfg.APIKeyID = newKey.ID

	verifyClient, err := b.newClient(newCfg.clientConfig())
	if err != nil {
		return nil, fmt.Errorf("building a client for the new root key: %w", err)
	}
	defer func() { _ = verifyClient.Close() }()

	if _, err := verifyClient.GetServiceAccount(ctx, cfg.AdminServiceAccountID); err != nil {
		// Clean up the key we just made but cannot use, so it does not linger
		// and consume one of the service account's twenty slots.
		if delErr := c.DeleteAPIKey(ctx, newKey.ID); delErr != nil {
			b.Logger().Error("could not delete the unusable replacement root key; "+
				"delete it by hand", "api_key_id", newKey.ID, "error", delErr)
		}
		return logical.ErrorResponse(
			"the newly minted root key failed verification, so the existing "+
				"credential was left in place: %s", err), nil
	}

	// 3. Store it. From here on, the new key is the credential.
	entry, err := logical.StorageEntryJSON(configStoragePath, &newCfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("storing the new root credential: %w", err)
	}
	b.resetClient()

	resp := &logical.Response{}

	// 4. Delete the key we replaced, if we know which one it was.
	if cfg.APIKeyID == "" {
		resp.AddWarning(
			"The previous root API key was not deleted because its ID is unknown — " +
				"api_key_id was not supplied when config was written. Delete it manually " +
				"in the Temporal Cloud UI. Future rotations will clean up automatically.")
		return resp, nil
	}

	// Use verifyClient rather than c: resetClient above closed c's gRPC
	// connection (c is the cached client getClient returned), and a call on a
	// closed connection would always fail. verifyClient is authenticated with
	// the new key, which has the same service-account permissions, and stays
	// open until this function returns.
	if err := verifyClient.DeleteAPIKey(ctx, cfg.APIKeyID); err != nil {
		// The rotation itself succeeded, so this is a warning rather than an
		// error: failing the request would suggest the new key is not in use.
		resp.AddWarning(fmt.Sprintf(
			"The new root API key is in use, but the previous key %q could not be "+
				"deleted: %s. Delete it manually in the Temporal Cloud UI.",
			cfg.APIKeyID, err))
	}

	return resp, nil
}

const pathRotateRootHelp = `
Mints a new API key on the configured admin service account, verifies it,
stores it as the engine's root credential, and deletes the key it replaced.

Run this immediately after configuring the engine. Doing so means the bootstrap
key an operator pasted into "config" is destroyed, and the only working root
credential is one that has never existed outside Vault.

Temporal Cloud API keys always expire, with a maximum lifetime of two years, so
this must be run again before root_key_ttl elapses. If the root key expires, the
mount stops working until an operator writes "config" with a fresh key.
`
