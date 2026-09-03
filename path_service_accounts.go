package temporalcloud

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

const (
	// serviceAccountStoragePrefix is singular while the API path is plural,
	// following the convention in Vault's own engines.
	serviceAccountStoragePrefix = "service-account/"

	defaultServiceAccountTTL    = time.Hour
	defaultServiceAccountMaxTTL = 24 * time.Hour

	// apiKeyExpiryGrace is added to max_ttl when setting a key's Temporal
	// Cloud expiry, so a key never expires before the lease that owns it.
	apiKeyExpiryGrace = 10 * time.Minute
)

// serviceAccountEntry is a Vault-side service account definition: the Temporal
// Cloud spec plus the credential policy applied to keys minted from it.
type serviceAccountEntry struct {
	// ServiceAccountID is the Temporal Cloud ID, and the only durable link
	// between this entry and the cloud-side resource.
	ServiceAccountID string `json:"service_account_id"`

	AccountRole     string            `json:"account_role"`
	NamespaceAccess map[string]string `json:"namespace_access"`
	Description     string            `json:"description"`

	TTL    time.Duration `json:"ttl"`
	MaxTTL time.Duration `json:"max_ttl"`

	// Adopted marks an entry that was bound to a service account Vault did
	// not create — one that already existed in Temporal Cloud under this
	// name and was claimed with force=true. It changes nothing about how
	// this entry behaves; it exists so an operator reading the entry, or
	// deciding whether to delete it, knows the Temporal Cloud side predates
	// Vault managing it.
	Adopted bool `json:"adopted"`

	// VerifyPropagation makes creds/<name> wait for every namespace in
	// NamespaceAccess to accept a newly minted key before returning it.
	// Defaults off: it costs five connections per namespace at minimum and
	// needs egress from the Vault node to the namespace frontends, which not
	// every deployment has.
	VerifyPropagation bool `json:"verify_propagation"`
}

func serviceAccountStoragePath(name string) string {
	return serviceAccountStoragePrefix + name
}

func (b *backend) pathServiceAccounts() *framework.Path {
	return &framework.Path{
		Pattern: "service-accounts/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name for this service account. Also becomes its name in Temporal Cloud.",
			},
			"account_role": {
				Type:        framework.TypeString,
				Description: "Account-level role: owner, admin, developer, finance-admin, read, or metrics-read. Required.",
			},
			"namespace_access": {
				Type:        framework.TypeCommaStringSlice,
				Description: `Namespace permissions as "namespace=permission" pairs, where permission is admin, write, or read. Example: prod.acct1=write,staging.acct1=read. On update, omit this field to leave existing namespace permissions untouched; pass an empty string to deliberately clear all of them (this reaches Temporal Cloud).`,
			},
			"description": {
				Type:        framework.TypeString,
				Description: "Description shown in the Temporal Cloud UI.",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default lease TTL for API keys issued from this service account.",
			},
			"max_ttl": {
				Type: framework.TypeDurationSecond,
				Description: "Maximum lease TTL. Also sets the Temporal Cloud expiry on every key minted " +
					"here (max_ttl plus a short grace margin). Temporal Cloud will not accept an expiry less " +
					"than 24 hours out, so a max_ttl below that is floored up to 24 hours for the purpose of " +
					"the Temporal Cloud expiry only — the key is still deleted when its lease ends, so a " +
					"short max_ttl still means a short-lived credential in practice. Raising max_ttl does " +
					"not extend leases that already exist: their keys carry the expiry they were minted " +
					"with, and Temporal Cloud cannot extend an existing key's expiry.",
			},
			"force": {
				Type: framework.TypeBool,
				Description: "If a service account with this name already exists in Temporal Cloud, adopt it and " +
					"reset its permissions to this specification instead of failing. Adoption makes the account " +
					"fully Vault-managed, exactly as if Vault had created it: deleting this entry afterward " +
					"deletes it in Temporal Cloud too. Ignored when updating an entry Vault already manages.",
			},
			"verify_propagation": {
				Type:    framework.TypeBool,
				Default: true,
				Description: "Before returning a credential, verify that every namespace in " +
					"namespace_access accepts the newly minted key. Temporal Cloud distributes keys " +
					"asynchronously, so a key the Cloud Ops API reports as created is not yet accepted " +
					"everywhere; a worker handed one fails at startup rather than retrying. This requires " +
					"the configured number of consecutive checks (ten by default) over fresh " +
					"connections per namespace and egress from the " +
					"Vault node to <namespace>.tmprl.cloud:7233. On timeout the credential is still returned, with a " +
					"warning naming the namespace. Defaults to true; set false to opt out.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathServiceAccountWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathServiceAccountWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathServiceAccountRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathServiceAccountDelete},
		},
		ExistenceCheck:  b.serviceAccountExists,
		HelpSynopsis:    "Manage a Temporal Cloud service account.",
		HelpDescription: pathServiceAccountHelp,
	}
}

func (b *backend) pathServiceAccountsList() *framework.Path {
	return &framework.Path{
		Pattern: "service-accounts/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathServiceAccountList},
		},
		HelpSynopsis: "List Vault-managed Temporal Cloud service accounts.",
	}
}

func (b *backend) serviceAccountExists(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	entry, err := b.getServiceAccount(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *backend) pathServiceAccountWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	existing, err := b.getServiceAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	// force describes an action ("adopt if this name collides"), not stored
	// state, so unlike namespace_access/ttl/max_ttl/description it is never
	// merged from an existing entry — it is read fresh on every write.
	force := d.Get("force").(bool)

	accountRole := d.Get("account_role").(string)
	if accountRole == "" {
		return logical.ErrorResponse("account_role is required"), nil
	}
	if _, err := client.ParseAccountRole(accountRole); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// namespace_access, ttl, max_ttl, and description merge against the stored
	// entry on update: an operator who omits a field means "leave it alone,"
	// not "reset it." d.GetOk reports whether the key was present in the
	// request at all, which is the only way to tell "omitted" from
	// "explicitly set to the zero value" (e.g. namespace_access="" to
	// deliberately clear it). account_role is exempt — it stays required on
	// every write. On create there is no stored entry to fall back to, so
	// every field behaves exactly as before: absent means default.
	_, namespaceAccessSet := d.GetOk("namespace_access")
	_, ttlSet := d.GetOk("ttl")
	_, maxTTLSet := d.GetOk("max_ttl")
	_, descriptionSet := d.GetOk("description")
	_, verifyPropagationSet := d.GetOk("verify_propagation")

	var namespaceAccess map[string]string
	var ttl, maxTTL time.Duration
	var description string

	if existing != nil && !namespaceAccessSet {
		namespaceAccess = existing.NamespaceAccess
	} else {
		namespaceAccess, err = parseNamespaceAccess(d.Get("namespace_access").([]string))
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	}

	if existing != nil && !ttlSet {
		ttl = existing.TTL
	} else {
		ttl = time.Duration(d.Get("ttl").(int)) * time.Second
		if ttl == 0 {
			ttl = defaultServiceAccountTTL
		}
	}

	if existing != nil && !maxTTLSet {
		maxTTL = existing.MaxTTL
	} else {
		maxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
		if maxTTL == 0 {
			maxTTL = defaultServiceAccountMaxTTL
		}
	}

	if ttl > maxTTL {
		return logical.ErrorResponse("ttl of %s exceeds max_ttl of %s", ttl, maxTTL), nil
	}
	// Every key minted here expires at max_ttl plus a grace margin, so max_ttl
	// must leave room under Temporal Cloud's two-year ceiling. There is no
	// matching floor check: a max_ttl below Temporal Cloud's undocumented
	// 24-hour minimum is legal here and rejects nothing, because path_creds.go
	// floors the Temporal Cloud expiry up to that minimum at mint time rather
	// than sending max_ttl's true value and having Temporal Cloud reject it.
	if maxTTL+apiKeyExpiryGrace > client.MaxAPIKeyExpiry {
		return logical.ErrorResponse(
			"max_ttl of %s exceeds Temporal Cloud's maximum API key expiry of %s "+
				"(minus a %s grace margin)",
			maxTTL, client.MaxAPIKeyExpiry, apiKeyExpiryGrace), nil
	}

	if existing != nil && !descriptionSet {
		description = existing.Description
	} else {
		description = d.Get("description").(string)
		if description == "" {
			description = fmt.Sprintf("Managed by Vault mount %s", req.MountPoint)
		}
	}

	// Same merge rule as ttl and description: an update that does not mention
	// the field leaves it alone, so changing ttl cannot silently disable the
	// probe.
	verifyPropagation := d.Get("verify_propagation").(bool)
	if existing != nil && !verifyPropagationSet {
		verifyPropagation = existing.VerifyPropagation
	}

	entry := &serviceAccountEntry{
		AccountRole:       accountRole,
		NamespaceAccess:   namespaceAccess,
		Description:       description,
		TTL:               ttl,
		MaxTTL:            maxTTL,
		VerifyPropagation: verifyPropagation,
	}

	spec := client.ServiceAccountSpec{
		Name:            name,
		Description:     entry.Description,
		AccountRole:     accountRole,
		NamespaceAccess: namespaceAccess,
	}

	c, release, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	defer release()

	switch {
	case existing == nil:
		// Temporal Cloud requires service-account names to be unique, so a
		// name already in use would be rejected by the server with a message
		// that does not tell the operator what to do about it. Check first and
		// explain the options ourselves.
		found, err := c.FindServiceAccountByName(ctx, name)
		switch {
		case err == nil:
			if !force {
				return logical.ErrorResponse(
					"a service account named %q already exists in Temporal Cloud (id %s) and "+
						"Vault did not create it. Either choose a different name, or re-run "+
						"with force=true to have Vault adopt that account and reset its "+
						"permissions to this specification.",
					name, found.ID), nil
			}

			// Adopt it: bind to the existing account and overwrite its spec so
			// what Vault stores and what Temporal Cloud enforces agree.
			entry.ServiceAccountID = found.ID
			entry.Adopted = true

			if err := c.UpdateServiceAccount(ctx, found.ID, spec); err != nil {
				return respondCloudErr(fmt.Sprintf("adopting service account %q", name), err)
			}

		case errors.Is(err, client.ErrNotFound):
			// The name is free — create it, which is the ordinary path.
			id, err := c.CreateServiceAccount(ctx, spec)
			if err != nil {
				// CreateServiceAccount deliberately returns the new ID even
				// when the wait for the async operation failed, because the
				// account may exist in Temporal Cloud regardless. Use it:
				// a half-created account holds the name, so leaving it there
				// makes every retry of this write collide with a service
				// account the operator never asked for and cannot find by
				// name in Vault.
				if id != "" {
					if delErr := c.DeleteServiceAccount(ctx, id); delErr != nil {
						b.Logger().Error(
							"could not delete a service account whose creation did not "+
								"complete; delete it by hand",
							"service_account_id", id, "name", name, "error", delErr)
					}
				}
				return respondCloudErr(
					fmt.Sprintf("creating service account %q in Temporal Cloud", name), err)
			}
			entry.ServiceAccountID = id

		default:
			// Any other lookup failure must not fall through to creating a
			// duplicate — we simply do not know whether the name is free.
			return respondCloudErr(
				fmt.Sprintf("checking whether service account %q already exists", name), err)
		}

	default:
		entry.ServiceAccountID = existing.ServiceAccountID

		// Adoption records how this binding came to exist, so it is carried
		// forward rather than re-derived: entry is rebuilt from the request on
		// every write, and force is read fresh, so without this an ordinary
		// update clears the flag. That matters because Adopted is the only
		// signal telling an operator that Vault manages an account it did not
		// create — and that deleting this entry destroys it anyway.
		entry.Adopted = existing.Adopted

		// Only call Temporal Cloud if something it knows about changed. TTLs
		// are a Vault-side concern, so a TTL-only edit needs no API call.
		if cloudSpecChanged(existing, entry) {
			if err := c.UpdateServiceAccount(ctx, entry.ServiceAccountID, spec); err != nil {
				return respondCloudErr(
					fmt.Sprintf("updating service account %q in Temporal Cloud", name), err)
			}
		}
	}

	storageEntry, err := logical.StorageEntryJSON(serviceAccountStoragePath(name), entry)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, storageEntry); err != nil {
		// Temporal Cloud has a service account Vault does not know about.
		// Compensate so it does not leak, and if that fails too, log the ID
		// loudly so an operator can clean up by hand. An adopted account is
		// exempt: Vault did not create it, so deleting it here would destroy
		// an account that predates this write and that Vault has no right to
		// remove just because its own storage write failed.
		if existing == nil && !entry.Adopted {
			if delErr := c.DeleteServiceAccount(ctx, entry.ServiceAccountID); delErr != nil {
				b.Logger().Error(
					"could not persist the service account and could not delete the "+
						"one created in Temporal Cloud; delete it by hand",
					"service_account_id", entry.ServiceAccountID,
					"name", name,
					"storage_error", err,
					"delete_error", delErr)
			}
		}
		return nil, fmt.Errorf("storing service account %q: %w", name, err)
	}

	return nil, nil
}

// cloudSpecChanged reports whether anything Temporal Cloud knows about differs.
func cloudSpecChanged(old, new *serviceAccountEntry) bool {
	if old.AccountRole != new.AccountRole || old.Description != new.Description {
		return true
	}
	if len(old.NamespaceAccess) != len(new.NamespaceAccess) {
		return true
	}
	for namespace, permission := range new.NamespaceAccess {
		if old.NamespaceAccess[namespace] != permission {
			return true
		}
	}
	return false
}

func (b *backend) pathServiceAccountRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getServiceAccount(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	namespaceAccess := make([]string, 0, len(entry.NamespaceAccess))
	for namespace, permission := range entry.NamespaceAccess {
		namespaceAccess = append(namespaceAccess, namespace+"="+permission)
	}
	sort.Strings(namespaceAccess) // stable output

	return &logical.Response{
		Data: map[string]interface{}{
			"service_account_id": entry.ServiceAccountID,
			"account_role":       entry.AccountRole,
			"namespace_access":   namespaceAccess,
			"description":        entry.Description,
			"ttl":                int64(entry.TTL.Seconds()),
			"max_ttl":            int64(entry.MaxTTL.Seconds()),
			"adopted":            entry.Adopted,
			"verify_propagation": entry.VerifyPropagation,
		},
	}, nil
}

func (b *backend) pathServiceAccountDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	entry, err := b.getServiceAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	c, release, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	defer release()

	resp := &logical.Response{}

	if err := c.DeleteServiceAccount(ctx, entry.ServiceAccountID); err != nil {
		if !errors.Is(err, client.ErrNotFound) {
			return respondCloudErr(
				fmt.Sprintf("deleting service account %q from Temporal Cloud", name), err)
		}
		// Already gone in Temporal Cloud — someone deleted it out of band.
		// Removing the Vault entry is still the right outcome.
		resp.AddWarning(fmt.Sprintf(
			"service account %q was already absent from Temporal Cloud; removed the Vault entry", name))
	}

	if err := req.Storage.Delete(ctx, serviceAccountStoragePath(name)); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *backend) pathServiceAccountList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, serviceAccountStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

// getServiceAccount loads an entry, returning nil if it does not exist.
func (b *backend) getServiceAccount(ctx context.Context, s logical.Storage, name string) (*serviceAccountEntry, error) {
	if name == "" {
		return nil, errors.New("service account name must not be empty")
	}

	raw, err := s.Get(ctx, serviceAccountStoragePath(name))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	entry := &serviceAccountEntry{}
	if err := raw.DecodeJSON(entry); err != nil {
		return nil, fmt.Errorf("decoding service account %q: %w", name, err)
	}
	return entry, nil
}

// parseNamespaceAccess turns "namespace=permission" pairs into a map,
// rejecting every malformed shape with a message naming the offending entry.
func parseNamespaceAccess(pairs []string) (map[string]string, error) {
	access := make(map[string]string, len(pairs))

	for _, pair := range pairs {
		if strings.TrimSpace(pair) == "" {
			continue
		}

		parts := strings.Split(pair, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf(
				"invalid namespace_access entry %q: expected namespace=permission", pair)
		}

		namespace := strings.TrimSpace(parts[0])
		permission := strings.TrimSpace(parts[1])

		if namespace == "" {
			return nil, fmt.Errorf("invalid namespace_access entry %q: namespace must not be empty", pair)
		}
		if permission == "" {
			return nil, fmt.Errorf("invalid namespace_access entry %q: permission must not be empty", pair)
		}
		if _, err := client.ParseNamespacePermission(permission); err != nil {
			return nil, fmt.Errorf("invalid namespace_access entry %q: %w", pair, err)
		}
		if _, seen := access[namespace]; seen {
			return nil, fmt.Errorf("duplicate namespace %q in namespace_access", namespace)
		}

		access[namespace] = permission
	}

	return access, nil
}

const pathServiceAccountHelp = `
Defines a Temporal Cloud service account managed by Vault, and the credential
policy for API keys issued from it.

Creating requires the full spec: account_role, and optionally namespace_access,
description, ttl, and max_ttl. Deleting it deletes the service account, which
invalidates every API key it owns.

Revoke the outstanding leases before deleting an entry:

    vault lease revoke -prefix <mount>/creds/<name>
    vault delete <mount>/service-accounts/<name>

Deleting the entry removes the service account in Temporal Cloud while leases
still reference the API keys it owned. Those leases can still be revoked
afterwards — revocation treats an already-absent key as success — but that
path has never been exercised against a live account, so revoking first keeps
the teardown on the behaviour that has.

Temporal Cloud requires service-account names to be unique across all active
service accounts. Creating a name already in use there fails, naming the
colliding account's ID and explaining the choice: pick a different name, or
re-run with force=true. force=true adopts that existing account instead of
creating a new one, resetting its permissions to the specification in this
write. Adoption makes the account fully Vault-managed, exactly as if Vault had
created it: in particular, 'vault delete' on this entry afterward deletes the
service account in Temporal Cloud, invalidating its API keys, the same as for
any other entry. force is ignored when updating an entry Vault already
manages — the binding already exists, so there is nothing to adopt.

Read whether an entry was adopted rather than created via the adopted field on
'vault read'.

Updating merges against what is already stored: any of namespace_access,
description, ttl, or max_ttl that you omit keeps its current value, so
'vault write service-accounts/<name> account_role=admin' changes only the role.
account_role itself is required on every write. To deliberately clear
namespace_access, pass it explicitly as an empty string
(namespace_access="") — that reaches Temporal Cloud and revokes those
namespace permissions, unlike a ttl or max_ttl change, which is Vault-side only
and makes no Temporal Cloud call.

Read credentials for this service account from creds/<name>.

Protect this path with Vault policy. An operator who can write here can create a
service account with the owner role and then mint keys for it, so write access
belongs only to platform operators. Applications need read on creds/<name> only.
`
