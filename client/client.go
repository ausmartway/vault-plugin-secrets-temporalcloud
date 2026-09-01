// Package client wraps the Temporal Cloud Ops API for the Vault secrets
// engine. It is the only package that knows about gRPC or the Cloud Ops API's
// asynchronous operation model; everything above it works in plain Go types.
package client

import (
	"context"
	"time"
)

// CloudOps is the seam between Vault logic and Temporal Cloud. Every method
// blocks until the underlying Cloud Ops async operation reaches a terminal
// state, so callers never poll.
type CloudOps interface {
	// CreateServiceAccount creates a service account and returns its ID.
	CreateServiceAccount(ctx context.Context, spec ServiceAccountSpec) (string, error)

	// GetServiceAccount fetches a service account, including the resource
	// version needed for optimistic concurrency on updates and deletes.
	GetServiceAccount(ctx context.Context, id string) (*ServiceAccount, error)

	// UpdateServiceAccount replaces a service account's spec. The current
	// resource version is fetched internally.
	UpdateServiceAccount(ctx context.Context, id string, spec ServiceAccountSpec) error

	// DeleteServiceAccount deletes a service account. Temporal Cloud also
	// invalidates the API keys it owns.
	DeleteServiceAccount(ctx context.Context, id string) error

	// FindServiceAccountByName looks up an active service account by its
	// Temporal Cloud name, returning ErrNotFound if none carries that name.
	//
	// Temporal Cloud requires these names to be unique across active service
	// accounts, so this is how the engine detects that a name an operator
	// asked for is already taken by an account Vault did not create.
	FindServiceAccountByName(ctx context.Context, name string) (*ServiceAccount, error)

	// CreateAPIKey mints an API key. The returned APIKey carries the token,
	// which Temporal Cloud reveals exactly once.
	CreateAPIKey(ctx context.Context, spec APIKeySpec) (*APIKey, error)

	// GetAPIKey fetches a key's owner metadata. Configuration uses this to
	// derive the root key's service account rather than asking an operator to
	// supply an ID the API can report authoritatively.
	GetAPIKey(ctx context.Context, id string) (*APIKeyMetadata, error)

	// DeleteAPIKey deletes an API key by ID.
	DeleteAPIKey(ctx context.Context, id string) error

	// CountAPIKeys counts non-expired API keys owned by a service account,
	// used to check Temporal Cloud's per-service-account ceiling before
	// minting another.
	CountAPIKeys(ctx context.Context, serviceAccountID string) (int, error)

	// Close releases the underlying connection.
	Close() error
}

// Config is what a CloudOps implementation needs to reach Temporal Cloud.
type Config struct {
	// APIKey is a Temporal Cloud API key owned by a service account with the
	// Global Admin role.
	APIKey string

	// HostPort overrides the Cloud Ops API address. Empty means the SDK
	// default, saas-api.tmprl.cloud:443.
	HostPort string
}

// ServiceAccountSpec describes a Temporal Cloud service account. AccountRole
// and the values of NamespaceAccess are the lowercase forms an operator writes
// ("developer", "write"); client/access.go validates and converts them.
type ServiceAccountSpec struct {
	Name        string
	Description string
	AccountRole string

	// NamespaceAccess maps a fully-qualified namespace ("prod.acct1") to a
	// permission ("admin", "write", or "read").
	NamespaceAccess map[string]string
}

// ServiceAccount is a service account as Temporal Cloud reports it.
type ServiceAccount struct {
	ID              string
	ResourceVersion string
	Spec            ServiceAccountSpec
}

// APIKeySpec describes an API key to mint. ExpiryTime is mandatory: Temporal
// Cloud has no non-expiring keys, and the maximum is two years out.
type APIKeySpec struct {
	ServiceAccountID string
	DisplayName      string
	Description      string
	ExpiryTime       time.Time
}

// APIKey is a newly minted API key. Token is populated only at creation and is
// never persisted by this engine.
type APIKey struct {
	ID    string
	Token string
}

// APIKeyOwnerType identifies the kind of identity that owns an API key without
// exposing Cloud API protobuf enums above this package.
type APIKeyOwnerType string

const (
	APIKeyOwnerUnknown        APIKeyOwnerType = "unknown"
	APIKeyOwnerUser           APIKeyOwnerType = "user"
	APIKeyOwnerServiceAccount APIKeyOwnerType = "service-account"
)

// APIKeyMetadata is the stable subset of a key record configuration needs to
// identify and validate the root credential's owner.
type APIKeyMetadata struct {
	ID        string
	OwnerID   string
	OwnerType APIKeyOwnerType
}

// MaxAPIKeysPerServiceAccount is Temporal Cloud's ceiling on non-expired API
// keys owned by one service account, and therefore this engine's ceiling on
// concurrent leases per service-accounts/<name> entry.
const MaxAPIKeysPerServiceAccount = 20

// MaxAPIKeyExpiry is the furthest out Temporal Cloud will accept an API key
// expiry time.
const MaxAPIKeyExpiry = 2 * 365 * 24 * time.Hour

// MinAPIKeyExpiry is the closest in Temporal Cloud will accept an API key
// expiry time. It is undocumented — found empirically via live testing, which
// hit "invalid argument: expiry must be after ... (24h0m0s from now)" when
// minting a key with a short max_ttl. The engine floors a key's expiry at
// this minimum so mint requests succeed regardless of max_ttl.
const MinAPIKeyExpiry = 24 * time.Hour
