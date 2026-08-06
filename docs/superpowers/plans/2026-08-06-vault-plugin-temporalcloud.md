# Temporal Cloud Vault Secrets Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a HashiCorp Vault secrets engine that provisions Temporal Cloud service accounts and issues short-lived, automatically-revoked Temporal Cloud API keys as Vault dynamic secrets.

**Architecture:** A Vault plugin with two management path layers — `service-accounts/<name>` does CRUD against the Temporal Cloud Ops API, and `creds/<name>` mints one API key per Vault lease on the named service account, deleting it on revocation. All Cloud Ops traffic goes through a narrow `client.CloudOps` interface that hides gRPC and the API's async-operation polling from every caller above it.

**Tech Stack:** Go 1.26, `github.com/hashicorp/vault/sdk` v0.25.1 (plugin framework), `go.temporal.io/cloud-sdk` v0.16.0 (Cloud Ops client and generated protos), gRPC.

**Spec:** `docs/superpowers/specs/2026-08-06-vault-plugin-temporalcloud-design.md` — read it before starting. It records why each decision was made, which this plan does not repeat.

## Global Constraints

Every task's requirements implicitly include this section.

- **Module path:** `github.com/temporal-sa/vault-plugin-temporalcloud`. Go directive `go 1.26`.
- **Package name:** `temporalcloud` at the repo root; `client` in `client/`.
- **Cloud Ops Go client is `go.temporal.io/cloud-sdk` v0.16.0, package `cloudclient`.** Not `go.temporal.io/api` (it has no `cloud/` package) and not `github.com/temporalio/cloud-api` (protos only, no Go code). Getting this wrong wastes an hour. Both dependency versions below are the current releases as of 2026-08-06 — pin them exactly; do not use `@latest`, which drifts.
- **Terminal async success state is `AsyncOperation_STATE_FULFILLED`.** There is no `SUCCEEDED`. `FAILED`, `CANCELLED`, `REJECTED` are terminal errors.
- **Never hand-roll retries or `async_operation_id`.** The SDK's default interceptor already sets operation IDs on writes and retries with exponential backoff + jitter, max 7 attempts. Setting `DisableRetry` or adding your own is wrong.
- **API key tokens are never persisted.** Only the key ID goes into lease internal data. `config` read never returns `api_key`.
- **Temporal Cloud limits:** 20 non-expired API keys per service account; maximum API key expiry 2 years; API key expiry is mandatory.
- **Account roles:** `owner`, `admin`, `developer`, `finance-admin`, `read`, `metrics-read`. **Namespace permissions:** `admin`, `write`, `read`.
- **No git remote, no push.** This repo stays local until the engine is verified against a live account. Commit locally as normal.
- **Comment the *why*, not the *what*.** This is customer-facing demo material; a reader may not know Vault or Temporal.
- Run `gofmt -w .` before every commit. Run `golangci-lint run` if available.

## File Structure

| File | Responsibility |
| --- | --- |
| `go.mod`, `go.sum` | Dependencies |
| `Makefile` | `build`, `dev`, `test`, `test-live`, `sweep` targets |
| `cmd/vault-plugin-secrets-temporalcloud/main.go` | Plugin entrypoint; serves the backend over Vault's plugin gRPC |
| `backend.go` | `framework.Backend`, path registration, cached client construction, config invalidation |
| `path_config.go` | `config` read/write/delete |
| `path_rotate_root.go` | `config/rotate-root` |
| `path_service_accounts.go` | `service-accounts/<name>` CRUD + list |
| `path_creds.go` | `creds/<name>` read: cap check, TTL math, mint |
| `secret_api_key.go` | Lease renew and revoke |
| `client/client.go` | `CloudOps` interface and its plain-Go types — the seam |
| `client/access.go` | Account role and namespace-access parsing/validation → protos |
| `client/errors.go` | gRPC status → typed engine errors |
| `client/async.go` | Poll `GetAsyncOperation` to a terminal state |
| `client/grpc.go` | `CloudOps` implementation over `cloudclient` |
| `acceptance_test.go` | Live end-to-end tests, build tag `acceptance` |
| `cmd/sweep/main.go` | Deletes leftover `vault-acctest-` resources |
| `README.md` | Problem, setup, every path, the 20-key ceiling, rotate-root warning, policy guidance |
| `examples/` | End-to-end walkthrough |

Tests live beside their subject: `client/access_test.go`, `client/errors_test.go`, `path_creds_test.go`, `path_service_accounts_test.go`, `backend_test.go`.

---

### Task 1: Scaffold, the `CloudOps` interface, and error mapping

Produces a compiling plugin with zero paths registered, plus the seam every later task builds on. No placeholder or stub code is written at any point — the interface is real from the first commit.

**Files:**
- Create: `go.mod`, `Makefile`, `backend.go`, `cmd/vault-plugin-secrets-temporalcloud/main.go`, `client/client.go`, `client/errors.go`
- Modify: `.gitignore` — it already exists and ignores `.superpowers/`. **Extend it, do not replace it.**
- Test: `backend_test.go`, `client/errors_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error)`; `Backend() *backend`
  - the `backend` struct with fields `*framework.Backend`, `clientMu sync.RWMutex`, `client client.CloudOps`
  - `const configStoragePath = "config"` (declared in `backend.go`, used by `invalidate`)
  - test helper `newTestBackend(t *testing.T) (*backend, logical.Storage)`
  - `type CloudOps interface` with methods `CreateServiceAccount(ctx, ServiceAccountSpec) (string, error)`, `GetServiceAccount(ctx, string) (*ServiceAccount, error)`, `UpdateServiceAccount(ctx, string, ServiceAccountSpec) error`, `DeleteServiceAccount(ctx, string) error`, `CreateAPIKey(ctx, APIKeySpec) (*APIKey, error)`, `DeleteAPIKey(ctx, string) error`, `CountAPIKeys(ctx, string) (int, error)`, `Close() error`
  - types `Config{APIKey, HostPort string}`, `ServiceAccountSpec{Name, Description, AccountRole string; NamespaceAccess map[string]string}`, `ServiceAccount{ID, ResourceVersion string; Spec ServiceAccountSpec}`, `APIKeySpec{ServiceAccountID, DisplayName, Description string; ExpiryTime time.Time}`, `APIKey{ID, Token string}`
  - constants `MaxAPIKeysPerServiceAccount = 20`, `MaxAPIKeyExpiry = 2 * 365 * 24 * time.Hour`
  - errors `ErrNotFound`, `ErrPermissionDenied`, `ErrInvalidArgument`, `ErrResourceExhausted`, `ErrUnavailable`, and `func MapGRPCError(error) error`

Note there is deliberately **no `newClient` field on `backend` in this task**. It is added in Task 3, when `client.NewGRPC` exists to assign to it. Nothing in this task needs it, and a nil function field waiting to be filled in is exactly the kind of half-built state this restructuring avoids.

- [ ] **Step 1: Initialise the module and fetch dependencies**

```bash
cd /Users/yuleiliu/repos/vault-plugin-temporalcloud
go mod init github.com/temporal-sa/vault-plugin-temporalcloud
go get github.com/hashicorp/vault/sdk@v0.25.1
go get go.temporal.io/cloud-sdk@v0.16.0
```

Verify you got what you asked for — a transitive dependency can silently pin an older version:

```bash
go list -m go.temporal.io/cloud-sdk github.com/hashicorp/vault/sdk
# expect: go.temporal.io/cloud-sdk v0.16.0
#         github.com/hashicorp/vault/sdk v0.25.1
```

- [ ] **Step 2: Extend `.gitignore`**

The file already exists with a `.superpowers/` entry. Append to it; do not overwrite:

```gitignore
# Build output
/bin/
vault-plugin-secrets-temporalcloud

# Credentials — never commit these
.env
*.pem
*.key
```

- [ ] **Step 3: Write the failing tests**

Two test files. First `client/errors_test.go`:

```go
package client

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMapGRPCError(t *testing.T) {
	tests := []struct {
		name string
		in   error
		want error
	}{
		{"nil passes through", nil, nil},
		{"not found", status.Error(codes.NotFound, "no such thing"), ErrNotFound},
		{"permission denied", status.Error(codes.PermissionDenied, "nope"), ErrPermissionDenied},
		{"invalid argument", status.Error(codes.InvalidArgument, "bad"), ErrInvalidArgument},
		{"resource exhausted", status.Error(codes.ResourceExhausted, "full"), ErrResourceExhausted},
		{"unavailable", status.Error(codes.Unavailable, "down"), ErrUnavailable},
		{"deadline exceeded maps to unavailable", status.Error(codes.DeadlineExceeded, "slow"), ErrUnavailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MapGRPCError(tc.in)

			if tc.want == nil {
				if got != nil {
					t.Fatalf("expected nil, got %v", got)
				}
				return
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("expected errors.Is(_, %v), got %v", tc.want, got)
			}
		})
	}
}

// The original gRPC message must survive, so operators see Temporal Cloud's
// own explanation rather than only our category.
func TestMapGRPCError_PreservesMessage(t *testing.T) {
	got := MapGRPCError(status.Error(codes.InvalidArgument, "namespace does not exist"))

	if got == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(got.Error(), "namespace does not exist") {
		t.Fatalf("expected original message to survive, got %q", got.Error())
	}
}

// A non-gRPC error must pass through untouched rather than be miscategorised.
func TestMapGRPCError_NonGRPCPassesThrough(t *testing.T) {
	sentinel := errors.New("plain error")

	got := MapGRPCError(sentinel)

	if !errors.Is(got, sentinel) {
		t.Fatalf("expected the original error, got %v", got)
	}
}
```

Then `backend_test.go` — the helper every later task reuses:

```go
package temporalcloud

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// newTestBackend builds a backend against in-memory storage. Tests drive it
// through b.HandleRequest, exactly as Vault does, so no Vault binary is needed.
func newTestBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()

	// TestBackendConfig supplies a logger and system view already; we only
	// need to attach storage.
	conf := logical.TestBackendConfig()
	conf.StorageView = &logical.InmemStorage{}

	b := Backend()
	if err := b.Setup(context.Background(), conf); err != nil {
		t.Fatalf("backend setup: %v", err)
	}
	return b, conf.StorageView
}

func TestBackend_Constructs(t *testing.T) {
	b, _ := newTestBackend(t)

	if b.Backend == nil {
		t.Fatal("expected embedded framework.Backend to be set")
	}
	if b.BackendType != logical.TypeLogical {
		t.Fatalf("expected TypeLogical, got %v", b.BackendType)
	}
}
```

The only imports `backend_test.go` needs are `context`, `testing`, and `github.com/hashicorp/vault/sdk/logical` — verified against vault/sdk v0.25.1, where `logical.TestBackendConfig()` already supplies the logger and system view.

- [ ] **Step 4: Run the tests to verify they fail**

Run: `go test ./... -v`
Expected: FAIL — `undefined: MapGRPCError`, `undefined: Backend`.

- [ ] **Step 5: Write `client/client.go`**

```go
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

	// CreateAPIKey mints an API key. The returned APIKey carries the token,
	// which Temporal Cloud reveals exactly once.
	CreateAPIKey(ctx context.Context, spec APIKeySpec) (*APIKey, error)

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

// MaxAPIKeysPerServiceAccount is Temporal Cloud's ceiling on non-expired API
// keys owned by one service account, and therefore this engine's ceiling on
// concurrent leases per service-accounts/<name> entry.
const MaxAPIKeysPerServiceAccount = 20

// MaxAPIKeyExpiry is the furthest out Temporal Cloud will accept an API key
// expiry time.
const MaxAPIKeyExpiry = 2 * 365 * 24 * time.Hour
```

- [ ] **Step 6: Write `client/errors.go`**

```go
package client

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Sentinel errors the Vault path handlers switch on. They deliberately do not
// mention gRPC: callers above this package decide what each category means for
// a Vault response, and should never import grpc/codes to do it.
var (
	// ErrNotFound means the resource does not exist. On revocation this is
	// success — the API key already expired or was deleted out of band.
	ErrNotFound = errors.New("resource not found")

	// ErrPermissionDenied usually means the configured root API key's service
	// account lacks the Global Admin role.
	ErrPermissionDenied = errors.New("permission denied")

	// ErrInvalidArgument means Temporal Cloud rejected the request as malformed.
	ErrInvalidArgument = errors.New("invalid argument")

	// ErrResourceExhausted means a Temporal Cloud quota was hit. The API key
	// cap is normally caught before the call, so seeing this means some other
	// limit was reached.
	ErrResourceExhausted = errors.New("resource exhausted")

	// ErrUnavailable means the request is worth retrying later.
	ErrUnavailable = errors.New("temporal cloud unavailable")
)

// MapGRPCError converts a gRPC status into one of this package's sentinel
// errors, wrapping it so the original message from Temporal Cloud survives.
// Non-gRPC errors pass through unchanged rather than being forced into a
// category they may not belong to.
func MapGRPCError(err error) error {
	if err == nil {
		return nil
	}

	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	var category error
	switch st.Code() {
	case codes.NotFound:
		category = ErrNotFound
	case codes.PermissionDenied, codes.Unauthenticated:
		category = ErrPermissionDenied
	case codes.InvalidArgument, codes.FailedPrecondition, codes.AlreadyExists:
		category = ErrInvalidArgument
	case codes.ResourceExhausted:
		category = ErrResourceExhausted
	case codes.Unavailable, codes.DeadlineExceeded, codes.Aborted, codes.Internal:
		category = ErrUnavailable
	default:
		return err
	}

	return fmt.Errorf("%w: %s", category, st.Message())
}
```

- [ ] **Step 7: Write `backend.go`**

```go
// Package temporalcloud implements a HashiCorp Vault secrets engine for
// Temporal Cloud. It provisions Temporal Cloud service accounts and issues
// short-lived API keys as Vault dynamic secrets, deleting each key when its
// Vault lease ends.
package temporalcloud

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/temporal-sa/vault-plugin-temporalcloud/client"
)

// configStoragePath is the storage key holding the engine's configuration.
const configStoragePath = "config"

// backend is the Temporal Cloud secrets engine.
type backend struct {
	*framework.Backend

	// clientMu guards the cached Cloud Ops client. The client owns a gRPC
	// connection, so we build it once and reuse it across requests rather
	// than dialling per request.
	clientMu sync.RWMutex
	client   client.CloudOps
}

// Factory is the entrypoint Vault calls to instantiate this plugin.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend constructs the engine without wiring it to Vault, so tests can
// drive it directly.
func Backend() *backend {
	var b backend

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			// The root API key lives here, so it must be seal-wrapped.
			SealWrapStorage: []string{configStoragePath},
		},
		// Paths and Secrets are appended by later tasks.
		Paths:      []*framework.Path{},
		Secrets:    []*framework.Secret{},
		Invalidate: b.invalidate,
		Clean:      b.clean,
	}

	return &b
}

// invalidate drops the cached client when config changes, so the next request
// rebuilds it with the new credential. Vault calls this on the active node and
// on replicas when storage under the given key changes.
func (b *backend) invalidate(_ context.Context, key string) {
	if key == configStoragePath {
		b.resetClient()
	}
}

// clean closes the gRPC connection when the mount is unmounted or sealed.
func (b *backend) clean(_ context.Context) {
	b.resetClient()
}

// resetClient closes and clears the cached client.
func (b *backend) resetClient() {
	b.clientMu.Lock()
	defer b.clientMu.Unlock()

	if b.client != nil {
		// Close errors are not actionable here: we are discarding the client
		// either way, and returning an error would block invalidation.
		_ = b.client.Close()
		b.client = nil
	}
}

const backendHelp = `
The Temporal Cloud secrets engine provisions Temporal Cloud service accounts and
issues short-lived Temporal Cloud API keys bound to Vault leases.

Configure the engine with a Global Admin service account API key at the "config"
path, define service accounts under "service-accounts/", then read credentials
from "creds/<name>".
`
```

- [ ] **Step 8: Write the plugin entrypoint**

`cmd/vault-plugin-secrets-temporalcloud/main.go`:

```go
// Command vault-plugin-secrets-temporalcloud serves the Temporal Cloud
// secrets engine as an external Vault plugin.
package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	temporalcloud "github.com/temporal-sa/vault-plugin-temporalcloud"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		logFatal(err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: temporalcloud.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		logFatal(err)
	}
}

func logFatal(err error) {
	hclog.New(&hclog.LoggerOptions{}).Error("plugin shutting down", "error", err)
	os.Exit(1)
}
```

Run `go mod tidy` — it will add `github.com/hashicorp/vault/api`.

- [ ] **Step 9: Write the Makefile**

```makefile
PLUGIN_NAME := vault-plugin-secrets-temporalcloud
PLUGIN_DIR  := ./bin
MOUNT       := temporalcloud

.PHONY: build test test-live sweep dev fmt lint clean

## build: compile the plugin and print the SHA256 Vault needs for registration
build:
	@mkdir -p $(PLUGIN_DIR)
	go build -o $(PLUGIN_DIR)/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)
	@echo "SHA256: $$(shasum -a 256 $(PLUGIN_DIR)/$(PLUGIN_NAME) | cut -d' ' -f1)"

## test: fast tests only — no credentials, no network
test:
	go test ./... -count=1

## test-live: tests against a real Temporal Cloud account
test-live:
	@test -n "$$TEMPORAL_CLOUD_API_KEY" || \
		(echo "TEMPORAL_CLOUD_API_KEY is not set. See README 'Running live tests'."; exit 1)
	@test -n "$$TEMPORAL_CLOUD_ADMIN_SA_ID" || \
		(echo "TEMPORAL_CLOUD_ADMIN_SA_ID is not set. See README 'Running live tests'."; exit 1)
	go test ./... -tags=acceptance -count=1 -v -timeout 20m

## sweep: delete leftover vault-acctest- resources from failed live tests
sweep:
	go run ./cmd/sweep

fmt:
	gofmt -w .

lint:
	golangci-lint run

clean:
	rm -rf $(PLUGIN_DIR)
```

The `dev` target is added in Task 9, once there is something to demo. `make sweep` will not run until Task 8 creates `cmd/sweep`; that is expected.

- [ ] **Step 10: Run the tests to verify they pass**

Run: `gofmt -w . && go mod tidy && go test ./... -v`
Expected: PASS — `TestBackend_Constructs` and all three `TestMapGRPCError*` tests.

- [ ] **Step 11: Verify the plugin binary builds**

Run: `make build`
Expected: a binary in `bin/` and a printed SHA256.

- [ ] **Step 12: Commit**

```bash
git add .
git commit -m "feat: scaffold plugin with the CloudOps interface and error mapping

Module, Makefile, plugin entrypoint, and a framework.Backend with no paths
registered yet. Also defines the seam between Vault logic and Temporal Cloud:
plain-Go request and response types, and sentinel errors that path handlers
switch on without importing grpc/codes."
```

---

### Task 2: Access parsing and validation

Converts the strings an operator writes into Temporal Cloud protos. Pure functions, no network — the densest validation logic in the engine and the cheapest to test.

**Files:**
- Create: `client/access.go`
- Test: `client/access_test.go`

**Interfaces:**
- Consumes: `ServiceAccountSpec` from Task 2.
- Produces: `func ParseAccountRole(string) (identityv1.AccountAccess_Role, error)`; `func ParseNamespacePermission(string) (identityv1.NamespaceAccess_Permission, error)`; `func (s ServiceAccountSpec) toProto() (*identityv1.ServiceAccountSpec, error)`; `func accountRoleFromProto(identityv1.AccountAccess_Role) string`; `func namespacePermissionFromProto(identityv1.NamespaceAccess_Permission) string`.

Import alias used throughout: `identityv1 "go.temporal.io/cloud-sdk/api/identity/v1"`.

- [ ] **Step 1: Write the failing test**

`client/access_test.go`:

```go
package client

import (
	"errors"
	"strings"
	"testing"

	identityv1 "go.temporal.io/cloud-sdk/api/identity/v1"
)

func TestParseAccountRole(t *testing.T) {
	tests := []struct {
		in      string
		want    identityv1.AccountAccess_Role
		wantErr bool
	}{
		{"owner", identityv1.AccountAccess_ROLE_OWNER, false},
		{"admin", identityv1.AccountAccess_ROLE_ADMIN, false},
		{"developer", identityv1.AccountAccess_ROLE_DEVELOPER, false},
		{"finance-admin", identityv1.AccountAccess_ROLE_FINANCE_ADMIN, false},
		{"read", identityv1.AccountAccess_ROLE_READ, false},
		{"metrics-read", identityv1.AccountAccess_ROLE_METRICS_READ, false},

		// Operators type inconsistently; accept case and surrounding space.
		{"Developer", identityv1.AccountAccess_ROLE_DEVELOPER, false},
		{"  developer  ", identityv1.AccountAccess_ROLE_DEVELOPER, false},

		{"", 0, true},
		{"superuser", 0, true},
		{"finance_admin", 0, true}, // underscore is not the documented spelling
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseAccountRole(tc.in)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got role %v", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

// The error must list the valid values, because an operator who typed the
// wrong one needs to know the right ones without opening the docs.
func TestParseAccountRole_ErrorListsValidValues(t *testing.T) {
	_, err := ParseAccountRole("superuser")

	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"owner", "admin", "developer", "finance-admin", "read", "metrics-read"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected error to mention %q, got: %v", want, err)
		}
	}
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestParseNamespacePermission(t *testing.T) {
	tests := []struct {
		in      string
		want    identityv1.NamespaceAccess_Permission
		wantErr bool
	}{
		{"admin", identityv1.NamespaceAccess_PERMISSION_ADMIN, false},
		{"write", identityv1.NamespaceAccess_PERMISSION_WRITE, false},
		{"read", identityv1.NamespaceAccess_PERMISSION_READ, false},
		{"Write", identityv1.NamespaceAccess_PERMISSION_WRITE, false},
		{"", 0, true},
		{"owner", 0, true}, // an account role, not a namespace permission
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseNamespacePermission(tc.in)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestServiceAccountSpec_ToProto(t *testing.T) {
	spec := ServiceAccountSpec{
		Name:        "prod-workers",
		Description: "managed by vault",
		AccountRole: "developer",
		NamespaceAccess: map[string]string{
			"prod.acct1":    "write",
			"staging.acct1": "read",
		},
	}

	got, err := spec.toProto()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.GetName() != "prod-workers" {
		t.Errorf("expected name prod-workers, got %q", got.GetName())
	}
	if got.GetDescription() != "managed by vault" {
		t.Errorf("expected description to carry through, got %q", got.GetDescription())
	}
	if role := got.GetAccess().GetAccountAccess().GetRole(); role != identityv1.AccountAccess_ROLE_DEVELOPER {
		t.Errorf("expected ROLE_DEVELOPER, got %v", role)
	}

	accesses := got.GetAccess().GetNamespaceAccesses()
	if len(accesses) != 2 {
		t.Fatalf("expected 2 namespace accesses, got %d", len(accesses))
	}
	if p := accesses["prod.acct1"].GetPermission(); p != identityv1.NamespaceAccess_PERMISSION_WRITE {
		t.Errorf("expected PERMISSION_WRITE for prod.acct1, got %v", p)
	}
	if p := accesses["staging.acct1"].GetPermission(); p != identityv1.NamespaceAccess_PERMISSION_READ {
		t.Errorf("expected PERMISSION_READ for staging.acct1, got %v", p)
	}
}

// A service account with no namespace access is valid — account-level role only.
func TestServiceAccountSpec_ToProto_NoNamespaceAccess(t *testing.T) {
	spec := ServiceAccountSpec{Name: "readonly", AccountRole: "read"}

	got, err := spec.toProto()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.GetAccess().GetNamespaceAccesses()) != 0 {
		t.Errorf("expected no namespace accesses, got %d", len(got.GetAccess().GetNamespaceAccesses()))
	}
}

func TestServiceAccountSpec_ToProto_Invalid(t *testing.T) {
	tests := []struct {
		name string
		spec ServiceAccountSpec
	}{
		{"empty name", ServiceAccountSpec{AccountRole: "read"}},
		{"bad account role", ServiceAccountSpec{Name: "x", AccountRole: "wizard"}},
		{
			"bad namespace permission",
			ServiceAccountSpec{Name: "x", AccountRole: "read", NamespaceAccess: map[string]string{"ns.acct": "sudo"}},
		},
		{
			"empty namespace name",
			ServiceAccountSpec{Name: "x", AccountRole: "read", NamespaceAccess: map[string]string{"": "read"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.spec.toProto(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// Round-tripping matters: service-accounts/<name> reads render the stored
// proto back as the strings the operator originally wrote.
func TestRoleAndPermissionRoundTrip(t *testing.T) {
	for _, role := range []string{"owner", "admin", "developer", "finance-admin", "read", "metrics-read"} {
		parsed, err := ParseAccountRole(role)
		if err != nil {
			t.Fatalf("parsing %q: %v", role, err)
		}
		if got := accountRoleFromProto(parsed); got != role {
			t.Errorf("round trip of %q produced %q", role, got)
		}
	}

	for _, perm := range []string{"admin", "write", "read"} {
		parsed, err := ParseNamespacePermission(perm)
		if err != nil {
			t.Fatalf("parsing %q: %v", perm, err)
		}
		if got := namespacePermissionFromProto(parsed); got != perm {
			t.Errorf("round trip of %q produced %q", perm, got)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./client/... -run 'TestParseAccountRole|TestParseNamespacePermission|TestServiceAccountSpec|TestRoleAndPermission' -v`
Expected: FAIL — `undefined: ParseAccountRole`.

- [ ] **Step 3: Write `client/access.go`**

```go
package client

import (
	"fmt"
	"sort"
	"strings"

	identityv1 "go.temporal.io/cloud-sdk/api/identity/v1"
)

// accountRoles maps the role names an operator writes to their proto values.
// The spellings match the Temporal Cloud CLI so operators can move between
// tcld and Vault without relearning them.
var accountRoles = map[string]identityv1.AccountAccess_Role{
	"owner":         identityv1.AccountAccess_ROLE_OWNER,
	"admin":         identityv1.AccountAccess_ROLE_ADMIN,
	"developer":     identityv1.AccountAccess_ROLE_DEVELOPER,
	"finance-admin": identityv1.AccountAccess_ROLE_FINANCE_ADMIN,
	"read":          identityv1.AccountAccess_ROLE_READ,
	"metrics-read":  identityv1.AccountAccess_ROLE_METRICS_READ,
}

// namespacePermissions maps namespace permission names to their proto values.
var namespacePermissions = map[string]identityv1.NamespaceAccess_Permission{
	"admin": identityv1.NamespaceAccess_PERMISSION_ADMIN,
	"write": identityv1.NamespaceAccess_PERMISSION_WRITE,
	"read":  identityv1.NamespaceAccess_PERMISSION_READ,
}

// ParseAccountRole converts an operator-supplied account role to its proto
// value. Input is trimmed and lowercased, because operators copy values out of
// docs and UIs with inconsistent casing.
func ParseAccountRole(s string) (identityv1.AccountAccess_Role, error) {
	role, ok := accountRoles[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		return 0, fmt.Errorf("%w: unknown account_role %q, must be one of: %s",
			ErrInvalidArgument, s, sortedKeys(accountRoles))
	}
	return role, nil
}

// ParseNamespacePermission converts an operator-supplied namespace permission
// to its proto value.
func ParseNamespacePermission(s string) (identityv1.NamespaceAccess_Permission, error) {
	perm, ok := namespacePermissions[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		return 0, fmt.Errorf("%w: unknown namespace permission %q, must be one of: %s",
			ErrInvalidArgument, s, sortedKeys(namespacePermissions))
	}
	return perm, nil
}

// accountRoleFromProto renders a role back as the string an operator wrote, so
// reads of service-accounts/<name> echo the input rather than proto constants.
func accountRoleFromProto(role identityv1.AccountAccess_Role) string {
	for name, v := range accountRoles {
		if v == role {
			return name
		}
	}
	return ""
}

// namespacePermissionFromProto is the inverse of ParseNamespacePermission.
func namespacePermissionFromProto(perm identityv1.NamespaceAccess_Permission) string {
	for name, v := range namespacePermissions {
		if v == perm {
			return name
		}
	}
	return ""
}

// toProto converts a spec into the Temporal Cloud representation, validating
// every field. Validation lives here rather than in the Vault path handler so
// there is exactly one place that decides what a valid spec is.
func (s ServiceAccountSpec) toProto() (*identityv1.ServiceAccountSpec, error) {
	if strings.TrimSpace(s.Name) == "" {
		return nil, fmt.Errorf("%w: service account name must not be empty", ErrInvalidArgument)
	}

	role, err := ParseAccountRole(s.AccountRole)
	if err != nil {
		return nil, err
	}

	access := &identityv1.Access{
		AccountAccess: &identityv1.AccountAccess{Role: role},
	}

	if len(s.NamespaceAccess) > 0 {
		access.NamespaceAccesses = make(map[string]*identityv1.NamespaceAccess, len(s.NamespaceAccess))

		for namespace, permission := range s.NamespaceAccess {
			if strings.TrimSpace(namespace) == "" {
				return nil, fmt.Errorf("%w: namespace name must not be empty", ErrInvalidArgument)
			}

			perm, err := ParseNamespacePermission(permission)
			if err != nil {
				return nil, fmt.Errorf("namespace %q: %w", namespace, err)
			}

			access.NamespaceAccesses[namespace] = &identityv1.NamespaceAccess{Permission: perm}
		}
	}

	return &identityv1.ServiceAccountSpec{
		Name:        s.Name,
		Description: s.Description,
		Access:      access,
	}, nil
}

// sortedKeys renders map keys in a stable order so error messages do not
// shuffle between runs.
func sortedKeys[V any](m map[string]V) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `gofmt -w . && go test ./client/... -v`
Expected: PASS — all access tests.

- [ ] **Step 5: Commit**

```bash
git add .
git commit -m "feat(client): parse and validate account roles and namespace access

Converts the strings operators write into Temporal Cloud protos, with errors
that list the valid values, and round-trips them back for reads."
```

---

### Task 3: Async operation polling and the gRPC client

Implements `CloudOps` for real. This is the only file that touches gRPC.

**Files:**
- Create: `client/async.go`, `client/grpc.go`
- Modify: `backend.go` — add the `newClient` field and assign it
- Test: `client/async_test.go`

**Interfaces:**
- Consumes: everything from Tasks 2 and 3.
- Produces: `func NewGRPC(cfg Config) (CloudOps, error)` (`Config` already exists from Task 1); `type grpcClient struct` implementing `CloudOps`; `func awaitOperation(ctx context.Context, svc cloudservicev1.CloudServiceClient, op *operationv1.AsyncOperation) error`; `func classifyOperationState(*operationv1.AsyncOperation) (bool, error)`; and on `backend`, the new field `newClient func(client.Config) (client.CloudOps, error)`.

Import aliases: `cloudservicev1 "go.temporal.io/cloud-sdk/api/cloudservice/v1"`, `operationv1 "go.temporal.io/cloud-sdk/api/operation/v1"`, `"go.temporal.io/cloud-sdk/cloudclient"`.

- [ ] **Step 1: Write the failing test for terminal-state classification**

Polling needs a live server, but the state classification does not, and that is where the bugs are. `client/async_test.go`:

```go
package client

import (
	"errors"
	"testing"

	operationv1 "go.temporal.io/cloud-sdk/api/operation/v1"
)

func TestClassifyOperationState(t *testing.T) {
	tests := []struct {
		name       string
		state      operationv1.AsyncOperation_State
		wantDone   bool
		wantErrIs  error
	}{
		{"fulfilled is success", operationv1.AsyncOperation_STATE_FULFILLED, true, nil},
		{"pending keeps polling", operationv1.AsyncOperation_STATE_PENDING, false, nil},
		{"in progress keeps polling", operationv1.AsyncOperation_STATE_IN_PROGRESS, false, nil},
		{"unspecified keeps polling", operationv1.AsyncOperation_STATE_UNSPECIFIED, false, nil},
		{"failed is terminal error", operationv1.AsyncOperation_STATE_FAILED, true, ErrInvalidArgument},
		{"cancelled is terminal error", operationv1.AsyncOperation_STATE_CANCELLED, true, ErrInvalidArgument},
		{"rejected is terminal error", operationv1.AsyncOperation_STATE_REJECTED, true, ErrInvalidArgument},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			op := &operationv1.AsyncOperation{
				State:         tc.state,
				FailureReason: "because reasons",
			}

			done, err := classifyOperationState(op)

			if done != tc.wantDone {
				t.Fatalf("expected done=%v, got %v", tc.wantDone, done)
			}
			if tc.wantErrIs == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErrIs) {
				t.Fatalf("expected errors.Is(_, %v), got %v", tc.wantErrIs, err)
			}
		})
	}
}

// The operator needs Temporal Cloud's reason, not just "the operation failed".
func TestClassifyOperationState_IncludesFailureReason(t *testing.T) {
	op := &operationv1.AsyncOperation{
		State:         operationv1.AsyncOperation_STATE_FAILED,
		FailureReason: "namespace prod.acct1 does not exist",
	}

	_, err := classifyOperationState(op)

	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "namespace prod.acct1 does not exist") {
		t.Fatalf("expected the failure reason in the error, got: %v", err)
	}
}

// A nil operation means the server did not report one. Treat it as complete
// rather than polling forever against a nil pointer.
func TestClassifyOperationState_NilOperation(t *testing.T) {
	done, err := classifyOperationState(nil)

	if !done {
		t.Fatal("expected a nil operation to be treated as done")
	}
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
```

Add `"strings"` to the imports.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./client/... -run TestClassifyOperationState -v`
Expected: FAIL — `undefined: classifyOperationState`.

- [ ] **Step 3: Write `client/async.go`**

```go
package client

import (
	"context"
	"fmt"
	"time"

	cloudservicev1 "go.temporal.io/cloud-sdk/api/cloudservice/v1"
	operationv1 "go.temporal.io/cloud-sdk/api/operation/v1"
)

const (
	// operationPollInterval is how often we ask Temporal Cloud whether an
	// operation has finished.
	operationPollInterval = time.Second

	// operationTimeout bounds the wait. It sits below Vault's 90s default
	// request timeout on purpose: we want to fail with this engine's error
	// message rather than have Vault time out the request underneath us.
	operationTimeout = 60 * time.Second
)

// awaitOperation blocks until the given Cloud Ops operation reaches a terminal
// state. Every mutating Cloud Ops call is asynchronous, so this is what lets
// the CloudOps methods present a simple blocking interface.
func awaitOperation(
	ctx context.Context,
	svc cloudservicev1.CloudServiceClient,
	op *operationv1.AsyncOperation,
) error {
	done, err := classifyOperationState(op)
	if err != nil {
		return err
	}
	if done {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()

	ticker := time.NewTicker(operationPollInterval)
	defer ticker.Stop()

	operationID := op.GetId()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: timed out after %s waiting for operation %s",
				ErrUnavailable, operationTimeout, operationID)

		case <-ticker.C:
			resp, err := svc.GetAsyncOperation(ctx, &cloudservicev1.GetAsyncOperationRequest{
				AsyncOperationId: operationID,
			})
			if err != nil {
				return MapGRPCError(err)
			}

			done, err := classifyOperationState(resp.GetAsyncOperation())
			if err != nil {
				return err
			}
			if done {
				return nil
			}
		}
	}
}

// classifyOperationState reports whether an operation has reached a terminal
// state, and returns an error if that state is a failure.
//
// Note the success state is FULFILLED. There is no SUCCEEDED state, despite
// what the name of every other async API might suggest.
func classifyOperationState(op *operationv1.AsyncOperation) (done bool, err error) {
	// No operation reported means there is nothing to wait for.
	if op == nil {
		return true, nil
	}

	switch op.GetState() {
	case operationv1.AsyncOperation_STATE_FULFILLED:
		return true, nil

	case operationv1.AsyncOperation_STATE_FAILED,
		operationv1.AsyncOperation_STATE_CANCELLED,
		operationv1.AsyncOperation_STATE_REJECTED:
		// These are the operator's problem to fix, not transient, so they map
		// to a user error rather than a retryable one.
		return true, fmt.Errorf("%w: temporal cloud operation %s: %s",
			ErrInvalidArgument, op.GetState(), op.GetFailureReason())

	default:
		// PENDING, IN_PROGRESS, UNSPECIFIED — keep waiting.
		return false, nil
	}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./client/... -run TestClassifyOperationState -v`
Expected: PASS.

- [ ] **Step 5: Write `client/grpc.go`**

```go
package client

import (
	"context"
	"fmt"

	cloudservicev1 "go.temporal.io/cloud-sdk/api/cloudservice/v1"
	identityv1 "go.temporal.io/cloud-sdk/api/identity/v1"
	"go.temporal.io/cloud-sdk/cloudclient"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Config already exists in client.go from Task 1 — do not redeclare it here.

// grpcClient implements CloudOps against the real Cloud Ops API.
type grpcClient struct {
	conn *cloudclient.Client
	svc  cloudservicev1.CloudServiceClient
}

// NewGRPC builds a CloudOps backed by Temporal Cloud.
//
// The SDK's default interceptors already assign an async_operation_id to every
// write and retry retryable failures with exponential backoff, so this engine
// deliberately adds neither. Setting DisableRetry would remove both.
func NewGRPC(cfg Config) (CloudOps, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("%w: api_key must not be empty", ErrInvalidArgument)
	}

	conn, err := cloudclient.New(cloudclient.Options{
		APIKey:   cfg.APIKey,
		HostPort: cfg.HostPort,
	})
	if err != nil {
		return nil, fmt.Errorf("connecting to temporal cloud: %w", err)
	}

	return &grpcClient{conn: conn, svc: conn.CloudService()}, nil
}

func (c *grpcClient) Close() error {
	return c.conn.Close()
}

func (c *grpcClient) CreateServiceAccount(ctx context.Context, spec ServiceAccountSpec) (string, error) {
	protoSpec, err := spec.toProto()
	if err != nil {
		return "", err
	}

	resp, err := c.svc.CreateServiceAccount(ctx, &cloudservicev1.CreateServiceAccountRequest{
		Spec: protoSpec,
	})
	if err != nil {
		return "", MapGRPCError(err)
	}

	if err := awaitOperation(ctx, c.svc, resp.GetAsyncOperation()); err != nil {
		// The ID is returned before the operation completes, so surface it:
		// the caller may need it to clean up a half-created account.
		return resp.GetServiceAccountId(), err
	}

	return resp.GetServiceAccountId(), nil
}

func (c *grpcClient) GetServiceAccount(ctx context.Context, id string) (*ServiceAccount, error) {
	resp, err := c.svc.GetServiceAccount(ctx, &cloudservicev1.GetServiceAccountRequest{
		ServiceAccountId: id,
	})
	if err != nil {
		return nil, MapGRPCError(err)
	}

	sa := resp.GetServiceAccount()
	if sa == nil {
		return nil, fmt.Errorf("%w: service account %s", ErrNotFound, id)
	}

	return &ServiceAccount{
		ID:              sa.GetId(),
		ResourceVersion: sa.GetResourceVersion(),
		Spec:            specFromProto(sa.GetSpec()),
	}, nil
}

func (c *grpcClient) UpdateServiceAccount(ctx context.Context, id string, spec ServiceAccountSpec) error {
	protoSpec, err := spec.toProto()
	if err != nil {
		return err
	}

	// Temporal Cloud uses optimistic concurrency: the update must name the
	// version it is replacing. Fetching it here keeps resource versions out
	// of the CloudOps interface entirely.
	current, err := c.GetServiceAccount(ctx, id)
	if err != nil {
		return err
	}

	resp, err := c.svc.UpdateServiceAccount(ctx, &cloudservicev1.UpdateServiceAccountRequest{
		ServiceAccountId: id,
		Spec:             protoSpec,
		ResourceVersion:  current.ResourceVersion,
	})
	if err != nil {
		return MapGRPCError(err)
	}

	return awaitOperation(ctx, c.svc, resp.GetAsyncOperation())
}

func (c *grpcClient) DeleteServiceAccount(ctx context.Context, id string) error {
	current, err := c.GetServiceAccount(ctx, id)
	if err != nil {
		return err
	}

	resp, err := c.svc.DeleteServiceAccount(ctx, &cloudservicev1.DeleteServiceAccountRequest{
		ServiceAccountId: id,
		ResourceVersion:  current.ResourceVersion,
	})
	if err != nil {
		return MapGRPCError(err)
	}

	return awaitOperation(ctx, c.svc, resp.GetAsyncOperation())
}

func (c *grpcClient) CreateAPIKey(ctx context.Context, spec APIKeySpec) (*APIKey, error) {
	if spec.ExpiryTime.IsZero() {
		return nil, fmt.Errorf("%w: api key expiry time is required", ErrInvalidArgument)
	}

	resp, err := c.svc.CreateApiKey(ctx, &cloudservicev1.CreateApiKeyRequest{
		Spec: &identityv1.ApiKeySpec{
			OwnerId:     spec.ServiceAccountID,
			OwnerType:   identityv1.OwnerType_OWNER_TYPE_SERVICE_ACCOUNT,
			DisplayName: spec.DisplayName,
			Description: spec.Description,
			ExpiryTime:  timestamppb.New(spec.ExpiryTime),
		},
	})
	if err != nil {
		return nil, MapGRPCError(err)
	}

	if err := awaitOperation(ctx, c.svc, resp.GetAsyncOperation()); err != nil {
		return nil, err
	}

	// The token is on the create response and is never retrievable again.
	return &APIKey{ID: resp.GetKeyId(), Token: resp.GetToken()}, nil
}

func (c *grpcClient) DeleteAPIKey(ctx context.Context, id string) error {
	resp, err := c.svc.DeleteApiKey(ctx, &cloudservicev1.DeleteApiKeyRequest{
		KeyId: id,
	})
	if err != nil {
		return MapGRPCError(err)
	}

	return awaitOperation(ctx, c.svc, resp.GetAsyncOperation())
}

func (c *grpcClient) CountAPIKeys(ctx context.Context, serviceAccountID string) (int, error) {
	count := 0
	pageToken := ""

	// The cap applies to non-expired keys, and the API pages, so count every
	// page rather than trusting the first one.
	for {
		resp, err := c.svc.GetApiKeys(ctx, &cloudservicev1.GetApiKeysRequest{
			OwnerId:   serviceAccountID,
			OwnerType: identityv1.OwnerType_OWNER_TYPE_SERVICE_ACCOUNT,
			PageSize:  100,
			PageToken: pageToken,
		})
		if err != nil {
			return 0, MapGRPCError(err)
		}

		count += len(resp.GetApiKeys())

		pageToken = resp.GetNextPageToken()
		if pageToken == "" {
			return count, nil
		}
	}
}

// specFromProto renders a Temporal Cloud service account spec back into the
// plain strings an operator wrote.
func specFromProto(p *identityv1.ServiceAccountSpec) ServiceAccountSpec {
	spec := ServiceAccountSpec{
		Name:        p.GetName(),
		Description: p.GetDescription(),
		AccountRole: accountRoleFromProto(p.GetAccess().GetAccountAccess().GetRole()),
	}

	accesses := p.GetAccess().GetNamespaceAccesses()
	if len(accesses) > 0 {
		spec.NamespaceAccess = make(map[string]string, len(accesses))
		for namespace, access := range accesses {
			spec.NamespaceAccess[namespace] = namespacePermissionFromProto(access.GetPermission())
		}
	}

	return spec
}
```

The `OwnerType` constant identifier is `identityv1.OwnerType_OWNER_TYPE_SERVICE_ACCOUNT` — verified against v0.16.0's generated code, note the `OwnerType_` prefix on an already-prefixed name.

- [ ] **Step 6: Add the client constructor field to `backend.go`**

Add the field to the `backend` struct, after `client`:

```go
	// newClient builds a Cloud Ops client. It is a field rather than a direct
	// call to client.NewGRPC so tests can substitute a stub without dialling
	// Temporal Cloud.
	newClient func(cfg client.Config) (client.CloudOps, error)
```

And assign it in `Backend()`, before the `b.Backend = ...` block:

```go
	b.newClient = client.NewGRPC
```

The signatures match exactly, so no adapter closure is needed. Task 4 converts the stored `config` into a `client.Config` at the call site.

- [ ] **Step 7: Verify everything builds and the fast tests pass**

Run: `gofmt -w . && go mod tidy && go build ./... && go test ./... -v`
Expected: build succeeds; all tests PASS.

- [ ] **Step 8: Commit**

```bash
git add .
git commit -m "feat(client): implement CloudOps over the Cloud Ops gRPC API

Adds async operation polling (terminal success state is FULFILLED, not
SUCCEEDED) and the gRPC implementation of every CloudOps method. Retries and
idempotency keys come from the SDK's default interceptors."
```

---

### Task 4: The `config` path

Stores the root credential and validates it against Temporal Cloud on write.

**Files:**
- Create: `path_config.go`
- Modify: `backend.go` — register the path, add `getClient`
- Test: `path_config_test.go`

**Interfaces:**
- Consumes: `client.CloudOps`, `client.Config`, `client.NewGRPC`, `client.ErrNotFound`.
- Produces: `type config struct{ APIKey, APIKeyID, AdminServiceAccountID, Address string; RootKeyTTL time.Duration }`; `const configStoragePath = "config"`; `func (b *backend) pathConfig() *framework.Path`; `func (b *backend) getConfig(ctx, logical.Storage) (*config, error)`; `func (b *backend) getClient(ctx, logical.Storage) (client.CloudOps, error)`.

- [ ] **Step 1: Write the failing test**

`path_config_test.go`. It uses a stub `CloudOps` — this is a test double for *our own interface*, not a fake Temporal Cloud server, so it stays cheap and credential-free.

```go
package temporalcloud

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/temporal-sa/vault-plugin-temporalcloud/client"
)

// stubCloudOps records calls and returns canned responses. Later tasks extend
// it; keep the zero value usable so tests only set what they care about.
type stubCloudOps struct {
	getServiceAccountFn func(ctx context.Context, id string) (*client.ServiceAccount, error)
	createAPIKeyFn      func(ctx context.Context, spec client.APIKeySpec) (*client.APIKey, error)
	deleteAPIKeyFn      func(ctx context.Context, id string) error
	countAPIKeysFn      func(ctx context.Context, saID string) (int, error)

	deletedAPIKeys []string
	closed         bool
}

func (s *stubCloudOps) CreateServiceAccount(context.Context, client.ServiceAccountSpec) (string, error) {
	return "", errors.New("not implemented in this stub")
}

func (s *stubCloudOps) GetServiceAccount(ctx context.Context, id string) (*client.ServiceAccount, error) {
	if s.getServiceAccountFn != nil {
		return s.getServiceAccountFn(ctx, id)
	}
	return &client.ServiceAccount{ID: id}, nil
}

func (s *stubCloudOps) UpdateServiceAccount(context.Context, string, client.ServiceAccountSpec) error {
	return errors.New("not implemented in this stub")
}

func (s *stubCloudOps) DeleteServiceAccount(context.Context, string) error {
	return errors.New("not implemented in this stub")
}

func (s *stubCloudOps) CreateAPIKey(ctx context.Context, spec client.APIKeySpec) (*client.APIKey, error) {
	if s.createAPIKeyFn != nil {
		return s.createAPIKeyFn(ctx, spec)
	}
	return &client.APIKey{ID: "key-stub", Token: "tmprl_sk_stub"}, nil
}

func (s *stubCloudOps) DeleteAPIKey(ctx context.Context, id string) error {
	s.deletedAPIKeys = append(s.deletedAPIKeys, id)
	if s.deleteAPIKeyFn != nil {
		return s.deleteAPIKeyFn(ctx, id)
	}
	return nil
}

func (s *stubCloudOps) CountAPIKeys(ctx context.Context, saID string) (int, error) {
	if s.countAPIKeysFn != nil {
		return s.countAPIKeysFn(ctx, saID)
	}
	return 0, nil
}

func (s *stubCloudOps) Close() error {
	s.closed = true
	return nil
}

// withStubClient makes the backend use the given stub instead of dialling
// Temporal Cloud.
func withStubClient(b *backend, stub client.CloudOps) {
	b.newClient = func(client.Config) (client.CloudOps, error) { return stub, nil }
}

func TestConfig_WriteAndRead(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  "tmprl_sk_test",
			"admin_service_account_id": "sa-123",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write config: err=%v resp=%v", err, resp)
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read config: err=%v resp=%v", err, resp)
	}

	if got := resp.Data["admin_service_account_id"]; got != "sa-123" {
		t.Errorf("expected sa-123, got %v", got)
	}
	// Defaults must be applied and visible.
	if got := resp.Data["address"]; got != "saas-api.tmprl.cloud:443" {
		t.Errorf("expected the default address, got %v", got)
	}
	if got := resp.Data["root_key_ttl"]; got != int64((2160 * time.Hour).Seconds()) {
		t.Errorf("expected the default root_key_ttl, got %v", got)
	}
}

// The root API key must never be readable back out of Vault.
func TestConfig_ReadNeverReturnsAPIKey(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})

	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	if _, present := resp.Data["api_key"]; present {
		t.Fatal("api_key must never be returned from a config read")
	}
}

// Writing config validates the credential by calling GetServiceAccount. A
// credential that does not work must be rejected at write time, not at first
// use, so the operator finds out immediately.
func TestConfig_WriteRejectsBadCredential(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{
		getServiceAccountFn: func(context.Context, string) (*client.ServiceAccount, error) {
			return nil, client.ErrPermissionDenied
		},
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  "tmprl_sk_bad",
			"admin_service_account_id": "sa-123",
		},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected writing an invalid credential to fail")
	}

	// Nothing may be persisted when validation fails.
	entry, err := storage.Get(context.Background(), configStoragePath)
	if err != nil {
		t.Fatalf("storage get: %v", err)
	}
	if entry != nil {
		t.Fatal("config must not be persisted when validation fails")
	}
}

func TestConfig_RequiredFields(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
	}{
		{"missing api_key", map[string]interface{}{"admin_service_account_id": "sa-1"}},
		{"missing admin_service_account_id", map[string]interface{}{"api_key": "tmprl_sk_x"}},
		{"empty api_key", map[string]interface{}{"api_key": "", "admin_service_account_id": "sa-1"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := newTestBackend(t)
			withStubClient(b, &stubCloudOps{})

			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "config",
				Storage:   storage,
				Data:      tc.data,
			})
			if err == nil && (resp == nil || !resp.IsError()) {
				t.Fatal("expected an error")
			}
		})
	}
}

// root_key_ttl beyond Temporal Cloud's two-year maximum must be rejected here
// rather than by Temporal Cloud at rotation time.
func TestConfig_RejectsRootKeyTTLOverTwoYears(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  "tmprl_sk_test",
			"admin_service_account_id": "sa-123",
			"root_key_ttl":             "20000h", // well over 2 years
		},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected root_key_ttl over two years to be rejected")
	}
}

func TestConfig_Delete(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})
	mustWriteConfig(t, b, storage)

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   storage,
	}); err != nil {
		t.Fatalf("delete config: %v", err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("read after delete: %v", err)
	}
	if resp != nil && len(resp.Data) > 0 {
		t.Fatal("expected no config after delete")
	}
}

// mustWriteConfig writes a valid config, failing the test if it does not take.
func mustWriteConfig(t *testing.T, b *backend, storage logical.Storage) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  "tmprl_sk_test",
			"api_key_id":               "key-bootstrap",
			"admin_service_account_id": "sa-123",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write config: err=%v resp=%v", err, resp)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test . -run TestConfig -v`
Expected: FAIL — `undefined: withStubClient` / compile errors from the missing path.

- [ ] **Step 3: Write `path_config.go`**

```go
package temporalcloud

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/temporal-sa/vault-plugin-temporalcloud/client"
)

const (
	// configStoragePath is the storage key holding the engine's configuration.
	configStoragePath = "config"

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
```

- [ ] **Step 4: Add `getClient` and register the path in `backend.go`**

Register the path:

```go
		Paths: []*framework.Path{
			b.pathConfig(),
		},
```

And add the cached-client accessor:

```go
// getClient returns the cached Cloud Ops client, building it from stored
// config on first use. The gRPC connection is expensive to establish, so it is
// shared across requests and rebuilt only when config changes.
func (b *backend) getClient(ctx context.Context, s logical.Storage) (client.CloudOps, error) {
	b.clientMu.RLock()
	if b.client != nil {
		defer b.clientMu.RUnlock()
		return b.client, nil
	}
	b.clientMu.RUnlock()

	b.clientMu.Lock()
	defer b.clientMu.Unlock()

	// Another goroutine may have built it while we waited for the write lock.
	if b.client != nil {
		return b.client, nil
	}

	cfg, err := b.getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errBackendNotConfigured
	}

	c, err := b.newClient(cfg.clientConfig())
	if err != nil {
		return nil, err
	}

	b.client = c
	return c, nil
}

// errBackendNotConfigured is returned when a path needs Temporal Cloud but the
// config path has not been written.
var errBackendNotConfigured = errors.New(
	"the Temporal Cloud secrets engine is not configured; write the config path first")
```

Add `"errors"` to `backend.go`'s imports.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `gofmt -w . && go test . -run TestConfig -v`
Expected: PASS — all `TestConfig*` tests.

- [ ] **Step 6: Run the whole fast suite**

Run: `go test ./... -count=1`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add .
git commit -m "feat: add the config path

Stores the root credential and validates it against Temporal Cloud before
persisting, so a bad key or wrong admin_service_account_id fails at write time.
Reads never return api_key."
```

---

### Task 5: `config/rotate-root`

Replaces the root credential with one only Vault has seen.

**Files:**
- Create: `path_rotate_root.go`
- Modify: `backend.go` — register the path
- Test: `path_rotate_root_test.go`

**Interfaces:**
- Consumes: `config`, `b.getConfig`, `b.getClient`, `client.APIKeySpec`, `client.MaxAPIKeyExpiry`.
- Produces: `func (b *backend) pathRotateRoot() *framework.Path`.

- [ ] **Step 1: Write the failing test**

`path_rotate_root_test.go`:

```go
package temporalcloud

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/temporal-sa/vault-plugin-temporalcloud/client"
)

func TestRotateRoot_ReplacesCredential(t *testing.T) {
	b, storage := newTestBackend(t)

	stub := &stubCloudOps{
		createAPIKeyFn: func(_ context.Context, spec client.APIKeySpec) (*client.APIKey, error) {
			if spec.ServiceAccountID != "sa-123" {
				t.Errorf("expected the key to be minted on sa-123, got %q", spec.ServiceAccountID)
			}
			if spec.ExpiryTime.IsZero() {
				t.Error("expected a non-zero expiry")
			}
			return &client.APIKey{ID: "key-new", Token: "tmprl_sk_new"}, nil
		},
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage) // stores api_key_id "key-bootstrap"

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate-root: err=%v resp=%v", err, resp)
	}

	cfg, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	if cfg.APIKey != "tmprl_sk_new" {
		t.Errorf("expected the stored key to be the new one, got %q", cfg.APIKey)
	}
	if cfg.APIKeyID != "key-new" {
		t.Errorf("expected the stored key ID to be key-new, got %q", cfg.APIKeyID)
	}

	// The key it replaced must be deleted.
	if len(stub.deletedAPIKeys) != 1 || stub.deletedAPIKeys[0] != "key-bootstrap" {
		t.Errorf("expected key-bootstrap to be deleted, got %v", stub.deletedAPIKeys)
	}
}

// Without a known api_key_id there is nothing to delete. Rotation must still
// succeed, and must warn so the operator cleans up by hand.
func TestRotateRoot_WarnsWhenOldKeyIDUnknown(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	withStubClient(b, stub)

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  "tmprl_sk_bootstrap",
			"admin_service_account_id": "sa-123",
			// api_key_id deliberately omitted
		},
	}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate-root: err=%v resp=%v", err, resp)
	}

	if len(resp.Warnings) == 0 {
		t.Fatal("expected a warning that the previous key could not be deleted")
	}
	if !strings.Contains(strings.Join(resp.Warnings, " "), "manually") {
		t.Errorf("expected the warning to tell the operator to delete it manually, got %v", resp.Warnings)
	}
	if len(stub.deletedAPIKeys) != 0 {
		t.Errorf("expected no deletion attempt, got %v", stub.deletedAPIKeys)
	}
}

// If the new key does not work, the old configuration must survive untouched.
// Storing an unverified credential would brick the mount.
func TestRotateRoot_KeepsOldConfigWhenNewKeyFailsVerification(t *testing.T) {
	b, storage := newTestBackend(t)

	calls := 0
	stub := &stubCloudOps{
		getServiceAccountFn: func(context.Context, string) (*client.ServiceAccount, error) {
			calls++
			// First call is the config write's validation and must succeed.
			// The second is rotate-root verifying the new key; fail that.
			if calls > 1 {
				return nil, client.ErrPermissionDenied
			}
			return &client.ServiceAccount{ID: "sa-123"}, nil
		},
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected rotation to fail when the new key does not verify")
	}

	cfg, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	if cfg.APIKey != "tmprl_sk_test" {
		t.Errorf("expected the original key to survive, got %q", cfg.APIKey)
	}
	if cfg.APIKeyID != "key-bootstrap" {
		t.Errorf("expected the original key ID to survive, got %q", cfg.APIKeyID)
	}
}

func TestRotateRoot_FailsWhenUnconfigured(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected rotate-root to fail when the engine is not configured")
	}
}

// The new key's expiry must come from root_key_ttl.
func TestRotateRoot_UsesRootKeyTTL(t *testing.T) {
	b, storage := newTestBackend(t)

	var gotExpiry time.Time
	withStubClient(b, &stubCloudOps{
		createAPIKeyFn: func(_ context.Context, spec client.APIKeySpec) (*client.APIKey, error) {
			gotExpiry = spec.ExpiryTime
			return &client.APIKey{ID: "key-new", Token: "tmprl_sk_new"}, nil
		},
	})

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  "tmprl_sk_test",
			"admin_service_account_id": "sa-123",
			"root_key_ttl":             "720h", // 30 days
		},
	}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
	}); err != nil {
		t.Fatalf("rotate-root: %v", err)
	}

	want := time.Now().Add(720 * time.Hour)
	if delta := gotExpiry.Sub(want); delta > time.Minute || delta < -time.Minute {
		t.Errorf("expected an expiry near %v, got %v", want, gotExpiry)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test . -run TestRotateRoot -v`
Expected: FAIL — unsupported path `config/rotate-root`.

- [ ] **Step 3: Write `path_rotate_root.go`**

```go
package temporalcloud

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/temporal-sa/vault-plugin-temporalcloud/client"
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

	if err := c.DeleteAPIKey(ctx, cfg.APIKeyID); err != nil {
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
```

- [ ] **Step 4: Register the path in `backend.go`**

```go
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathRotateRoot(),
		},
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `gofmt -w . && go test . -run TestRotateRoot -v`
Expected: PASS — all five rotate-root tests.

- [ ] **Step 6: Run the whole fast suite**

Run: `go test ./... -count=1`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add .
git commit -m "feat: add config/rotate-root

Mints, verifies, stores, then deletes the previous root API key. Every
intermediate failure leaves a working credential in place; an unusable
replacement is cleaned up rather than left to consume a key slot."
```

---

### Task 6: The `service-accounts/<name>` path

Full CRUD against Temporal Cloud, plus the TTL fields `creds/` will consume.

**Files:**
- Create: `path_service_accounts.go`
- Modify: `backend.go` — register two paths
- Test: `path_service_accounts_test.go`

**Interfaces:**
- Consumes: `b.getClient`, `client.ServiceAccountSpec`, `client.CloudOps`.
- Produces: `type serviceAccountEntry struct{ ServiceAccountID, AccountRole, Description string; NamespaceAccess map[string]string; TTL, MaxTTL time.Duration }`; `func serviceAccountStoragePath(name string) string`; `func (b *backend) getServiceAccount(ctx, logical.Storage, string) (*serviceAccountEntry, error)`; `func (b *backend) pathServiceAccounts() *framework.Path`; `func (b *backend) pathServiceAccountsList() *framework.Path`; `func parseNamespaceAccess([]string) (map[string]string, error)`.

- [ ] **Step 1: Write the failing test for `parseNamespaceAccess`**

Operators write `namespace=permission` pairs. This parsing is pure and is where malformed input must be caught. Add to `path_service_accounts_test.go`:

```go
package temporalcloud

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/temporal-sa/vault-plugin-temporalcloud/client"
)

func TestParseNamespaceAccess(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    map[string]string
		wantErr string
	}{
		{
			name: "single pair",
			in:   []string{"prod.acct1=write"},
			want: map[string]string{"prod.acct1": "write"},
		},
		{
			name: "several pairs",
			in:   []string{"prod.acct1=write", "staging.acct1=read", "dev.acct1=admin"},
			want: map[string]string{"prod.acct1": "write", "staging.acct1": "read", "dev.acct1": "admin"},
		},
		{
			name: "surrounding whitespace is tolerated",
			in:   []string{"  prod.acct1 = write  "},
			want: map[string]string{"prod.acct1": "write"},
		},
		{
			name: "empty input yields no access",
			in:   nil,
			want: map[string]string{},
		},
		{
			name:    "missing equals sign",
			in:      []string{"prod.acct1"},
			wantErr: "namespace=permission",
		},
		{
			name:    "empty namespace",
			in:      []string{"=write"},
			wantErr: "namespace",
		},
		{
			name:    "empty permission",
			in:      []string{"prod.acct1="},
			wantErr: "permission",
		},
		{
			name:    "unknown permission",
			in:      []string{"prod.acct1=sudo"},
			wantErr: "sudo",
		},
		{
			name:    "duplicate namespace",
			in:      []string{"prod.acct1=write", "prod.acct1=read"},
			wantErr: "duplicate",
		},
		{
			name:    "more than one equals sign",
			in:      []string{"prod.acct1=write=read"},
			wantErr: "namespace=permission",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseNamespaceAccess(tc.in)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got %v", tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected the error to mention %q, got: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestServiceAccounts_CreateReadDelete(t *testing.T) {
	b, storage := newTestBackend(t)

	var createdSpec client.ServiceAccountSpec
	deleted := ""
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(_ context.Context, spec client.ServiceAccountSpec) (string, error) {
		createdSpec = spec
		return "sa-created", nil
	}
	stub.deleteServiceAccountFn = func(_ context.Context, id string) error {
		deleted = id
		return nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_role":     "developer",
			"namespace_access": []string{"prod.acct1=write"},
			"description":      "vault managed",
			"ttl":              "1h",
			"max_ttl":          "8h",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create: err=%v resp=%v", err, resp)
	}

	// The name in the path becomes the Temporal Cloud service account name.
	if createdSpec.Name != "prod-workers" {
		t.Errorf("expected the SA to be named prod-workers, got %q", createdSpec.Name)
	}
	if createdSpec.AccountRole != "developer" {
		t.Errorf("expected role developer, got %q", createdSpec.AccountRole)
	}
	if createdSpec.NamespaceAccess["prod.acct1"] != "write" {
		t.Errorf("expected write on prod.acct1, got %v", createdSpec.NamespaceAccess)
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read: err=%v resp=%v", err, resp)
	}
	if resp.Data["service_account_id"] != "sa-created" {
		t.Errorf("expected sa-created, got %v", resp.Data["service_account_id"])
	}
	if resp.Data["account_role"] != "developer" {
		t.Errorf("expected developer, got %v", resp.Data["account_role"])
	}
	if resp.Data["ttl"] != int64(3600) {
		t.Errorf("expected ttl 3600, got %v", resp.Data["ttl"])
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if deleted != "sa-created" {
		t.Errorf("expected the Temporal Cloud SA to be deleted, got %q", deleted)
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/prod-workers",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("read after delete: %v", err)
	}
	if resp != nil && len(resp.Data) > 0 {
		t.Fatal("expected the entry to be gone after delete")
	}
}

// If Temporal Cloud creates the account but Vault cannot persist it, the
// orphaned account must be cleaned up rather than silently leaked.
func TestServiceAccounts_CompensatesWhenStorageFails(t *testing.T) {
	b, _ := newTestBackend(t)

	deleted := ""
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-orphan", nil
	}
	stub.deleteServiceAccountFn = func(_ context.Context, id string) error {
		deleted = id
		return nil
	}
	withStubClient(b, stub)

	// A storage view that accepts the config write but fails the service
	// account write, so we exercise exactly the compensation path.
	storage := &failingStorage{
		Storage:      &logical.InmemStorage{},
		failOnPrefix: "service-account/",
	}
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/doomed",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "read"},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected the create to fail when storage fails")
	}
	if deleted != "sa-orphan" {
		t.Errorf("expected the orphaned service account to be deleted, got %q", deleted)
	}
}

func TestServiceAccounts_List(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-x", nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	for _, name := range []string{"alpha", "beta"} {
		if _, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "service-accounts/" + name,
			Storage:   storage,
			Data:      map[string]interface{}{"account_role": "read"},
		}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "service-accounts/",
		Storage:   storage,
	})
	if err != nil || resp == nil {
		t.Fatalf("list: err=%v resp=%v", err, resp)
	}

	keys, _ := resp.Data["keys"].([]string)
	if len(keys) != 2 {
		t.Fatalf("expected 2 entries, got %v", keys)
	}
}

// Changing only TTLs must not call Temporal Cloud: nothing about the cloud-side
// resource changed.
func TestServiceAccounts_TTLOnlyUpdateSkipsCloudCall(t *testing.T) {
	b, storage := newTestBackend(t)

	updates := 0
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	stub.updateServiceAccountFn = func(context.Context, string, client.ServiceAccountSpec) error {
		updates++
		return nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	base := map[string]interface{}{"account_role": "read", "ttl": "1h"}
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data:      base,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "read", "ttl": "2h"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	if updates != 0 {
		t.Errorf("expected no UpdateServiceAccount call for a TTL-only change, got %d", updates)
	}
}

// Changing the role must reach Temporal Cloud.
func TestServiceAccounts_RoleChangeCallsCloud(t *testing.T) {
	b, storage := newTestBackend(t)

	updates := 0
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	stub.updateServiceAccountFn = func(context.Context, string, client.ServiceAccountSpec) error {
		updates++
		return nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "read"},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "service-accounts/svc",
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "developer"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	if updates != 1 {
		t.Errorf("expected exactly one UpdateServiceAccount call, got %d", updates)
	}
}

func TestServiceAccounts_Validation(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
	}{
		{"missing account_role", map[string]interface{}{}},
		{"bad account_role", map[string]interface{}{"account_role": "wizard"}},
		{"bad namespace_access", map[string]interface{}{"account_role": "read", "namespace_access": []string{"oops"}}},
		{"ttl greater than max_ttl", map[string]interface{}{"account_role": "read", "ttl": "10h", "max_ttl": "1h"}},
		{"max_ttl beyond two years", map[string]interface{}{"account_role": "read", "max_ttl": "20000h"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := newTestBackend(t)
			withStubClient(b, &stubCloudOps{})
			mustWriteConfig(t, b, storage)

			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "service-accounts/x",
				Storage:   storage,
				Data:      tc.data,
			})
			if err == nil && (resp == nil || !resp.IsError()) {
				t.Fatal("expected an error")
			}
		})
	}
}

// failingStorage fails writes under a given prefix, to exercise compensation.
type failingStorage struct {
	logical.Storage
	failOnPrefix string
}

func (s *failingStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if strings.HasPrefix(entry.Key, s.failOnPrefix) {
		return errors.New("simulated storage failure")
	}
	return s.Storage.Put(ctx, entry)
}
```

Add `"errors"` to that file's imports.

- [ ] **Step 2: Extend the stub in `path_config_test.go`**

Add these fields to `stubCloudOps` and make the three methods consult them:

```go
	createServiceAccountFn func(ctx context.Context, spec client.ServiceAccountSpec) (string, error)
	updateServiceAccountFn func(ctx context.Context, id string, spec client.ServiceAccountSpec) error
	deleteServiceAccountFn func(ctx context.Context, id string) error
```

```go
func (s *stubCloudOps) CreateServiceAccount(ctx context.Context, spec client.ServiceAccountSpec) (string, error) {
	if s.createServiceAccountFn != nil {
		return s.createServiceAccountFn(ctx, spec)
	}
	return "sa-stub", nil
}

func (s *stubCloudOps) UpdateServiceAccount(ctx context.Context, id string, spec client.ServiceAccountSpec) error {
	if s.updateServiceAccountFn != nil {
		return s.updateServiceAccountFn(ctx, id, spec)
	}
	return nil
}

func (s *stubCloudOps) DeleteServiceAccount(ctx context.Context, id string) error {
	if s.deleteServiceAccountFn != nil {
		return s.deleteServiceAccountFn(ctx, id)
	}
	return nil
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test . -run 'TestParseNamespaceAccess|TestServiceAccounts' -v`
Expected: FAIL — `undefined: parseNamespaceAccess`.

- [ ] **Step 4: Write `path_service_accounts.go`**

```go
package temporalcloud

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/temporal-sa/vault-plugin-temporalcloud/client"
)

const (
	// serviceAccountStoragePrefix is singular while the API path is plural,
	// following the convention in Vault's own engines.
	serviceAccountStoragePrefix = "service-account/"

	defaultServiceAccountTTL    = time.Hour
	defaultServiceAccountMaxTTL = 24 * time.Hour

	// apiKeyExpiryGrace is added to max_ttl when setting a key's Temporal
	// Cloud expiry, so a key never expires before the lease that owns it.
	// Task 7 uses this when minting.
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
				Description: `Namespace permissions as "namespace=permission" pairs, where permission is admin, write, or read. Example: prod.acct1=write,staging.acct1=read`,
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
				Type:        framework.TypeDurationSecond,
				Description: "Maximum lease TTL. Also sets the Temporal Cloud expiry on every key minted here.",
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

	accountRole := d.Get("account_role").(string)
	if accountRole == "" {
		return logical.ErrorResponse("account_role is required"), nil
	}
	if _, err := client.ParseAccountRole(accountRole); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	namespaceAccess, err := parseNamespaceAccess(d.Get("namespace_access").([]string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	ttl := time.Duration(d.Get("ttl").(int)) * time.Second
	maxTTL := time.Duration(d.Get("max_ttl").(int)) * time.Second
	if ttl == 0 {
		ttl = defaultServiceAccountTTL
	}
	if maxTTL == 0 {
		maxTTL = defaultServiceAccountMaxTTL
	}
	if ttl > maxTTL {
		return logical.ErrorResponse("ttl of %s exceeds max_ttl of %s", ttl, maxTTL), nil
	}
	// Every key minted here expires at max_ttl plus a grace margin, so max_ttl
	// must leave room under Temporal Cloud's two-year ceiling.
	if maxTTL+apiKeyExpiryGrace > client.MaxAPIKeyExpiry {
		return logical.ErrorResponse(
			"max_ttl of %s exceeds Temporal Cloud's maximum API key expiry of %s "+
				"(minus a %s grace margin)",
			maxTTL, client.MaxAPIKeyExpiry, apiKeyExpiryGrace), nil
	}

	entry := &serviceAccountEntry{
		AccountRole:     accountRole,
		NamespaceAccess: namespaceAccess,
		Description:     d.Get("description").(string),
		TTL:             ttl,
		MaxTTL:          maxTTL,
	}
	if entry.Description == "" {
		entry.Description = fmt.Sprintf("Managed by Vault mount %s", req.MountPoint)
	}

	spec := client.ServiceAccountSpec{
		Name:            name,
		Description:     entry.Description,
		AccountRole:     accountRole,
		NamespaceAccess: namespaceAccess,
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	switch {
	case existing == nil:
		// New entry: create the service account in Temporal Cloud.
		id, err := c.CreateServiceAccount(ctx, spec)
		if err != nil {
			return nil, fmt.Errorf("creating service account %q in Temporal Cloud: %w", name, err)
		}
		entry.ServiceAccountID = id

	default:
		entry.ServiceAccountID = existing.ServiceAccountID

		// Only call Temporal Cloud if something it knows about changed. TTLs
		// are a Vault-side concern, so a TTL-only edit needs no API call.
		if cloudSpecChanged(existing, entry) {
			if err := c.UpdateServiceAccount(ctx, entry.ServiceAccountID, spec); err != nil {
				return nil, fmt.Errorf("updating service account %q in Temporal Cloud: %w", name, err)
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
		// loudly so an operator can clean up by hand.
		if existing == nil {
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

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	if err := c.DeleteServiceAccount(ctx, entry.ServiceAccountID); err != nil {
		if !errors.Is(err, client.ErrNotFound) {
			return nil, fmt.Errorf("deleting service account %q from Temporal Cloud: %w", name, err)
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

Writing this path creates the service account in Temporal Cloud; deleting it
deletes the service account, which invalidates every API key it owns. Changing
only ttl or max_ttl is a Vault-side change and makes no Temporal Cloud call.

Read credentials for this service account from creds/<name>.

Protect this path with Vault policy. An operator who can write here can create a
service account with the owner role and then mint keys for it, so write access
belongs only to platform operators. Applications need read on creds/<name> only.
`
```

Add `"sort"` to the imports.

- [ ] **Step 5: Register both paths in `backend.go`**

```go
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathRotateRoot(),
			b.pathServiceAccounts(),
			b.pathServiceAccountsList(),
		},
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `gofmt -w . && go test . -run 'TestParseNamespaceAccess|TestServiceAccounts' -v`
Expected: PASS — all `TestParseNamespaceAccess` and `TestServiceAccounts` tests.

- [ ] **Step 7: Run the whole fast suite**

Run: `go test ./... -count=1`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add .
git commit -m "feat: add service-accounts/<name> CRUD

Creates, updates, and deletes Temporal Cloud service accounts, with
namespace=permission parsing that rejects every malformed shape. TTL-only edits
skip the Cloud Ops call; a failed storage write compensates by deleting the
service account it just created."
```

---

### Task 7: `creds/<name>` and the lease lifecycle

The heart of the engine: mint a key per lease, revoke it when the lease ends.

**Files:**
- Create: `path_creds.go`, `secret_api_key.go`
- Modify: `backend.go` — register the path and the secret type
- Test: `path_creds_test.go`

**Interfaces:**
- Consumes: `b.getClient`, `b.getServiceAccount`, `serviceAccountEntry`, `apiKeyExpiryGrace`, `client.MaxAPIKeysPerServiceAccount`.
- Produces: `const secretTypeAPIKey = "temporalcloud_api_key"`; `func (b *backend) pathCreds() *framework.Path`; `func (b *backend) secretAPIKey() *framework.Secret`; `func apiKeyDisplayName(name string) string`; `func checkAPIKeyCapacity(name string, count int, ttl time.Duration) error`.

- [ ] **Step 1: Write the failing test**

`path_creds_test.go`:

```go
package temporalcloud

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/temporal-sa/vault-plugin-temporalcloud/client"
)

// The cap check is where a confusing failure would otherwise surface, so it is
// tested directly at its boundaries.
func TestCheckAPIKeyCapacity(t *testing.T) {
	tests := []struct {
		name    string
		count   int
		wantErr bool
	}{
		{"well under the cap", 0, false},
		{"one below the cap", 19, false},
		{"at the cap", 20, true},
		{"above the cap", 21, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAPIKeyCapacity("prod-workers", tc.count, time.Hour)

			if tc.wantErr && err == nil {
				t.Fatalf("expected an error at count %d", tc.count)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error at count %d: %v", tc.count, err)
			}
		})
	}
}

// The message must be actionable: it has to name the service account, the cap,
// the current TTL, and what the operator can do about it.
func TestCheckAPIKeyCapacity_MessageIsActionable(t *testing.T) {
	err := checkAPIKeyCapacity("prod-workers", 20, time.Hour)
	if err == nil {
		t.Fatal("expected an error")
	}

	for _, want := range []string{"prod-workers", "20", "1h", "Revoke", "service account"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected the message to mention %q, got: %v", want, err)
		}
	}
}

func TestCreds_MintsKeyAndIssuesLease(t *testing.T) {
	b, storage := newTestBackend(t)

	var gotSpec client.APIKeySpec
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	stub.createAPIKeyFn = func(_ context.Context, spec client.APIKeySpec) (*client.APIKey, error) {
		gotSpec = spec
		return &client.APIKey{ID: "key-1", Token: "tmprl_sk_minted"}, nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "developer",
		"ttl":          "1h",
		"max_ttl":      "8h",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read creds: err=%v resp=%v", err, resp)
	}

	if resp.Data["api_key"] != "tmprl_sk_minted" {
		t.Errorf("expected the minted token, got %v", resp.Data["api_key"])
	}
	if resp.Data["api_key_id"] != "key-1" {
		t.Errorf("expected key-1, got %v", resp.Data["api_key_id"])
	}
	if resp.Data["service_account_id"] != "sa-1" {
		t.Errorf("expected sa-1, got %v", resp.Data["service_account_id"])
	}

	if resp.Secret == nil {
		t.Fatal("expected a lease")
	}
	if resp.Secret.TTL != time.Hour {
		t.Errorf("expected a 1h lease, got %v", resp.Secret.TTL)
	}
	if resp.Secret.MaxTTL != 8*time.Hour {
		t.Errorf("expected an 8h max TTL, got %v", resp.Secret.MaxTTL)
	}

	// The key ID must be in internal data so revocation can find it, and the
	// token must not be, because Vault never persists it.
	if resp.Secret.InternalData["api_key_id"] != "key-1" {
		t.Errorf("expected api_key_id in internal data, got %v", resp.Secret.InternalData)
	}
	if _, present := resp.Secret.InternalData["api_key"]; present {
		t.Error("the token must never be stored in lease internal data")
	}

	// The Temporal Cloud expiry must cover max_ttl plus grace, not just ttl:
	// otherwise a renewed lease would outlive its own key.
	wantExpiry := time.Now().Add(8*time.Hour + apiKeyExpiryGrace)
	if delta := gotSpec.ExpiryTime.Sub(wantExpiry); delta > time.Minute || delta < -time.Minute {
		t.Errorf("expected an expiry near %v (max_ttl + grace), got %v", wantExpiry, gotSpec.ExpiryTime)
	}
	if gotSpec.ServiceAccountID != "sa-1" {
		t.Errorf("expected the key to be minted on sa-1, got %q", gotSpec.ServiceAccountID)
	}
}

func TestCreds_FailsAtCapacity(t *testing.T) {
	b, storage := newTestBackend(t)

	minted := 0
	stub := &stubCloudOps{}
	stub.createServiceAccountFn = func(context.Context, client.ServiceAccountSpec) (string, error) {
		return "sa-1", nil
	}
	stub.countAPIKeysFn = func(context.Context, string) (int, error) {
		return client.MaxAPIKeysPerServiceAccount, nil
	}
	stub.createAPIKeyFn = func(context.Context, client.APIKeySpec) (*client.APIKey, error) {
		minted++
		return &client.APIKey{ID: "key-x", Token: "tok"}, nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{"account_role": "read"})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected the read to fail at the key cap")
	}
	if minted != 0 {
		t.Error("no key should be minted once the cap is reached")
	}
}

func TestCreds_UnknownServiceAccount(t *testing.T) {
	b, storage := newTestBackend(t)
	withStubClient(b, &stubCloudOps{})
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/does-not-exist",
		Storage:   storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected an error for an unknown service account")
	}
	if resp != nil && !strings.Contains(resp.Error().Error(), "does-not-exist") {
		t.Errorf("expected the message to name the entry, got %v", resp.Error())
	}
}

func TestRevoke_DeletesKey(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"api_key_id":   "key-to-revoke",
				"secret_type":  secretTypeAPIKey,
			},
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("revoke: err=%v resp=%v", err, resp)
	}

	if len(stub.deletedAPIKeys) != 1 || stub.deletedAPIKeys[0] != "key-to-revoke" {
		t.Errorf("expected key-to-revoke to be deleted, got %v", stub.deletedAPIKeys)
	}
}

// A key that is already gone means revocation has nothing left to do. Failing
// here would leave the lease stuck forever.
func TestRevoke_TreatsNotFoundAsSuccess(t *testing.T) {
	b, storage := newTestBackend(t)
	stub := &stubCloudOps{
		deleteAPIKeyFn: func(context.Context, string) error { return client.ErrNotFound },
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"api_key_id":  "already-gone",
				"secret_type": secretTypeAPIKey,
			},
		},
	})
	if err != nil {
		t.Fatalf("revoking an already-deleted key must succeed, got: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("revoking an already-deleted key must succeed, got: %v", resp.Error())
	}
}

func TestRenew_ExtendsWithoutCloudCall(t *testing.T) {
	b, storage := newTestBackend(t)

	minted := 0
	stub := &stubCloudOps{}
	stub.createAPIKeyFn = func(context.Context, client.APIKeySpec) (*client.APIKey, error) {
		minted++
		return &client.APIKey{ID: "k", Token: "t"}, nil
	}
	withStubClient(b, stub)
	mustWriteConfig(t, b, storage)
	mustWriteServiceAccount(t, b, storage, "prod-workers", map[string]interface{}{
		"account_role": "read",
		"ttl":          "1h",
		"max_ttl":      "8h",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/prod-workers",
		Storage:   storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"api_key_id":           "key-1",
				"service_account_name": "prod-workers",
				"secret_type":          secretTypeAPIKey,
			},
			LeaseOptions: logical.LeaseOptions{TTL: time.Hour, IssueTime: time.Now()},
		},
	})
	if err != nil || resp == nil {
		t.Fatalf("renew: err=%v resp=%v", err, resp)
	}

	if resp.Secret.TTL != time.Hour {
		t.Errorf("expected the entry's ttl of 1h, got %v", resp.Secret.TTL)
	}
	// Renewal must not touch Temporal Cloud: the key already expires at
	// max_ttl + grace, so extending the lease needs no API call.
	if minted != 0 || len(stub.deletedAPIKeys) != 0 {
		t.Error("renewal must make no Temporal Cloud calls")
	}
}

// mustWriteServiceAccount creates a service-accounts/<name> entry.
func mustWriteServiceAccount(t *testing.T, b *backend, storage logical.Storage, name string, data map[string]interface{}) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/" + name,
		Storage:   storage,
		Data:      data,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write service account %s: err=%v resp=%v", name, err, resp)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test . -run 'TestCheckAPIKeyCapacity|TestCreds|TestRevoke|TestRenew' -v`
Expected: FAIL — `undefined: checkAPIKeyCapacity`.

- [ ] **Step 3: Write `path_creds.go`**

```go
package temporalcloud

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/temporal-sa/vault-plugin-temporalcloud/client"
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
```

- [ ] **Step 4: Write `secret_api_key.go`**

```go
package temporalcloud

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/temporal-sa/vault-plugin-temporalcloud/client"
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
```

- [ ] **Step 5: Register the path and secret in `backend.go`**

```go
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathRotateRoot(),
			b.pathServiceAccounts(),
			b.pathServiceAccountsList(),
			b.pathCreds(),
		},
		Secrets: []*framework.Secret{
			b.secretAPIKey(),
		},
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `gofmt -w . && go test . -run 'TestCheckAPIKeyCapacity|TestCreds|TestRevoke|TestRenew' -v`
Expected: PASS — all eight tests.

- [ ] **Step 7: Run the whole fast suite**

Run: `go test ./... -count=1`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add .
git commit -m "feat: add creds/<name> and the API key lease lifecycle

Mints one API key per lease, checks the 20-key ceiling first with an actionable
error, and deletes the key on revocation. Key expiry covers max_ttl plus grace
so renewal needs no Cloud Ops call and orphaned keys self-destruct."
```

---

### Task 8: Live acceptance tests and the sweeper

The first task that proves anything against real Temporal Cloud. Everything before this was verified only against stubs.

**Files:**
- Create: `acceptance_test.go` (build tag `acceptance`), `cmd/sweep/main.go`
- Test: this task *is* the test

**Interfaces:**
- Consumes: everything.
- Produces: `func liveBackend(t *testing.T) (*backend, logical.Storage)`; `func acctestName(t *testing.T) string`; `const acctestPrefix = "vault-acctest-"`.

**Before starting:** confirm the credentials are present, or this task cannot be verified.

```bash
test -n "$TEMPORAL_CLOUD_API_KEY" && test -n "$TEMPORAL_CLOUD_ADMIN_SA_ID" && echo OK
```

If they are absent, stop and tell the user rather than writing tests you cannot run. Store them in `.env` (already gitignored), not in shell history.

- [ ] **Step 1: Write `acceptance_test.go`**

Every create registers cleanup **immediately**, before any assertion that could fail — that is the whole debris-control strategy.

```go
//go:build acceptance

package temporalcloud

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/temporal-sa/vault-plugin-temporalcloud/client"
)

// acctestPrefix names every resource these tests create, so anything left
// behind by a crashed run is identifiable and sweepable.
const acctestPrefix = "vault-acctest-"

// liveBackend builds a backend wired to the real Cloud Ops API and configured
// from the environment.
func liveBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()

	apiKey := os.Getenv("TEMPORAL_CLOUD_API_KEY")
	adminSAID := os.Getenv("TEMPORAL_CLOUD_ADMIN_SA_ID")
	if apiKey == "" || adminSAID == "" {
		t.Skip("set TEMPORAL_CLOUD_API_KEY and TEMPORAL_CLOUD_ADMIN_SA_ID to run live tests")
	}

	conf := logical.TestBackendConfig()
	conf.StorageView = &logical.InmemStorage{}
	storage := conf.StorageView

	b := Backend()
	if err := b.Setup(context.Background(), conf); err != nil {
		t.Fatalf("backend setup: %v", err)
	}

	data := map[string]interface{}{
		"api_key":                  apiKey,
		"admin_service_account_id": adminSAID,
	}
	if id := os.Getenv("TEMPORAL_CLOUD_API_KEY_ID"); id != "" {
		data["api_key_id"] = id
	}
	if addr := os.Getenv("TEMPORAL_CLOUD_ADDRESS"); addr != "" {
		data["address"] = addr
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("configuring against the live account failed: err=%v resp=%v", err, resp)
	}

	t.Cleanup(func() { b.resetClient() })

	return b, storage
}

// acctestName produces a unique, identifiable resource name.
func acctestName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s%d", acctestPrefix, time.Now().UnixNano())
}

// createServiceAccount creates one and registers its deletion immediately, so
// a later assertion failure cannot leak it.
func createServiceAccount(t *testing.T, b *backend, storage logical.Storage, name string, data map[string]interface{}) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "service-accounts/" + name,
		Storage:   storage,
		Data:      data,
	})

	// Register cleanup before checking the result: a partial failure may still
	// have created the cloud-side account.
	t.Cleanup(func() {
		_, _ = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "service-accounts/" + name,
			Storage:   storage,
		})
	})

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create service account %s: err=%v resp=%v", name, err, resp)
	}
}

// TestLive_ConfigValidatesCredential proves the write-time validation actually
// talks to Temporal Cloud.
func TestLive_ConfigValidatesCredential(t *testing.T) {
	b, storage := liveBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read config: err=%v resp=%v", err, resp)
	}
	if _, present := resp.Data["api_key"]; present {
		t.Error("api_key must never be returned")
	}
}

func TestLive_ConfigRejectsBadServiceAccountID(t *testing.T) {
	b, _ := liveBackend(t)

	storage := &logical.InmemStorage{}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_key":                  os.Getenv("TEMPORAL_CLOUD_API_KEY"),
			"admin_service_account_id": "definitely-not-a-real-service-account-id",
		},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected a nonexistent admin_service_account_id to be rejected")
	}
}

// TestLive_ServiceAccountLifecycle exercises create, read, update, and delete
// against the real API, including the async operation polling.
func TestLive_ServiceAccountLifecycle(t *testing.T) {
	b, storage := liveBackend(t)
	name := acctestName(t)

	createServiceAccount(t, b, storage, name, map[string]interface{}{
		"account_role": "read",
		"ttl":          "10m",
		"max_ttl":      "1h",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-accounts/" + name,
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read: err=%v resp=%v", err, resp)
	}

	saID, _ := resp.Data["service_account_id"].(string)
	if saID == "" {
		t.Fatal("expected a Temporal Cloud service account ID")
	}
	t.Logf("created service account %s (%s)", name, saID)

	// Update the role — this must reach Temporal Cloud and complete its async
	// operation.
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "service-accounts/" + name,
		Storage:   storage,
		Data:      map[string]interface{}{"account_role": "developer"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	c, err := b.getClient(context.Background(), storage)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	sa, err := c.GetServiceAccount(context.Background(), saID)
	if err != nil {
		t.Fatalf("fetching the updated service account: %v", err)
	}
	if sa.Spec.AccountRole != "developer" {
		t.Errorf("expected the role change to reach Temporal Cloud, got %q", sa.Spec.AccountRole)
	}
}

// TestLive_CredentialLifecycle is the test that matters: a minted key must
// actually authenticate, and must stop working once revoked.
func TestLive_CredentialLifecycle(t *testing.T) {
	b, storage := liveBackend(t)
	name := acctestName(t)

	createServiceAccount(t, b, storage, name, map[string]interface{}{
		"account_role": "read",
		"ttl":          "10m",
		"max_ttl":      "1h",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + name,
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read creds: err=%v resp=%v", err, resp)
	}

	token, _ := resp.Data["api_key"].(string)
	keyID, _ := resp.Data["api_key_id"].(string)
	if token == "" || keyID == "" {
		t.Fatalf("expected a token and key ID, got %v", resp.Data)
	}

	// Clean up the key even if the assertions below fail.
	t.Cleanup(func() {
		c, err := b.getClient(context.Background(), storage)
		if err != nil {
			return
		}
		_ = c.DeleteAPIKey(context.Background(), keyID)
	})

	// The minted key must authenticate. Building a client with it and reading
	// the admin service account is the cheapest proof.
	minted, err := client.NewGRPC(client.Config{
		APIKey:   token,
		HostPort: os.Getenv("TEMPORAL_CLOUD_ADDRESS"),
	})
	if err != nil {
		t.Fatalf("building a client with the minted key: %v", err)
	}
	defer func() { _ = minted.Close() }()

	saID, _ := resp.Data["service_account_id"].(string)
	if _, err := minted.GetServiceAccount(context.Background(), saID); err != nil {
		t.Fatalf("the minted key failed to authenticate: %v", err)
	}
	t.Logf("minted key %s authenticated", keyID)

	// Revoke, then prove the key is gone.
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/" + name,
		Storage:   storage,
		Secret:    resp.Secret,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Temporal Cloud may take a moment to propagate the deletion, so retry
	// briefly rather than asserting once and flaking.
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, err := minted.GetServiceAccount(context.Background(), saID)
		if err != nil {
			t.Logf("revoked key correctly rejected: %v", err)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the revoked key still authenticates after 30s")
		}
		time.Sleep(2 * time.Second)
	}
}

// TestLive_RotateRoot rotates the root credential and rotates it back, leaving
// the account as it was found.
func TestLive_RotateRoot(t *testing.T) {
	if os.Getenv("TEMPORAL_CLOUD_ALLOW_ROOT_ROTATION") == "" {
		t.Skip("set TEMPORAL_CLOUD_ALLOW_ROOT_ROTATION=1 to run this; it replaces the configured root key")
	}

	b, storage := liveBackend(t)

	before, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("get config: %v", err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate-root: err=%v resp=%v", err, resp)
	}
	for _, w := range resp.Warnings {
		t.Logf("warning: %s", w)
	}

	after, err := b.getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	if after.APIKey == before.APIKey {
		t.Fatal("expected the stored root key to change")
	}

	// The new key must work.
	c, err := b.getClient(context.Background(), storage)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if _, err := c.GetServiceAccount(context.Background(), after.AdminServiceAccountID); err != nil {
		t.Fatalf("the rotated root key does not work: %v", err)
	}

	t.Logf("root rotated: %s -> %s. The key in your environment is now DELETED; "+
		"update TEMPORAL_CLOUD_API_KEY before the next run.", before.APIKeyID, after.APIKeyID)
}

// TestLive_KeyCapacity proves the ceiling is real and our error fires first.
// It is slow and consumes all 20 slots, so it is opt-in.
func TestLive_KeyCapacity(t *testing.T) {
	if os.Getenv("TEMPORAL_CLOUD_RUN_CAPACITY_TEST") == "" {
		t.Skip("set TEMPORAL_CLOUD_RUN_CAPACITY_TEST=1 to run this; it mints 20 API keys")
	}

	b, storage := liveBackend(t)
	name := acctestName(t)

	createServiceAccount(t, b, storage, name, map[string]interface{}{
		"account_role": "read",
		"ttl":          "10m",
		"max_ttl":      "1h",
	})

	for i := 0; i < client.MaxAPIKeysPerServiceAccount; i++ {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   storage,
		})
		if err != nil || resp == nil || resp.IsError() {
			t.Fatalf("mint %d: err=%v resp=%v", i, err, resp)
		}

		keyID, _ := resp.Data["api_key_id"].(string)
		t.Cleanup(func() {
			c, err := b.getClient(context.Background(), storage)
			if err != nil {
				return
			}
			_ = c.DeleteAPIKey(context.Background(), keyID)
		})
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + name,
		Storage:   storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected the 21st mint to be refused")
	}
	if !strings.Contains(resp.Error().Error(), "20 of 20") {
		t.Errorf("expected our capacity message, got: %v", resp.Error())
	}
}
```

- [ ] **Step 2: Run the live tests**

Run: `make test-live`
Expected: PASS. `TestLive_RotateRoot` and `TestLive_KeyCapacity` skip unless explicitly enabled.

If a test fails, read the error before changing code — a Cloud Ops rejection usually names the real problem. Then run `make sweep` before retrying, so leftover resources do not affect the next run.

- [ ] **Step 2a: Verify the assumption behind `CountAPIKeys`**

`CountAPIKeys` counts every key `GetApiKeys` returns and compares that to the cap of 20. That is only correct if the API omits expired and deleted keys. If it includes them, the count drifts upward forever and the engine will start refusing to mint long before the real ceiling.

Check it directly:

```bash
go run ./cmd/checkcount   # see below
```

Write `cmd/checkcount/main.go` as a throwaway that mints a key with a 60-second expiry on a test service account, prints `CountAPIKeys` before minting, after minting, and again after the key expires, then deletes the service account. If the third count does not return to the first, fix `CountAPIKeys` to filter on `ApiKey.State` — keep only `ResourceState_RESOURCE_STATE_ACTIVE` — and add a `TestLive_CountExcludesExpiredKeys` covering it.

Delete `cmd/checkcount` once the question is settled; record the answer as a comment on `CountAPIKeys` either way, so nobody has to re-derive it.

- [ ] **Step 3: Write the sweeper**

`cmd/sweep/main.go`:

```go
// Command sweep deletes Temporal Cloud service accounts left behind by failed
// acceptance test runs. Live tests create real resources, and a test that dies
// mid-flight cannot clean up after itself.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	cloudservicev1 "go.temporal.io/cloud-sdk/api/cloudservice/v1"
	"go.temporal.io/cloud-sdk/cloudclient"
)

// acctestPrefix must match the constant in acceptance_test.go.
const acctestPrefix = "vault-acctest-"

func main() {
	apiKey := os.Getenv("TEMPORAL_CLOUD_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "TEMPORAL_CLOUD_API_KEY is not set")
		os.Exit(1)
	}

	conn, err := cloudclient.New(cloudclient.Options{
		APIKey:   apiKey,
		HostPort: os.Getenv("TEMPORAL_CLOUD_ADDRESS"),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "connecting: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	ctx := context.Background()
	svc := conn.CloudService()

	swept := 0
	pageToken := ""

	for {
		resp, err := svc.GetServiceAccounts(ctx, &cloudservicev1.GetServiceAccountsRequest{
			PageSize:  100,
			PageToken: pageToken,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "listing service accounts: %v\n", err)
			os.Exit(1)
		}

		for _, sa := range resp.GetServiceAccounts() {
			if !strings.HasPrefix(sa.GetSpec().GetName(), acctestPrefix) {
				continue
			}

			fmt.Printf("deleting %s (%s)\n", sa.GetSpec().GetName(), sa.GetId())

			if _, err := svc.DeleteServiceAccount(ctx, &cloudservicev1.DeleteServiceAccountRequest{
				ServiceAccountId: sa.GetId(),
				ResourceVersion:  sa.GetResourceVersion(),
			}); err != nil {
				fmt.Fprintf(os.Stderr, "  could not delete: %v\n", err)
				continue
			}
			swept++
		}

		pageToken = resp.GetNextPageToken()
		if pageToken == "" {
			break
		}
	}

	fmt.Printf("swept %d test service account(s)\n", swept)
}
```

Deleting a service account also invalidates the API keys it owns, so sweeping accounts is enough — there is no separate key sweep.

- [ ] **Step 4: Verify the sweeper runs clean**

Run: `make sweep`
Expected: `swept 0 test service account(s)` after a successful test run. If it reports more, the cleanup registration in a test is in the wrong place — fix that rather than relying on the sweeper.

- [ ] **Step 5: Commit**

```bash
git add .
git commit -m "test: add live acceptance tests and the sweeper

Exercises config validation, service account CRUD, and the full credential
lifecycle against a real Temporal Cloud account, including proving a minted key
authenticates and a revoked one does not. Root rotation and the 20-key capacity
test are opt-in. cmd/sweep clears debris from crashed runs."
```

---

### Task 9: README, examples, and the demo target

Makes the engine presentable. For customer-facing material this is deliverable, not decoration.

**Files:**
- Create: `README.md`, `examples/README.md`, `examples/demo.sh`, `scripts/dev.sh`
- Modify: `Makefile` — add `dev`

**Interfaces:**
- Consumes: everything.
- Produces: `make dev`.

- [ ] **Step 1: Write `scripts/dev.sh`**

```bash
#!/usr/bin/env bash
# Starts a dev-mode Vault with this plugin built, registered, and mounted.
# Dev mode keeps everything in memory and auto-unseals, so it is right for a
# demo and wrong for anything else.
set -euo pipefail

PLUGIN_NAME="vault-plugin-secrets-temporalcloud"
PLUGIN_DIR="$(pwd)/bin"
MOUNT="${MOUNT:-temporalcloud}"
export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-root}"

command -v vault >/dev/null || { echo "vault is not installed: brew install vault"; exit 1; }

echo "==> Building the plugin"
mkdir -p "$PLUGIN_DIR"
go build -o "$PLUGIN_DIR/$PLUGIN_NAME" "./cmd/$PLUGIN_NAME"

echo "==> Starting Vault in dev mode"
vault server -dev -dev-root-token-id="$VAULT_TOKEN" \
    -dev-plugin-dir="$PLUGIN_DIR" -log-level=info &
VAULT_PID=$!
trap 'kill $VAULT_PID 2>/dev/null || true' EXIT

# Wait for Vault to accept connections rather than guessing with sleep.
for _ in $(seq 1 30); do
    if vault status >/dev/null 2>&1; then break; fi
    sleep 0.5
done

echo "==> Enabling the secrets engine at $MOUNT/"
vault secrets enable -path="$MOUNT" "$PLUGIN_NAME"

cat <<EOF

Vault is running with the plugin mounted at $MOUNT/

  export VAULT_ADDR=$VAULT_ADDR
  export VAULT_TOKEN=$VAULT_TOKEN

Next, configure it against your Temporal Cloud account:

  vault write $MOUNT/config \\
      api_key="\$TEMPORAL_CLOUD_API_KEY" \\
      admin_service_account_id="\$TEMPORAL_CLOUD_ADMIN_SA_ID"

Then run ./examples/demo.sh for the full walkthrough.
Press Ctrl-C to stop Vault.

EOF

wait $VAULT_PID
```

Make it executable: `chmod +x scripts/dev.sh`

- [ ] **Step 2: Add the `dev` target to the Makefile**

```makefile
## dev: build the plugin and run Vault in dev mode with it mounted
dev:
	@./scripts/dev.sh
```

Add `dev` to the `.PHONY` line.

- [ ] **Step 3: Write `examples/demo.sh`**

```bash
#!/usr/bin/env bash
# End-to-end walkthrough. Run after `make dev` in another terminal, with
# TEMPORAL_CLOUD_API_KEY and TEMPORAL_CLOUD_ADMIN_SA_ID set.
set -euo pipefail

MOUNT="${MOUNT:-temporalcloud}"
SA_NAME="${SA_NAME:-demo-workers}"
: "${TEMPORAL_CLOUD_API_KEY:?set TEMPORAL_CLOUD_API_KEY}"
: "${TEMPORAL_CLOUD_ADMIN_SA_ID:?set TEMPORAL_CLOUD_ADMIN_SA_ID}"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }

step "1. Configure the engine with the bootstrap credential"
vault write "$MOUNT/config" \
    api_key="$TEMPORAL_CLOUD_API_KEY" \
    admin_service_account_id="$TEMPORAL_CLOUD_ADMIN_SA_ID"

step "2. Rotate the root key so only Vault holds a working credential"
vault write -f "$MOUNT/config/rotate-root"
echo "The key you pasted in step 1 is now replaced by one Vault minted itself."

step "3. Create a service account in Temporal Cloud"
vault write "$MOUNT/service-accounts/$SA_NAME" \
    account_role=read \
    ttl=5m max_ttl=30m
vault read "$MOUNT/service-accounts/$SA_NAME"

step "4. Read a dynamic credential"
vault read "$MOUNT/creds/$SA_NAME"
echo "That API key exists in Temporal Cloud right now, and expires with its lease."

step "5. Show the lease"
vault list sys/leases/lookup/"$MOUNT"/creds/"$SA_NAME"

step "6. Revoke every lease — the keys are deleted in Temporal Cloud"
vault lease revoke -prefix "$MOUNT/creds/$SA_NAME"
echo "Check Settings -> API Keys in the Temporal Cloud UI: they are gone."

step "7. Tear down"
vault delete "$MOUNT/service-accounts/$SA_NAME"
echo "The service account is deleted in Temporal Cloud too."
```

Make it executable: `chmod +x examples/demo.sh`

- [ ] **Step 4: Write `README.md`**

It must cover, in this order: the problem, quick start, every path with examples, the 20-key ceiling, the rotate-root warning, policy guidance, running tests, and how it works. Write it as prose a customer can follow, not a reference dump. Required content:

- **The problem** — Temporal Cloud API keys are shown once, must expire (2y max), rotate manually in four steps, and have no lifecycle tie to the workload holding them. Vault dynamic secrets solve exactly this.
- **Quick start** — `make dev`, then the seven steps from `examples/demo.sh`.
- **Paths** — `config`, `config/rotate-root`, `service-accounts/<name>`, `creds/<name>`, with the field tables from the spec and a worked example each.
- **The 20-key ceiling** — a callout, not a footnote:
  > Temporal Cloud allows 20 non-expired API keys per service account, so at most **20 concurrent leases** per `service-accounts/<name>` entry. Revoking a lease frees a slot immediately; letting it expire does too. If you need more concurrent consumers, create more service accounts.
- **Root key expiry** — a warning callout:
  > Every Temporal Cloud API key expires, including Vault's own. Re-run `config/rotate-root` before `root_key_ttl` (default 90 days) elapses. If it expires, the mount stops working until an operator writes `config` with a fresh key made by hand.
- **Policy guidance** — with a working example:
  ```hcl
  # Platform operators: manage service accounts.
  path "temporalcloud/service-accounts/*" { capabilities = ["create","read","update","delete","list"] }

  # Applications: read their own credentials, nothing else.
  path "temporalcloud/creds/prod-workers" { capabilities = ["read"] }
  ```
  Plus the explanation: anyone who can write `service-accounts/*` can create an `owner`-role service account and mint keys for it, so that path is a privilege boundary. The engine relies on Vault policy for this rather than a second allowlist.
- **Running tests** — `make test` needs nothing; `make test-live` needs `TEMPORAL_CLOUD_API_KEY` and `TEMPORAL_CLOUD_ADMIN_SA_ID` in `.env`; `make sweep` clears debris. Note that `TestLive_RotateRoot` **deletes the key in your environment**, so it is opt-in via `TEMPORAL_CLOUD_ALLOW_ROOT_ROTATION=1`.
- **How it works** — the credential lifecycle diagram from the spec, and why the Temporal-side expiry is `max_ttl + 10m`.

- [ ] **Step 5: Write `examples/README.md`**

A short page: prerequisites, what `demo.sh` does step by step, what to point at in the Temporal Cloud UI at each step (Settings → Identities for the service account, Settings → API Keys for keys appearing and disappearing), and the two or three questions a customer usually asks — the 20-key ceiling, what happens to a running worker when a lease is revoked, and whether this works with mTLS instead.

- [ ] **Step 6: Verify the demo end to end**

In one terminal: `make dev`
In another: `export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root && ./examples/demo.sh`

Expected: all seven steps succeed. Check the Temporal Cloud UI to confirm the service account and keys appear and then disappear.

- [ ] **Step 7: Final verification**

```bash
gofmt -l .            # expect no output
go vet ./...
golangci-lint run     # if installed
make test
make sweep            # expect 0 swept
```

- [ ] **Step 8: Commit**

```bash
git add .
git commit -m "docs: add README, examples, and the dev demo target

make dev builds the plugin and starts Vault with it mounted; examples/demo.sh
walks the full lifecycle from configuration through revocation. README covers
the 20-key ceiling, root key expiry, and the policy boundary on
service-accounts/*."
```

---

## Verification against the spec's success criteria

After Task 9, confirm each criterion from the spec:

1. `make dev` yields a working mount against a real account — Task 9, Step 6.
2. `creds/<name>` returns a key that authenticates — `TestLive_CredentialLifecycle`.
3. Revoking deletes the key; it then fails to authenticate — `TestLive_CredentialLifecycle`.
4. `rotate-root` replaces the key, new works, old deleted — `TestLive_RotateRoot`.
5. At 20 keys, `creds/<name>` fails with the actionable message — `TestLive_KeyCapacity`.
6. Fast tests pass with no credentials — `make test`.
7. `make sweep` leaves no `vault-acctest-` resources — Task 8, Step 4.

Criteria 4 and 5 are behind opt-in environment variables because they are destructive or slow. Run both at least once before calling the engine done.
