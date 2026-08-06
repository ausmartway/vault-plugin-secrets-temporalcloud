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

### Task 1: Repository scaffold and backend skeleton

Produces a compiling, testable plugin with zero paths registered. Later tasks append paths.

**Files:**
- Create: `go.mod`, `Makefile`, `.gitignore`, `backend.go`, `cmd/vault-plugin-secrets-temporalcloud/main.go`
- Test: `backend_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error)`; `Backend() *backend`; the `backend` struct with fields `*framework.Backend`, `clientMu sync.RWMutex`, `client client.CloudOps`, `newClient func(*config) (client.CloudOps, error)`; test helper `newTestBackend(t *testing.T) (*backend, logical.Storage)`.

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

- [ ] **Step 2: Write `.gitignore`**

```gitignore
# Build output
/bin/
vault-plugin-secrets-temporalcloud

# Credentials — never commit these
.env
*.pem
*.key
```

- [ ] **Step 3: Write the failing test**

`backend_test.go` — a helper every later task reuses, plus a test that the backend constructs. `client` is not imported yet because no path needs it.

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

	storage := &logical.InmemStorage{}
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      logging.NewVaultLogger(log.Trace),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: time.Hour,
			MaxLeaseTTLVal:     24 * time.Hour,
		},
	}

	b := Backend()
	if err := b.Setup(context.Background(), conf); err != nil {
		t.Fatalf("backend setup: %v", err)
	}
	return b, storage
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

Add these imports to the file's import block:

```go
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
```

Note: the correct import path for hclog is `github.com/hashicorp/go-hclog`. If `go build` reports it missing, use `github.com/hashicorp/go-hclog` as provided transitively by the Vault SDK — run `go mod tidy` and let it resolve.

- [ ] **Step 4: Run the test to verify it fails**

Run: `go test ./... -run TestBackend_Constructs -v`
Expected: FAIL — `undefined: Backend`.

- [ ] **Step 5: Write `backend.go`**

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

// backend is the Temporal Cloud secrets engine.
type backend struct {
	*framework.Backend

	// clientMu guards the cached Cloud Ops client. The client owns a gRPC
	// connection, so we build it once and reuse it across requests rather
	// than dialling per request.
	clientMu sync.RWMutex
	client   client.CloudOps

	// newClient is a seam for tests: acceptance tests can substitute a
	// constructor that points at a different account or address.
	newClient func(cfg *config) (client.CloudOps, error)
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

	b.newClient = client.NewGRPC

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			// The root API key lives here, so it must be seal-wrapped.
			SealWrapStorage: []string{"config"},
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

`configStoragePath`, `config`, and `client.NewGRPC` do not exist yet. To keep this task compiling on its own, also create the two placeholder declarations below — Tasks 2 and 5 replace them with real implementations.

In a new file `placeholders.go` (deleted in Task 5):

```go
package temporalcloud

// configStoragePath is the storage key for the engine's configuration.
// Task 5 moves this to path_config.go along with the config type.
const configStoragePath = "config"

// config is replaced by the real type in Task 5.
type config struct{}
```

And in `client/client.go`, the minimum needed to compile (Task 2 replaces the whole file):

```go
package client

// CloudOps is replaced by the real interface in Task 2.
type CloudOps interface {
	Close() error
}

// NewGRPC is replaced by the real constructor in Task 4.
func NewGRPC(_ any) (CloudOps, error) { return nil, nil }
```

Adjust `b.newClient = client.NewGRPC` to compile against this signature by declaring the field as `func(cfg *config) (client.CloudOps, error)` and assigning a small adapter for now:

```go
	b.newClient = func(cfg *config) (client.CloudOps, error) {
		return client.NewGRPC(cfg)
	}
```

- [ ] **Step 6: Write the plugin entrypoint**

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

- [ ] **Step 7: Write the Makefile**

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

The `dev` target is added in Task 10, once there is something to demo.

- [ ] **Step 8: Run the test to verify it passes**

Run: `gofmt -w . && go mod tidy && go test ./... -v`
Expected: PASS — `TestBackend_Constructs`.

- [ ] **Step 9: Verify the plugin binary builds**

Run: `make build`
Expected: a binary in `bin/` and a printed SHA256.

- [ ] **Step 10: Commit**

```bash
git add .
git commit -m "feat: scaffold Vault plugin with backend skeleton

Module, Makefile, plugin entrypoint, and a framework.Backend with no paths
registered yet. Later tasks append paths and secrets."
```

---

### Task 2: `CloudOps` interface and its plain-Go types

Defines the seam. No gRPC yet — this task is types plus the error taxonomy that path handlers switch on.

**Files:**
- Create: `client/client.go`, `client/errors.go`
- Test: `client/errors_test.go`
- Delete: the placeholder `CloudOps`/`NewGRPC` from Task 1's `client/client.go` (overwrite the file)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type CloudOps interface` with methods `CreateServiceAccount(ctx, ServiceAccountSpec) (string, error)`, `GetServiceAccount(ctx, string) (*ServiceAccount, error)`, `UpdateServiceAccount(ctx, string, ServiceAccountSpec) error`, `DeleteServiceAccount(ctx, string) error`, `CreateAPIKey(ctx, APIKeySpec) (*APIKey, error)`, `DeleteAPIKey(ctx, string) error`, `CountAPIKeys(ctx, string) (int, error)`, `Close() error`
  - Types `ServiceAccountSpec{Name, Description string; AccountRole string; NamespaceAccess map[string]string}`, `ServiceAccount{ID, ResourceVersion string; Spec ServiceAccountSpec}`, `APIKeySpec{ServiceAccountID, DisplayName, Description string; ExpiryTime time.Time}`, `APIKey{ID, Token string}`
  - Errors `ErrNotFound`, `ErrPermissionDenied`, `ErrInvalidArgument`, `ErrResourceExhausted`, `ErrUnavailable`, and `func MapGRPCError(error) error`

- [ ] **Step 1: Write the failing test**

`client/errors_test.go`:

```go
package client

import (
	"errors"
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

Add `"strings"` to that file's imports.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./client/... -v`
Expected: FAIL — `undefined: MapGRPCError`.

- [ ] **Step 3: Write `client/errors.go`**

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

- [ ] **Step 4: Write `client/client.go`, replacing the placeholder**

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

- [ ] **Step 5: Fix `backend.go` for the real interface**

Task 1's adapter assigned `client.NewGRPC` with an `any` parameter. `NewGRPC` does not exist yet — Task 4 adds it. For now, leave `newClient` nil-valued by deleting the assignment line from `Backend()`, and add a comment:

```go
	// newClient is assigned in Task 4, once the gRPC implementation exists.
	// Until then it stays nil; no path calls it yet.
```

Delete `client/client.go`'s placeholder `NewGRPC` if you have not already (it was replaced wholesale in Step 4).

- [ ] **Step 6: Run the tests to verify they pass**

Run: `gofmt -w . && go mod tidy && go test ./... -v`
Expected: PASS — all `TestMapGRPCError*` tests and `TestBackend_Constructs`.

- [ ] **Step 7: Commit**

```bash
git add .
git commit -m "feat(client): add CloudOps interface and gRPC error mapping

Defines the seam between Vault logic and Temporal Cloud: plain-Go request and
response types, and sentinel errors that path handlers switch on without
importing grpc/codes."
```

---

### Task 3: Access parsing and validation

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

### Task 4: Async operation polling and the gRPC client

Implements `CloudOps` for real. This is the only file that touches gRPC.

**Files:**
- Create: `client/async.go`, `client/grpc.go`
- Modify: `backend.go` — restore the `newClient` assignment removed in Task 2
- Test: `client/async_test.go`

**Interfaces:**
- Consumes: everything from Tasks 2 and 3.
- Produces: `func NewGRPC(cfg Config) (CloudOps, error)`; `type Config struct{ APIKey, HostPort string }`; `type grpcClient struct` implementing `CloudOps`; `func awaitOperation(ctx context.Context, svc cloudservicev1.CloudServiceClient, op *operationv1.AsyncOperation) error`.

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

// Config is what NewGRPC needs to reach Temporal Cloud.
type Config struct {
	// APIKey is a Temporal Cloud API key owned by a service account with the
	// Global Admin role.
	APIKey string

	// HostPort overrides the Cloud Ops API address. Empty means the SDK
	// default, saas-api.tmprl.cloud:443.
	HostPort string
}

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

- [ ] **Step 6: Restore the client constructor in `backend.go`**

Replace the Task 2 placeholder comment in `Backend()` with the real assignment:

```go
	b.newClient = func(cfg *config) (client.CloudOps, error) {
		return client.NewGRPC(client.Config{
			APIKey:   cfg.APIKey,
			HostPort: cfg.Address,
		})
	}
```

`config.APIKey` and `config.Address` do not exist until Task 5. Keep the placeholder `config` struct compiling by giving it those two fields now, in `placeholders.go`:

```go
type config struct {
	APIKey  string
	Address string
}
```

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

### Task 5: The `config` path

Stores the root credential and validates it against Temporal Cloud on write.

**Files:**
- Create: `path_config.go`
- Delete: `placeholders.go`
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
	b.newClient = func(*config) (client.CloudOps, error) { return stub, nil }
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
	c, err := b.newClient(cfg)
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

Delete `placeholders.go`. Register the path:

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

	c, err := b.newClient(cfg)
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

### Task 6: `config/rotate-root`

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

	verifyClient, err := b.newClient(&newCfg)
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
