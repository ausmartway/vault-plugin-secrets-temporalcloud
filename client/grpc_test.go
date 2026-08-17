package client

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	cloudservicev1 "go.temporal.io/cloud-sdk/api/cloudservice/v1"
	identityv1 "go.temporal.io/cloud-sdk/api/identity/v1"
	operationv1 "go.temporal.io/cloud-sdk/api/operation/v1"
	resourcev1 "go.temporal.io/cloud-sdk/api/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeCloudServiceClient embeds the generated client interface without a
// value, so any method no test overrides panics loudly if called — the paths
// under test here reach only the three RPCs stubbed below. A test sets just
// the funcs its path needs; leaving the others nil is deliberate, so a call
// that should not happen fails the test instead of returning a zero value.
type fakeCloudServiceClient struct {
	cloudservicev1.CloudServiceClient
	getServiceAccountsFn func(ctx context.Context, req *cloudservicev1.GetServiceAccountsRequest) (*cloudservicev1.GetServiceAccountsResponse, error)
	getApiKeysFn         func(ctx context.Context, req *cloudservicev1.GetApiKeysRequest) (*cloudservicev1.GetApiKeysResponse, error)
	getAsyncOperationFn  func(ctx context.Context, req *cloudservicev1.GetAsyncOperationRequest) (*cloudservicev1.GetAsyncOperationResponse, error)
	getApiKeyFn          func(ctx context.Context, req *cloudservicev1.GetApiKeyRequest) (*cloudservicev1.GetApiKeyResponse, error)
	deleteApiKeyFn       func(ctx context.Context, req *cloudservicev1.DeleteApiKeyRequest) (*cloudservicev1.DeleteApiKeyResponse, error)
	createApiKeyFn       func(ctx context.Context, req *cloudservicev1.CreateApiKeyRequest) (*cloudservicev1.CreateApiKeyResponse, error)

	getServiceAccountFn    func(ctx context.Context, req *cloudservicev1.GetServiceAccountRequest) (*cloudservicev1.GetServiceAccountResponse, error)
	createServiceAccountFn func(ctx context.Context, req *cloudservicev1.CreateServiceAccountRequest) (*cloudservicev1.CreateServiceAccountResponse, error)
	deleteServiceAccountFn func(ctx context.Context, req *cloudservicev1.DeleteServiceAccountRequest) (*cloudservicev1.DeleteServiceAccountResponse, error)
}

func (f *fakeCloudServiceClient) GetServiceAccount(ctx context.Context, req *cloudservicev1.GetServiceAccountRequest, _ ...grpc.CallOption) (*cloudservicev1.GetServiceAccountResponse, error) {
	return f.getServiceAccountFn(ctx, req)
}

func (f *fakeCloudServiceClient) CreateServiceAccount(ctx context.Context, req *cloudservicev1.CreateServiceAccountRequest, _ ...grpc.CallOption) (*cloudservicev1.CreateServiceAccountResponse, error) {
	return f.createServiceAccountFn(ctx, req)
}

func (f *fakeCloudServiceClient) DeleteServiceAccount(ctx context.Context, req *cloudservicev1.DeleteServiceAccountRequest, _ ...grpc.CallOption) (*cloudservicev1.DeleteServiceAccountResponse, error) {
	return f.deleteServiceAccountFn(ctx, req)
}

// fulfilledOp is a terminal-successful async operation, so awaitOperation
// returns on its first check and the test is left exercising the read-back.
func fulfilledOp() *operationv1.AsyncOperation {
	return &operationv1.AsyncOperation{
		Id:    "op-1",
		State: operationv1.AsyncOperation_STATE_FULFILLED,
	}
}

func (f *fakeCloudServiceClient) GetApiKey(ctx context.Context, req *cloudservicev1.GetApiKeyRequest, _ ...grpc.CallOption) (*cloudservicev1.GetApiKeyResponse, error) {
	return f.getApiKeyFn(ctx, req)
}

func (f *fakeCloudServiceClient) DeleteApiKey(ctx context.Context, req *cloudservicev1.DeleteApiKeyRequest, _ ...grpc.CallOption) (*cloudservicev1.DeleteApiKeyResponse, error) {
	return f.deleteApiKeyFn(ctx, req)
}

func (f *fakeCloudServiceClient) CreateApiKey(ctx context.Context, req *cloudservicev1.CreateApiKeyRequest, _ ...grpc.CallOption) (*cloudservicev1.CreateApiKeyResponse, error) {
	return f.createApiKeyFn(ctx, req)
}

// failedOp is a terminal-failed async operation. Returning one directly on a
// mutation response means awaitOperation reaches its verdict on the first
// classifyOperationState call, with no poll and so no 1s ticker wait.
func failedOp() *operationv1.AsyncOperation {
	return &operationv1.AsyncOperation{
		Id:            "op-1",
		State:         operationv1.AsyncOperation_STATE_FAILED,
		FailureReason: "operation failed",
	}
}

func (f *fakeCloudServiceClient) GetServiceAccounts(ctx context.Context, req *cloudservicev1.GetServiceAccountsRequest, _ ...grpc.CallOption) (*cloudservicev1.GetServiceAccountsResponse, error) {
	return f.getServiceAccountsFn(ctx, req)
}

func (f *fakeCloudServiceClient) GetApiKeys(ctx context.Context, req *cloudservicev1.GetApiKeysRequest, _ ...grpc.CallOption) (*cloudservicev1.GetApiKeysResponse, error) {
	return f.getApiKeysFn(ctx, req)
}

func (f *fakeCloudServiceClient) GetAsyncOperation(ctx context.Context, req *cloudservicev1.GetAsyncOperationRequest, _ ...grpc.CallOption) (*cloudservicev1.GetAsyncOperationResponse, error) {
	return f.getAsyncOperationFn(ctx, req)
}

// TestFindServiceAccountByName_Found covers the ordinary match, including
// that the SINGULAR getter (GetServiceAccount, despite the plural field) is
// what carries the results.
func TestFindServiceAccountByName_Found(t *testing.T) {
	fake := &fakeCloudServiceClient{
		getServiceAccountsFn: func(context.Context, *cloudservicev1.GetServiceAccountsRequest) (*cloudservicev1.GetServiceAccountsResponse, error) {
			return &cloudservicev1.GetServiceAccountsResponse{
				ServiceAccount: []*identityv1.ServiceAccount{
					{Id: "sa-other", Spec: &identityv1.ServiceAccountSpec{Name: "other"}},
					{Id: "sa-match", Spec: &identityv1.ServiceAccountSpec{Name: "prod-workers"}},
				},
			}, nil
		},
	}
	c := &grpcClient{svc: fake}

	got, err := c.FindServiceAccountByName(context.Background(), "prod-workers")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "sa-match" {
		t.Errorf("expected sa-match, got %q", got.ID)
	}
}

// TestFindServiceAccountByName_NotFound covers exhausting every page with no
// match, which must return ErrNotFound rather than a generic error so the
// write path can distinguish "free to create" from "lookup broke."
func TestFindServiceAccountByName_NotFound(t *testing.T) {
	fake := &fakeCloudServiceClient{
		getServiceAccountsFn: func(context.Context, *cloudservicev1.GetServiceAccountsRequest) (*cloudservicev1.GetServiceAccountsResponse, error) {
			return &cloudservicev1.GetServiceAccountsResponse{
				ServiceAccount: []*identityv1.ServiceAccount{
					{Id: "sa-other", Spec: &identityv1.ServiceAccountSpec{Name: "other"}},
				},
			}, nil
		},
	}
	c := &grpcClient{svc: fake}

	_, err := c.FindServiceAccountByName(context.Background(), "prod-workers")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestFindServiceAccountByName_PagesThrough confirms a match on a later page
// is not missed just because the first page didn't have it.
func TestFindServiceAccountByName_PagesThrough(t *testing.T) {
	calls := 0
	fake := &fakeCloudServiceClient{
		getServiceAccountsFn: func(_ context.Context, req *cloudservicev1.GetServiceAccountsRequest) (*cloudservicev1.GetServiceAccountsResponse, error) {
			calls++
			if req.GetPageToken() == "" {
				return &cloudservicev1.GetServiceAccountsResponse{
					ServiceAccount: []*identityv1.ServiceAccount{
						{Id: "sa-1", Spec: &identityv1.ServiceAccountSpec{Name: "alpha"}},
					},
					NextPageToken: "page-2",
				}, nil
			}
			return &cloudservicev1.GetServiceAccountsResponse{
				ServiceAccount: []*identityv1.ServiceAccount{
					{Id: "sa-2", Spec: &identityv1.ServiceAccountSpec{Name: "prod-workers"}},
				},
			}, nil
		},
	}
	c := &grpcClient{svc: fake}

	got, err := c.FindServiceAccountByName(context.Background(), "prod-workers")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "sa-2" {
		t.Errorf("expected sa-2, got %q", got.ID)
	}
	if calls != 2 {
		t.Errorf("expected 2 pages fetched, got %d", calls)
	}
}

// TestFindServiceAccountByName_NonAdvancingPageToken guards against a server
// that returns the same next-page token forever, which would otherwise spin
// this loop with no bound but context cancellation.
func TestFindServiceAccountByName_NonAdvancingPageToken(t *testing.T) {
	fake := &fakeCloudServiceClient{
		getServiceAccountsFn: func(context.Context, *cloudservicev1.GetServiceAccountsRequest) (*cloudservicev1.GetServiceAccountsResponse, error) {
			return &cloudservicev1.GetServiceAccountsResponse{
				NextPageToken: "stuck",
			}, nil
		},
	}
	c := &grpcClient{svc: fake}

	_, err := c.FindServiceAccountByName(context.Background(), "prod-workers")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

// apiKeysInState builds n keys all sitting in the given resource state, for
// the CountAPIKeys tests below.
func apiKeysInState(n int, state resourcev1.ResourceState) []*identityv1.ApiKey {
	keys := make([]*identityv1.ApiKey, n)
	for i := range keys {
		keys[i] = &identityv1.ApiKey{
			Id:    fmt.Sprintf("apikey-%d", i),
			State: state,
		}
	}
	return keys
}

// TestCountAPIKeys_SinglePage covers the ordinary case, and pins that the
// request is scoped to the service account it was asked about — counting
// another owner's keys would silently misreport the ceiling.
func TestCountAPIKeys_SinglePage(t *testing.T) {
	var gotOwnerID string
	var gotOwnerType identityv1.OwnerType

	fake := &fakeCloudServiceClient{
		getApiKeysFn: func(_ context.Context, req *cloudservicev1.GetApiKeysRequest) (*cloudservicev1.GetApiKeysResponse, error) {
			gotOwnerID = req.GetOwnerId()
			gotOwnerType = req.GetOwnerType()
			return &cloudservicev1.GetApiKeysResponse{
				ApiKeys: apiKeysInState(3, resourcev1.ResourceState_RESOURCE_STATE_ACTIVE),
			}, nil
		},
	}
	c := &grpcClient{svc: fake}

	got, err := c.CountAPIKeys(context.Background(), "svcacct-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 3 {
		t.Errorf("expected 3, got %d", got)
	}
	if gotOwnerID != "svcacct-abc" {
		t.Errorf("expected the count scoped to svcacct-abc, got owner_id %q", gotOwnerID)
	}
	if gotOwnerType != identityv1.OwnerType_OWNER_TYPE_SERVICE_ACCOUNT {
		t.Errorf("expected owner type SERVICE_ACCOUNT, got %v", gotOwnerType)
	}
}

// TestCountAPIKeys_PagesThrough confirms keys on later pages are summed in.
// Missing them would UNDERcount, which is the dangerous direction: an
// undercount lets a mint slip past the 20-key ceiling and fail with a raw
// ResourceExhausted instead of this engine's actionable message.
func TestCountAPIKeys_PagesThrough(t *testing.T) {
	fake := &fakeCloudServiceClient{
		getApiKeysFn: func(_ context.Context, req *cloudservicev1.GetApiKeysRequest) (*cloudservicev1.GetApiKeysResponse, error) {
			if req.GetPageToken() == "" {
				return &cloudservicev1.GetApiKeysResponse{
					ApiKeys:       apiKeysInState(12, resourcev1.ResourceState_RESOURCE_STATE_ACTIVE),
					NextPageToken: "page-2",
				}, nil
			}
			return &cloudservicev1.GetApiKeysResponse{
				ApiKeys: apiKeysInState(8, resourcev1.ResourceState_RESOURCE_STATE_ACTIVE),
			}, nil
		},
	}
	c := &grpcClient{svc: fake}

	got, err := c.CountAPIKeys(context.Background(), "svcacct-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 20 {
		t.Errorf("expected 12+8=20, got %d", got)
	}
}

// TestCountAPIKeys_CountsNonActiveStates is the regression guard for the
// invariant documented on CountAPIKeys: never filter to RESOURCE_STATE_ACTIVE.
// A suspended key is not ACTIVE but still occupies one of the 20 slots — proved
// against a live account by TestLive_CountDisabledKey, which needs credentials
// and so does not run in CI. This pins the same rule in the fast suite, where a
// refactor that "helpfully" adds an ACTIVE filter would otherwise pass clean.
func TestCountAPIKeys_CountsNonActiveStates(t *testing.T) {
	// Every state a key can be parked in while still holding its slot.
	states := []resourcev1.ResourceState{
		resourcev1.ResourceState_RESOURCE_STATE_ACTIVE,
		resourcev1.ResourceState_RESOURCE_STATE_SUSPENDED,
		resourcev1.ResourceState_RESOURCE_STATE_ACTIVATING,
		resourcev1.ResourceState_RESOURCE_STATE_UPDATING,
		resourcev1.ResourceState_RESOURCE_STATE_UNSPECIFIED,
	}

	keys := make([]*identityv1.ApiKey, 0, len(states))
	for i, state := range states {
		keys = append(keys, &identityv1.ApiKey{Id: fmt.Sprintf("apikey-%d", i), State: state})
	}

	fake := &fakeCloudServiceClient{
		getApiKeysFn: func(context.Context, *cloudservicev1.GetApiKeysRequest) (*cloudservicev1.GetApiKeysResponse, error) {
			return &cloudservicev1.GetApiKeysResponse{ApiKeys: keys}, nil
		},
	}
	c := &grpcClient{svc: fake}

	got, err := c.CountAPIKeys(context.Background(), "svcacct-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != len(states) {
		t.Fatalf("expected all %d keys counted regardless of state, got %d — "+
			"CountAPIKeys must not filter on ApiKey.State (see its doc comment)",
			len(states), got)
	}
}

// TestCountAPIKeys_NonAdvancingPageToken guards the same spin-forever case as
// FindServiceAccountByName, but this one sits on the credential-issuing path,
// so failing loudly matters more.
func TestCountAPIKeys_NonAdvancingPageToken(t *testing.T) {
	fake := &fakeCloudServiceClient{
		getApiKeysFn: func(context.Context, *cloudservicev1.GetApiKeysRequest) (*cloudservicev1.GetApiKeysResponse, error) {
			return &cloudservicev1.GetApiKeysResponse{
				ApiKeys:       apiKeysInState(1, resourcev1.ResourceState_RESOURCE_STATE_ACTIVE),
				NextPageToken: "stuck",
			}, nil
		},
	}
	c := &grpcClient{svc: fake}

	got, err := c.CountAPIKeys(context.Background(), "svcacct-abc")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
	// The count must not be reported alongside an error — a partial count read
	// as a real one would undercount against the ceiling.
	if got != 0 {
		t.Errorf("expected a zero count on error, got %d", got)
	}
}

// TestCountAPIKeys_MapsTransportError confirms a gRPC status is translated into
// this package's sentinels rather than leaking a raw status up to the Vault
// handler, which switches on the sentinels to decide 400 vs 500.
func TestCountAPIKeys_MapsTransportError(t *testing.T) {
	fake := &fakeCloudServiceClient{
		getApiKeysFn: func(context.Context, *cloudservicev1.GetApiKeysRequest) (*cloudservicev1.GetApiKeysResponse, error) {
			return nil, status.Error(codes.PermissionDenied, "root key rejected")
		},
	}
	c := &grpcClient{svc: fake}

	_, err := c.CountAPIKeys(context.Background(), "svcacct-abc")
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
	if !strings.Contains(err.Error(), "root key rejected") {
		t.Errorf("expected Temporal Cloud's message preserved, got: %v", err)
	}
}

// A delete operation that lands terminally failed because the key was already
// gone must be reported as ErrNotFound, not as the generic ErrInvalidArgument
// every terminal failure maps to. secret_api_key.go treats only ErrNotFound as
// "revocation is done"; anything else makes Vault retry the lease revocation on
// its backoff schedule forever, which is precisely what that code's ErrNotFound
// branch exists to prevent.
func TestDeleteAPIKey_AlreadyGoneAfterFailedOperation(t *testing.T) {
	getCalls := 0
	fake := &fakeCloudServiceClient{
		getApiKeyFn: func(context.Context, *cloudservicev1.GetApiKeyRequest) (*cloudservicev1.GetApiKeyResponse, error) {
			getCalls++
			if getCalls == 1 {
				// The version fetch that precedes every delete.
				return &cloudservicev1.GetApiKeyResponse{
					ApiKey: &identityv1.ApiKey{Id: "apikey-1", ResourceVersion: "v1"},
				}, nil
			}
			// The re-check after the operation failed: deleted out of band.
			return nil, status.Error(codes.NotFound, "api key not found")
		},
		deleteApiKeyFn: func(context.Context, *cloudservicev1.DeleteApiKeyRequest) (*cloudservicev1.DeleteApiKeyResponse, error) {
			return &cloudservicev1.DeleteApiKeyResponse{AsyncOperation: failedOp()}, nil
		},
	}
	c := &grpcClient{svc: fake}

	err := c.DeleteAPIKey(context.Background(), "apikey-1")

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound so revocation counts as done, got %v", err)
	}
	if getCalls != 2 {
		t.Errorf("expected a re-check after the failed operation, got %d GetApiKey calls", getCalls)
	}
}

// The mirror image: if the key is still there after a failed delete operation,
// the failure is real and must stay an error, so Vault retries the revocation
// rather than dropping a lease whose credential is still live.
func TestDeleteAPIKey_StillPresentAfterFailedOperationStaysAnError(t *testing.T) {
	fake := &fakeCloudServiceClient{
		getApiKeyFn: func(context.Context, *cloudservicev1.GetApiKeyRequest) (*cloudservicev1.GetApiKeyResponse, error) {
			return &cloudservicev1.GetApiKeyResponse{
				ApiKey: &identityv1.ApiKey{Id: "apikey-1", ResourceVersion: "v1"},
			}, nil
		},
		deleteApiKeyFn: func(context.Context, *cloudservicev1.DeleteApiKeyRequest) (*cloudservicev1.DeleteApiKeyResponse, error) {
			return &cloudservicev1.DeleteApiKeyResponse{AsyncOperation: failedOp()}, nil
		},
	}
	c := &grpcClient{svc: fake}

	err := c.DeleteAPIKey(context.Background(), "apikey-1")

	if err == nil {
		t.Fatal("expected an error while the key still exists")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the original failure, not ErrNotFound, got %v", err)
	}
}

// CreateAPIKey must hand back what it minted even when the wait fails. The
// token is on this response only and is never retrievable again, so a caller
// that gets nothing back cannot delete the key, and it occupies one of the
// service account's twenty slots until it expires.
func TestCreateAPIKey_ReturnsKeyAlongsideAwaitError(t *testing.T) {
	fake := &fakeCloudServiceClient{
		createApiKeyFn: func(context.Context, *cloudservicev1.CreateApiKeyRequest) (*cloudservicev1.CreateApiKeyResponse, error) {
			return &cloudservicev1.CreateApiKeyResponse{
				KeyId:          "apikey-1",
				Token:          "tmprl_sk_real",
				AsyncOperation: failedOp(),
			}, nil
		},
	}
	c := &grpcClient{svc: fake}

	key, err := c.CreateAPIKey(context.Background(), APIKeySpec{
		ServiceAccountID: "svcacct-abc",
		ExpiryTime:       time.Now().Add(48 * time.Hour),
	})

	if err == nil {
		t.Fatal("expected the await failure to surface as an error")
	}
	if key == nil {
		t.Fatal("expected the minted key to be returned so the caller can delete it")
	}
	if key.ID != "apikey-1" {
		t.Errorf("expected the key id to survive, got %q", key.ID)
	}
}

// specFromProto must never silently render an unrecognised account role or
// namespace permission as an empty string: an empty AccountRole reads exactly
// like "no role configured," which is a worse failure mode than a visibly odd
// value. This covers ROLE_UNSPECIFIED and PERMISSION_UNSPECIFIED, the case
// accountRoleFromProto/namespacePermissionFromProto (client/access.go) return
// "" for today, and stands in for any future role/permission Temporal Cloud
// adds before this engine's lookup tables catch up.
func TestSpecFromProto_UnmappedRoleAndPermission(t *testing.T) {
	p := &identityv1.ServiceAccountSpec{
		Name:        "svc",
		Description: "test",
		Access: &identityv1.Access{
			AccountAccess: &identityv1.AccountAccess{
				Role: identityv1.AccountAccess_ROLE_UNSPECIFIED,
			},
			NamespaceAccesses: map[string]*identityv1.NamespaceAccess{
				"prod.acct1": {
					Permission: identityv1.NamespaceAccess_PERMISSION_UNSPECIFIED,
				},
			},
		},
	}

	spec := specFromProto(p)

	if spec.AccountRole == "" {
		t.Fatal("expected a non-empty sentinel for an unmapped account role, got empty string")
	}
	if !strings.Contains(spec.AccountRole, "unmapped") {
		t.Fatalf("expected the sentinel to flag itself as unmapped, got %q", spec.AccountRole)
	}

	perm := spec.NamespaceAccess["prod.acct1"]
	if perm == "" {
		t.Fatal("expected a non-empty sentinel for an unmapped namespace permission, got empty string")
	}
	if !strings.Contains(perm, "unmapped") {
		t.Fatalf("expected the sentinel to flag itself as unmapped, got %q", perm)
	}
}
