package client

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cloudservicev1 "go.temporal.io/cloud-sdk/api/cloudservice/v1"
	identityv1 "go.temporal.io/cloud-sdk/api/identity/v1"
	resourcev1 "go.temporal.io/cloud-sdk/api/resource/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// notFound is what Temporal Cloud returns for a resource that no longer exists.
func notFound() error {
	return status.Error(codes.NotFound, "not found")
}

func apiKeyInState(id string, state resourcev1.ResourceState) *cloudservicev1.GetApiKeyResponse {
	return &cloudservicev1.GetApiKeyResponse{
		ApiKey: &identityv1.ApiKey{Id: id, ResourceVersion: "v1", State: state},
	}
}

func serviceAccountInState(id string, state resourcev1.ResourceState) *cloudservicev1.GetServiceAccountResponse {
	return &cloudservicev1.GetServiceAccountResponse{
		ServiceAccount: &identityv1.ServiceAccount{Id: id, ResourceVersion: "v1", State: state},
	}
}

// The check this whole file exists for. Temporal Cloud accepts the delete and
// reports the operation FULFILLED, but the key is still there. Without a
// read-back DeleteAPIKey returns nil, secret_api_key.go drops the Vault lease,
// and a live Temporal Cloud credential is left with nothing tracking it and no
// record that it was ever issued.
func TestDeleteAPIKey_FailsWhenKeySurvivesAFulfilledDelete(t *testing.T) {
	t.Parallel()

	fake := &fakeCloudServiceClient{
		getApiKeyFn: func(context.Context, *cloudservicev1.GetApiKeyRequest) (*cloudservicev1.GetApiKeyResponse, error) {
			// Still active, before and after the "successful" delete.
			return apiKeyInState("apikey-1", resourcev1.ResourceState_RESOURCE_STATE_ACTIVE), nil
		},
		deleteApiKeyFn: func(context.Context, *cloudservicev1.DeleteApiKeyRequest) (*cloudservicev1.DeleteApiKeyResponse, error) {
			return &cloudservicev1.DeleteApiKeyResponse{AsyncOperation: fulfilledOp()}, nil
		},
	}
	c := &grpcClient{svc: fake}

	// The caller's deadline bounds the read-back, so this does not sit here for
	// the full confirmTimeout.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := c.DeleteAPIKey(ctx, "apikey-1")

	if err == nil {
		t.Fatal("expected an error when the key is still present after a fulfilled delete")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("expected ErrUnavailable so the revocation is retried, got %v", err)
	}
	if !errors.Is(err, ErrNotFound) && strings.Contains(err.Error(), "already deleted") {
		t.Error("a surviving key must never be reported as already deleted")
	}
}

// A deleted resource may still be readable, carrying RESOURCE_STATE_DELETED
// rather than vanishing. That must count as gone, or every successful delete
// would wait out its timeout and report failure.
func TestDeleteAPIKey_AcceptsDeletedState(t *testing.T) {
	t.Parallel()

	calls := 0
	fake := &fakeCloudServiceClient{
		getApiKeyFn: func(context.Context, *cloudservicev1.GetApiKeyRequest) (*cloudservicev1.GetApiKeyResponse, error) {
			calls++
			if calls == 1 {
				// The version fetch that precedes the delete.
				return apiKeyInState("apikey-1", resourcev1.ResourceState_RESOURCE_STATE_ACTIVE), nil
			}
			return apiKeyInState("apikey-1", resourcev1.ResourceState_RESOURCE_STATE_DELETED), nil
		},
		deleteApiKeyFn: func(context.Context, *cloudservicev1.DeleteApiKeyRequest) (*cloudservicev1.DeleteApiKeyResponse, error) {
			return &cloudservicev1.DeleteApiKeyResponse{AsyncOperation: fulfilledOp()}, nil
		},
	}
	c := &grpcClient{svc: fake}

	if err := c.DeleteAPIKey(context.Background(), "apikey-1"); err != nil {
		t.Fatalf("expected RESOURCE_STATE_DELETED to count as gone, got %v", err)
	}
	if calls < 2 {
		t.Errorf("expected the delete to be confirmed by a read-back, got %d GetApiKey calls", calls)
	}
}

// The ordinary case: the key vanishes entirely.
func TestDeleteAPIKey_AcceptsNotFound(t *testing.T) {
	t.Parallel()

	calls := 0
	fake := &fakeCloudServiceClient{
		getApiKeyFn: func(context.Context, *cloudservicev1.GetApiKeyRequest) (*cloudservicev1.GetApiKeyResponse, error) {
			calls++
			if calls == 1 {
				return apiKeyInState("apikey-1", resourcev1.ResourceState_RESOURCE_STATE_ACTIVE), nil
			}
			return nil, notFound()
		},
		deleteApiKeyFn: func(context.Context, *cloudservicev1.DeleteApiKeyRequest) (*cloudservicev1.DeleteApiKeyResponse, error) {
			return &cloudservicev1.DeleteApiKeyResponse{AsyncOperation: fulfilledOp()}, nil
		},
	}
	c := &grpcClient{svc: fake}

	if err := c.DeleteAPIKey(context.Background(), "apikey-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A key mid-deletion when first read must be waited out rather than reported
// as a failure — the point of polling rather than checking once.
func TestDeleteAPIKey_WaitsForDeletionToPropagate(t *testing.T) {
	t.Parallel()

	calls := 0
	fake := &fakeCloudServiceClient{
		getApiKeyFn: func(context.Context, *cloudservicev1.GetApiKeyRequest) (*cloudservicev1.GetApiKeyResponse, error) {
			calls++
			switch calls {
			case 1:
				return apiKeyInState("apikey-1", resourcev1.ResourceState_RESOURCE_STATE_ACTIVE), nil
			case 2:
				return apiKeyInState("apikey-1", resourcev1.ResourceState_RESOURCE_STATE_DELETING), nil
			default:
				return nil, notFound()
			}
		},
		deleteApiKeyFn: func(context.Context, *cloudservicev1.DeleteApiKeyRequest) (*cloudservicev1.DeleteApiKeyResponse, error) {
			return &cloudservicev1.DeleteApiKeyResponse{AsyncOperation: fulfilledOp()}, nil
		},
	}
	c := &grpcClient{svc: fake}

	if err := c.DeleteAPIKey(context.Background(), "apikey-1"); err != nil {
		t.Fatalf("expected DELETING to be waited out, got %v", err)
	}
	if calls != 3 {
		t.Errorf("expected the read-back to poll past DELETING, got %d GetApiKey calls", calls)
	}
}

// DELETE_FAILED is terminal. Polling it to the timeout would turn an
// actionable answer into a generic one, so it fails immediately and says so.
func TestDeleteAPIKey_FailsFastOnDeleteFailed(t *testing.T) {
	t.Parallel()

	fake := &fakeCloudServiceClient{
		getApiKeyFn: func(context.Context, *cloudservicev1.GetApiKeyRequest) (*cloudservicev1.GetApiKeyResponse, error) {
			return apiKeyInState("apikey-1", resourcev1.ResourceState_RESOURCE_STATE_DELETE_FAILED), nil
		},
		deleteApiKeyFn: func(context.Context, *cloudservicev1.DeleteApiKeyRequest) (*cloudservicev1.DeleteApiKeyResponse, error) {
			return &cloudservicev1.DeleteApiKeyResponse{AsyncOperation: fulfilledOp()}, nil
		},
	}
	c := &grpcClient{svc: fake}

	start := time.Now()
	err := c.DeleteAPIKey(context.Background(), "apikey-1")

	if err == nil {
		t.Fatal("expected DELETE_FAILED to be an error")
	}
	if !strings.Contains(err.Error(), "DELETE_FAILED") {
		t.Errorf("expected the error to name the state, got: %v", err)
	}
	if elapsed := time.Since(start); elapsed > confirmTimeout/2 {
		t.Errorf("expected an immediate failure, waited %s", elapsed)
	}
}

// The same guarantee for service accounts. Deleting one invalidates every API
// key it owns, so a delete reported as done but not actually applied leaves
// the caller believing a whole set of credentials is dead when none of them is.
func TestDeleteServiceAccount_FailsWhenAccountSurvives(t *testing.T) {
	t.Parallel()

	fake := &fakeCloudServiceClient{
		getServiceAccountFn: func(context.Context, *cloudservicev1.GetServiceAccountRequest) (*cloudservicev1.GetServiceAccountResponse, error) {
			return serviceAccountInState("sa-1", resourcev1.ResourceState_RESOURCE_STATE_ACTIVE), nil
		},
		deleteServiceAccountFn: func(context.Context, *cloudservicev1.DeleteServiceAccountRequest) (*cloudservicev1.DeleteServiceAccountResponse, error) {
			return &cloudservicev1.DeleteServiceAccountResponse{AsyncOperation: fulfilledOp()}, nil
		},
	}
	c := &grpcClient{svc: fake}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := c.DeleteServiceAccount(ctx, "sa-1")

	if err == nil {
		t.Fatal("expected an error when the service account is still present")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("expected ErrUnavailable, got %v", err)
	}
}

func TestDeleteServiceAccount_AcceptsDeletedState(t *testing.T) {
	t.Parallel()

	calls := 0
	fake := &fakeCloudServiceClient{
		getServiceAccountFn: func(context.Context, *cloudservicev1.GetServiceAccountRequest) (*cloudservicev1.GetServiceAccountResponse, error) {
			calls++
			if calls == 1 {
				return serviceAccountInState("sa-1", resourcev1.ResourceState_RESOURCE_STATE_ACTIVE), nil
			}
			return serviceAccountInState("sa-1", resourcev1.ResourceState_RESOURCE_STATE_DELETED), nil
		},
		deleteServiceAccountFn: func(context.Context, *cloudservicev1.DeleteServiceAccountRequest) (*cloudservicev1.DeleteServiceAccountResponse, error) {
			return &cloudservicev1.DeleteServiceAccountResponse{AsyncOperation: fulfilledOp()}, nil
		},
	}
	c := &grpcClient{svc: fake}

	if err := c.DeleteServiceAccount(context.Background(), "sa-1"); err != nil {
		t.Fatalf("expected RESOURCE_STATE_DELETED to count as gone, got %v", err)
	}
}

// A create that reports success but whose resource is not readable hands back
// an ID the caller will immediately store and mint keys against.
func TestCreateServiceAccount_FailsWhenAccountNeverAppears(t *testing.T) {
	t.Parallel()

	fake := &fakeCloudServiceClient{
		createServiceAccountFn: func(context.Context, *cloudservicev1.CreateServiceAccountRequest) (*cloudservicev1.CreateServiceAccountResponse, error) {
			return &cloudservicev1.CreateServiceAccountResponse{
				ServiceAccountId: "sa-1",
				AsyncOperation:   fulfilledOp(),
			}, nil
		},
		getServiceAccountFn: func(context.Context, *cloudservicev1.GetServiceAccountRequest) (*cloudservicev1.GetServiceAccountResponse, error) {
			return nil, notFound()
		},
	}
	c := &grpcClient{svc: fake}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	id, err := c.CreateServiceAccount(ctx, ServiceAccountSpec{Name: "sa", AccountRole: "read"})

	if err == nil {
		t.Fatal("expected an error when the created account is not readable")
	}
	// The ID must still come back so the caller can clean up what may exist.
	if id != "sa-1" {
		t.Errorf("expected the id to be returned alongside the error, got %q", id)
	}
}

// An account that becomes readable a moment later is fine — that is what the
// read-back is waiting for.
func TestCreateServiceAccount_WaitsForAccountToAppear(t *testing.T) {
	t.Parallel()

	calls := 0
	fake := &fakeCloudServiceClient{
		createServiceAccountFn: func(context.Context, *cloudservicev1.CreateServiceAccountRequest) (*cloudservicev1.CreateServiceAccountResponse, error) {
			return &cloudservicev1.CreateServiceAccountResponse{
				ServiceAccountId: "sa-1",
				AsyncOperation:   fulfilledOp(),
			}, nil
		},
		getServiceAccountFn: func(context.Context, *cloudservicev1.GetServiceAccountRequest) (*cloudservicev1.GetServiceAccountResponse, error) {
			calls++
			if calls == 1 {
				return nil, notFound()
			}
			return serviceAccountInState("sa-1", resourcev1.ResourceState_RESOURCE_STATE_ACTIVE), nil
		},
	}
	c := &grpcClient{svc: fake}

	id, err := c.CreateServiceAccount(context.Background(), ServiceAccountSpec{Name: "sa", AccountRole: "read"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "sa-1" {
		t.Errorf("expected sa-1, got %q", id)
	}
	if calls != 2 {
		t.Errorf("expected the read-back to poll until visible, got %d calls", calls)
	}
}

// ACTIVATION_FAILED will never clear, so it must not be polled to the timeout.
func TestCreateServiceAccount_FailsFastOnActivationFailed(t *testing.T) {
	t.Parallel()

	fake := &fakeCloudServiceClient{
		createServiceAccountFn: func(context.Context, *cloudservicev1.CreateServiceAccountRequest) (*cloudservicev1.CreateServiceAccountResponse, error) {
			return &cloudservicev1.CreateServiceAccountResponse{
				ServiceAccountId: "sa-1",
				AsyncOperation:   fulfilledOp(),
			}, nil
		},
		getServiceAccountFn: func(context.Context, *cloudservicev1.GetServiceAccountRequest) (*cloudservicev1.GetServiceAccountResponse, error) {
			return serviceAccountInState("sa-1", resourcev1.ResourceState_RESOURCE_STATE_ACTIVATION_FAILED), nil
		},
	}
	c := &grpcClient{svc: fake}

	start := time.Now()
	_, err := c.CreateServiceAccount(context.Background(), ServiceAccountSpec{Name: "sa", AccountRole: "read"})

	if err == nil {
		t.Fatal("expected ACTIVATION_FAILED to be an error")
	}
	if !strings.Contains(err.Error(), "ACTIVATION_FAILED") {
		t.Errorf("expected the error to name the state, got: %v", err)
	}
	if elapsed := time.Since(start); elapsed > confirmTimeout/2 {
		t.Errorf("expected an immediate failure, waited %s", elapsed)
	}
}

// A minted key whose token is handed out must be one Temporal Cloud admits to
// having: a lease over an unusable credential fails at the workload, far from
// here, with nothing pointing back at this call.
func TestCreateAPIKey_FailsWhenKeyNeverAppears(t *testing.T) {
	t.Parallel()

	fake := &fakeCloudServiceClient{
		createApiKeyFn: func(context.Context, *cloudservicev1.CreateApiKeyRequest) (*cloudservicev1.CreateApiKeyResponse, error) {
			return &cloudservicev1.CreateApiKeyResponse{
				KeyId:          "apikey-1",
				Token:          "tmprl_sk_real",
				AsyncOperation: fulfilledOp(),
			}, nil
		},
		getApiKeyFn: func(context.Context, *cloudservicev1.GetApiKeyRequest) (*cloudservicev1.GetApiKeyResponse, error) {
			return nil, notFound()
		},
	}
	c := &grpcClient{svc: fake}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	key, err := c.CreateAPIKey(ctx, APIKeySpec{
		ServiceAccountID: "sa-1",
		ExpiryTime:       time.Now().Add(48 * time.Hour),
	})

	if err == nil {
		t.Fatal("expected an error when the minted key is not readable")
	}
	// Returned anyway, so the caller can delete what may exist.
	if key == nil || key.ID != "apikey-1" {
		t.Errorf("expected the key to be returned alongside the error, got %+v", key)
	}
}

func TestCreateAPIKey_ConfirmsKeyBeforeReturning(t *testing.T) {
	t.Parallel()

	confirmed := false
	fake := &fakeCloudServiceClient{
		createApiKeyFn: func(context.Context, *cloudservicev1.CreateApiKeyRequest) (*cloudservicev1.CreateApiKeyResponse, error) {
			return &cloudservicev1.CreateApiKeyResponse{
				KeyId:          "apikey-1",
				Token:          "tmprl_sk_real",
				AsyncOperation: fulfilledOp(),
			}, nil
		},
		getApiKeyFn: func(_ context.Context, req *cloudservicev1.GetApiKeyRequest) (*cloudservicev1.GetApiKeyResponse, error) {
			if req.GetKeyId() == "apikey-1" {
				confirmed = true
			}
			return apiKeyInState("apikey-1", resourcev1.ResourceState_RESOURCE_STATE_ACTIVE), nil
		},
	}
	c := &grpcClient{svc: fake}

	key, err := c.CreateAPIKey(context.Background(), APIKeySpec{
		ServiceAccountID: "sa-1",
		ExpiryTime:       time.Now().Add(48 * time.Hour),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.Token != "tmprl_sk_real" {
		t.Errorf("expected the token to survive confirmation, got %q", key.Token)
	}
	if !confirmed {
		t.Error("expected the minted key to be read back before being returned")
	}
}

// A resource that is already in the wanted state must cost one call and no
// delay. Sleeping first would put confirmPollInterval on the floor of every
// credential issue and every revocation.
func TestAwaitCondition_DoesNotSleepWhenAlreadySatisfied(t *testing.T) {
	t.Parallel()

	calls := 0
	start := time.Now()

	err := awaitCondition(context.Background(), "thing", func(context.Context) (bool, error) {
		calls++
		return true, nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected exactly one check, got %d", calls)
	}
	if elapsed := time.Since(start); elapsed >= confirmPollInterval {
		t.Errorf("expected no delay for an already-satisfied condition, took %s", elapsed)
	}
}

// A transport failure during a read-back is not evidence either way, so it
// must surface rather than be read as "not yet" and polled to the timeout.
func TestAwaitCondition_PropagatesCheckErrors(t *testing.T) {
	t.Parallel()

	err := awaitCondition(context.Background(), "thing", func(context.Context) (bool, error) {
		return false, errors.New("boom")
	})

	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected the check's error to surface, got %v", err)
	}
}
