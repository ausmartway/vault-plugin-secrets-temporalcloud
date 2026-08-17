package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	cloudservicev1 "go.temporal.io/cloud-sdk/api/cloudservice/v1"
	resourcev1 "go.temporal.io/cloud-sdk/api/resource/v1"
)

// Every mutating Cloud Ops call in this package finishes by reading the
// resource back and checking it actually reached the state that was asked for,
// rather than trusting that the request was accepted and its async operation
// reported FULFILLED.
//
// Those two are not the same claim. An operation state describes the
// operation; it says nothing about when the resource plane caught up, and
// nothing about a resource that was changed out from under us in between. The
// gap is not hypothetical here: DeleteAPIKey already has to cope with a
// terminally FAILED operation that means "the key was already gone," which is
// the same seam viewed from the other side.
//
// What each failure would cost is why this is worth an extra call:
//
//   - A create reported as done whose resource is not yet readable hands back
//     an ID the very next call will fail on — CreateAPIKey against a service
//     account Temporal Cloud does not admit to having yet.
//   - A delete reported as done whose resource still exists is the dangerous
//     one. Vault drops the lease, the operator sees a clean revocation, and a
//     live Temporal Cloud credential stays valid with nothing tracking it.
//
// Deletion in particular cannot be confirmed by absence alone. Temporal Cloud
// models a removed resource as RESOURCE_STATE_DELETED, so a deleted service
// account or API key may still be readable — a check that only looked for
// NotFound would wait out its timeout on a delete that had in fact succeeded.
const (
	// confirmPollInterval is how often a read-back is retried while the
	// resource plane catches up.
	confirmPollInterval = 500 * time.Millisecond

	// confirmTimeout bounds a read-back. It is deliberately short: the
	// operation has already completed by this point, so this covers
	// propagation, not the work itself. Like operationTimeout it must leave
	// room under Vault's 90s default request timeout, and it may run after
	// awaitOperation has already spent time.
	confirmTimeout = 15 * time.Second
)

// awaitCondition polls check until it is satisfied, the caller's context ends,
// or confirmTimeout elapses.
//
// It evaluates check before sleeping, so a resource that is already consistent
// — the overwhelmingly common case — costs one call and no delay.
func awaitCondition(ctx context.Context, what string, check func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, confirmTimeout)
	defer cancel()

	for {
		satisfied, err := check(ctx)
		if err != nil {
			return err
		}
		if satisfied {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %s did not take effect within %s; temporal cloud "+
				"reported the operation complete but the resource does not reflect it",
				ErrUnavailable, what, confirmTimeout)
		case <-time.After(confirmPollInterval):
		}
	}
}

// failedState reports whether a resource is parked in one of Temporal Cloud's
// error states, which no amount of further polling will clear.
func failedState(state resourcev1.ResourceState) bool {
	switch state {
	case resourcev1.ResourceState_RESOURCE_STATE_ACTIVATION_FAILED,
		resourcev1.ResourceState_RESOURCE_STATE_UPDATE_FAILED,
		resourcev1.ResourceState_RESOURCE_STATE_DELETE_FAILED:
		return true
	default:
		return false
	}
}

// deletedState reports whether a resource has been removed. Both spellings
// count: gone entirely, or present and marked deleted.
func deletedState(state resourcev1.ResourceState) bool {
	return state == resourcev1.ResourceState_RESOURCE_STATE_DELETED
}

// The four predicates below are the single definition of "created" and "gone"
// for each resource. They are exposed separately from the polling wrappers
// because DeleteAPIKey needs to ask the question once, without waiting, on a
// path that has already failed — and asking it a different way there is how
// the DELETED-state case gets missed.

// serviceAccountPresent reports whether the service account is readable now.
func (c *grpcClient) serviceAccountPresent(ctx context.Context, id string) (bool, error) {
	resp, err := c.svc.GetServiceAccount(ctx, &cloudservicev1.GetServiceAccountRequest{
		ServiceAccountId: id,
	})
	if err != nil {
		mapped := MapGRPCError(err)
		// Not visible yet is the case the caller is waiting out.
		if errors.Is(mapped, ErrNotFound) {
			return false, nil
		}
		return false, mapped
	}

	sa := resp.GetServiceAccount()
	if sa == nil {
		return false, nil
	}
	if failedState(sa.GetState()) {
		return false, fmt.Errorf("%w: service account %s is in state %s",
			ErrInvalidArgument, id, sa.GetState())
	}
	if deletedState(sa.GetState()) {
		return false, fmt.Errorf("%w: service account %s was created but is already deleted",
			ErrNotFound, id)
	}
	return true, nil
}

// serviceAccountGone reports whether the service account is removed now.
func (c *grpcClient) serviceAccountGone(ctx context.Context, id string) (bool, error) {
	resp, err := c.svc.GetServiceAccount(ctx, &cloudservicev1.GetServiceAccountRequest{
		ServiceAccountId: id,
	})
	if err != nil {
		mapped := MapGRPCError(err)
		if errors.Is(mapped, ErrNotFound) {
			return true, nil
		}
		return false, mapped
	}

	sa := resp.GetServiceAccount()
	if sa == nil {
		return true, nil
	}
	if sa.GetState() == resourcev1.ResourceState_RESOURCE_STATE_DELETE_FAILED {
		return false, fmt.Errorf("%w: service account %s is in state %s",
			ErrInvalidArgument, id, sa.GetState())
	}
	return deletedState(sa.GetState()), nil
}

// apiKeyPresent reports whether the API key is readable now.
func (c *grpcClient) apiKeyPresent(ctx context.Context, id string) (bool, error) {
	resp, err := c.svc.GetApiKey(ctx, &cloudservicev1.GetApiKeyRequest{KeyId: id})
	if err != nil {
		mapped := MapGRPCError(err)
		if errors.Is(mapped, ErrNotFound) {
			return false, nil
		}
		return false, mapped
	}

	key := resp.GetApiKey()
	if key == nil {
		return false, nil
	}
	if failedState(key.GetState()) {
		return false, fmt.Errorf("%w: api key %s is in state %s",
			ErrInvalidArgument, id, key.GetState())
	}
	if deletedState(key.GetState()) {
		return false, fmt.Errorf("%w: api key %s was created but is already deleted",
			ErrNotFound, id)
	}
	return true, nil
}

// apiKeyGone reports whether the API key is removed now.
func (c *grpcClient) apiKeyGone(ctx context.Context, id string) (bool, error) {
	resp, err := c.svc.GetApiKey(ctx, &cloudservicev1.GetApiKeyRequest{KeyId: id})
	if err != nil {
		mapped := MapGRPCError(err)
		if errors.Is(mapped, ErrNotFound) {
			return true, nil
		}
		return false, mapped
	}

	key := resp.GetApiKey()
	if key == nil {
		return true, nil
	}
	if key.GetState() == resourcev1.ResourceState_RESOURCE_STATE_DELETE_FAILED {
		return false, fmt.Errorf("%w: api key %s is in state %s",
			ErrInvalidArgument, id, key.GetState())
	}
	return deletedState(key.GetState()), nil
}

// confirmServiceAccountExists blocks until the service account is readable.
func (c *grpcClient) confirmServiceAccountExists(ctx context.Context, id string) error {
	return awaitCondition(ctx, fmt.Sprintf("creation of service account %s", id),
		func(ctx context.Context) (bool, error) { return c.serviceAccountPresent(ctx, id) })
}

// confirmServiceAccountGone blocks until the service account is removed.
func (c *grpcClient) confirmServiceAccountGone(ctx context.Context, id string) error {
	return awaitCondition(ctx, fmt.Sprintf("deletion of service account %s", id),
		func(ctx context.Context) (bool, error) { return c.serviceAccountGone(ctx, id) })
}

// confirmAPIKeyExists blocks until the API key is readable.
func (c *grpcClient) confirmAPIKeyExists(ctx context.Context, id string) error {
	return awaitCondition(ctx, fmt.Sprintf("creation of api key %s", id),
		func(ctx context.Context) (bool, error) { return c.apiKeyPresent(ctx, id) })
}

// confirmAPIKeyGone blocks until the API key is removed. This is the check
// that matters most: a key reported as revoked but still live is a standing
// credential with no Vault lease tracking it.
func (c *grpcClient) confirmAPIKeyGone(ctx context.Context, id string) error {
	return awaitCondition(ctx, fmt.Sprintf("deletion of api key %s", id),
		func(ctx context.Context) (bool, error) { return c.apiKeyGone(ctx, id) })
}
