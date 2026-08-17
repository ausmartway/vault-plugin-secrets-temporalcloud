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

			// A nil operation means something different here than it does on
			// the create response. There it means the server reported no
			// operation, so there is nothing to wait for. Here we asked about
			// an id we know exists and were told nothing, and
			// classifyOperationState reads nil as "done, no error" — which
			// would report a mutation complete that was never confirmed. For
			// CreateAPIKey that means handing out a token for a key whose
			// provisioning is unknown, and storing a Vault lease against it.
			polled := resp.GetAsyncOperation()
			if polled == nil {
				return fmt.Errorf("%w: temporal cloud reported no operation for %s",
					ErrUnavailable, operationID)
			}

			done, err := classifyOperationState(polled)
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
