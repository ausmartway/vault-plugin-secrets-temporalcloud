package client

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cloudservicev1 "go.temporal.io/cloud-sdk/api/cloudservice/v1"
	operationv1 "go.temporal.io/cloud-sdk/api/operation/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestClassifyOperationState(t *testing.T) {
	tests := []struct {
		name      string
		state     operationv1.AsyncOperation_State
		wantDone  bool
		wantErrIs error
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

// The tests below drive awaitOperation itself — the polling loop wrapped around
// classifyOperationState. Every mutating Cloud Ops call goes through it, so its
// terminal conditions are worth pinning in the fast suite rather than only
// observing them incidentally during a live run.
//
// Two notes on how they stay quick. First, the ones that must actually see a
// poll cost one operationPollInterval per tick, so they call t.Parallel() and
// overlap instead of running back to back. Second, the timeout test does not
// wait out operationTimeout: awaitOperation derives its deadline from the
// caller's context, and context.WithTimeout keeps whichever deadline lands
// first, so a short parent deadline reaches the same ctx.Done() branch in
// milliseconds.

func pendingOp(id string) *operationv1.AsyncOperation {
	return &operationv1.AsyncOperation{Id: id, State: operationv1.AsyncOperation_STATE_PENDING}
}

// A terminal operation on the create response is the common case — the write
// already finished server-side. awaitOperation must return without a poll at
// all, since a needless round trip on every mutating call is pure latency.
func TestAwaitOperation_AlreadyFulfilledDoesNotPoll(t *testing.T) {
	polls := 0
	fake := &fakeCloudServiceClient{
		getAsyncOperationFn: func(context.Context, *cloudservicev1.GetAsyncOperationRequest) (*cloudservicev1.GetAsyncOperationResponse, error) {
			polls++
			return nil, nil
		},
	}

	op := &operationv1.AsyncOperation{Id: "op-1", State: operationv1.AsyncOperation_STATE_FULFILLED}

	if err := awaitOperation(context.Background(), fake, op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if polls != 0 {
		t.Errorf("expected no poll for an already-terminal operation, got %d", polls)
	}
}

// Likewise for a nil operation: nothing to wait for, nothing to poll.
func TestAwaitOperation_NilOperationDoesNotPoll(t *testing.T) {
	polls := 0
	fake := &fakeCloudServiceClient{
		getAsyncOperationFn: func(context.Context, *cloudservicev1.GetAsyncOperationRequest) (*cloudservicev1.GetAsyncOperationResponse, error) {
			polls++
			return nil, nil
		},
	}

	if err := awaitOperation(context.Background(), fake, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if polls != 0 {
		t.Errorf("expected no poll for a nil operation, got %d", polls)
	}
}

// An operation that comes back already failed must surface that immediately
// rather than polling a doomed operation until the timeout.
func TestAwaitOperation_AlreadyFailedReturnsImmediately(t *testing.T) {
	polls := 0
	fake := &fakeCloudServiceClient{
		getAsyncOperationFn: func(context.Context, *cloudservicev1.GetAsyncOperationRequest) (*cloudservicev1.GetAsyncOperationResponse, error) {
			polls++
			return nil, nil
		},
	}

	op := &operationv1.AsyncOperation{
		Id:            "op-1",
		State:         operationv1.AsyncOperation_STATE_FAILED,
		FailureReason: "namespace prod.acct1 does not exist",
	}

	err := awaitOperation(context.Background(), fake, op)

	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if polls != 0 {
		t.Errorf("expected no poll for an already-failed operation, got %d", polls)
	}
}

// The loop's happy path: keep polling while the operation is pending, return
// once it reaches FULFILLED. This also pins that the poll asks about the
// operation it was given — polling the wrong id would either hang or report
// some other operation's outcome as this one's.
func TestAwaitOperation_PollsUntilFulfilled(t *testing.T) {
	t.Parallel()

	polls := 0
	var gotID string

	fake := &fakeCloudServiceClient{
		getAsyncOperationFn: func(_ context.Context, req *cloudservicev1.GetAsyncOperationRequest) (*cloudservicev1.GetAsyncOperationResponse, error) {
			polls++
			gotID = req.GetAsyncOperationId()

			state := operationv1.AsyncOperation_STATE_IN_PROGRESS
			if polls >= 2 {
				state = operationv1.AsyncOperation_STATE_FULFILLED
			}
			return &cloudservicev1.GetAsyncOperationResponse{
				AsyncOperation: &operationv1.AsyncOperation{Id: "op-1", State: state},
			}, nil
		},
	}

	if err := awaitOperation(context.Background(), fake, pendingOp("op-1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if polls != 2 {
		t.Errorf("expected 2 polls (in-progress then fulfilled), got %d", polls)
	}
	if gotID != "op-1" {
		t.Errorf("expected the poll to name op-1, got %q", gotID)
	}
}

// An operation that fails partway through must report Temporal Cloud's reason.
// This is the path that surfaces things like a bad namespace in a service
// account spec, where the create call itself returned OK.
func TestAwaitOperation_PollReportsFailure(t *testing.T) {
	t.Parallel()

	fake := &fakeCloudServiceClient{
		getAsyncOperationFn: func(context.Context, *cloudservicev1.GetAsyncOperationRequest) (*cloudservicev1.GetAsyncOperationResponse, error) {
			return &cloudservicev1.GetAsyncOperationResponse{
				AsyncOperation: &operationv1.AsyncOperation{
					Id:            "op-1",
					State:         operationv1.AsyncOperation_STATE_FAILED,
					FailureReason: "namespace prod.acct1 does not exist",
				},
			}, nil
		},
	}

	err := awaitOperation(context.Background(), fake, pendingOp("op-1"))

	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if !strings.Contains(err.Error(), "namespace prod.acct1 does not exist") {
		t.Errorf("expected the failure reason in the error, got: %v", err)
	}
}

// A transport failure on the poll must come back as one of this package's
// sentinels, not a raw gRPC status: the Vault handlers switch on the sentinels
// to decide whether the operator sees a 400 or a 500.
func TestAwaitOperation_PollTransportErrorIsMapped(t *testing.T) {
	t.Parallel()

	fake := &fakeCloudServiceClient{
		getAsyncOperationFn: func(context.Context, *cloudservicev1.GetAsyncOperationRequest) (*cloudservicev1.GetAsyncOperationResponse, error) {
			return nil, status.Error(codes.Unavailable, "backend down")
		},
	}

	err := awaitOperation(context.Background(), fake, pendingOp("op-1"))

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "backend down") {
		t.Errorf("expected Temporal Cloud's message preserved, got: %v", err)
	}
}

// A poll that comes back with no operation must be an error, not success.
// classifyOperationState reads a nil operation as "done, no error", which is
// right for a create response (the server reported nothing to wait for) and
// wrong here (we asked about an id we know exists). Treating it as success
// would let CreateAPIKey return a token for a key whose provisioning was never
// confirmed, and Vault would store a lease against it.
func TestAwaitOperation_NilOperationFromPollIsAnError(t *testing.T) {
	t.Parallel()

	fake := &fakeCloudServiceClient{
		getAsyncOperationFn: func(context.Context, *cloudservicev1.GetAsyncOperationRequest) (*cloudservicev1.GetAsyncOperationResponse, error) {
			// An empty response — the shape a server returns when it has
			// nothing to say about the id.
			return &cloudservicev1.GetAsyncOperationResponse{}, nil
		},
	}

	err := awaitOperation(context.Background(), fake, pendingOp("op-1"))

	if err == nil {
		t.Fatal("expected an error when the poll reports no operation")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "op-1") {
		t.Errorf("expected the operation id in the error, got: %v", err)
	}
}

// An operation that never reaches a terminal state must give up rather than
// block until Vault times out the request underneath us — the whole reason
// operationTimeout sits below Vault's 90s default. The error is ErrUnavailable
// (retryable, a 500) rather than a user error, because a stuck operation is
// infrastructure, not something the operator wrote wrong.
//
// The short parent deadline is what keeps this fast; see the note above.
func TestAwaitOperation_TimesOutWhileStillPending(t *testing.T) {
	t.Parallel()

	fake := &fakeCloudServiceClient{
		getAsyncOperationFn: func(context.Context, *cloudservicev1.GetAsyncOperationRequest) (*cloudservicev1.GetAsyncOperationResponse, error) {
			return &cloudservicev1.GetAsyncOperationResponse{
				AsyncOperation: pendingOp("op-1"),
			}, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := awaitOperation(ctx, fake, pendingOp("op-1"))
	elapsed := time.Since(start)

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "op-1") {
		t.Errorf("expected the operation id in the timeout error, got: %v", err)
	}
	// Guards the mechanism, not just the outcome: if awaitOperation ever stopped
	// deriving its deadline from the caller's context, this would sit here for
	// the full operationTimeout and the assertion would say why.
	if elapsed >= operationTimeout {
		t.Errorf("expected the caller's deadline to win, but waited %s", elapsed)
	}
}
