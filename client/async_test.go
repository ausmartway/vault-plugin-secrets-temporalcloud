package client

import (
	"errors"
	"strings"
	"testing"

	operationv1 "go.temporal.io/cloud-sdk/api/operation/v1"
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
