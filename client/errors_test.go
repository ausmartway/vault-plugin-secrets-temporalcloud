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
