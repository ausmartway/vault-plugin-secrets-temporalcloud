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
