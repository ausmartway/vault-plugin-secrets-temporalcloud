package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	workflowservicev1 "go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Creating an API key and having every Temporal Cloud cell accept it are
// different events. CreateAPIKey confirms the first by reading the key back
// from the Cloud Ops API; this file confirms the second by asking a namespace
// frontend directly, authenticating as the new key.
//
// The distinction matters because an unpropagated key does not degrade
// gracefully on the caller's side. Temporal SDKs treat Unauthenticated and
// PermissionDenied as non-retryable and fail eagerly on the first connection,
// so a worker handed a key its cell has not seen yet dies at startup rather
// than backing off and recovering.
const (
	// MaxProbeTimeout is the ceiling on how long one namespace is given to
	// accept a new key. It is a ceiling, not a reservation: the caller derives
	// the real budget from the remaining request deadline, so a slow
	// CreateAPIKey shortens the probe instead of pushing the request past
	// Vault's timeout.
	MaxProbeTimeout = 55 * time.Second

	// probePollInterval is how often the probe re-asks. It is deliberately
	// slower than confirmPollInterval: that one polls at 500ms because it
	// expects to succeed almost immediately against a 15s ceiling, whereas
	// cross-cell propagation is a slower phenomenon on a much longer budget,
	// and polling a namespace frontend four times a second is pointless
	// chatter.
	probePollInterval = 2 * time.Second
)

// namespaceEndpoint builds the gRPC address for a namespace.
//
// Temporal Cloud's namespace ID is already "<namespace>.<account>", which is
// exactly the form the keys of a service account's namespace_access map take,
// so no account lookup is needed. The namespace endpoint is preferred over a
// regional one because it routes to whichever region is currently active,
// so a namespace with High Availability enabled needs no special handling.
func namespaceEndpoint(namespace string) string {
	return namespace + ".tmprl.cloud:7233"
}

// retryableProbeCode reports whether waiting could plausibly change the answer.
//
// A key that has not propagated yet and a key that will never be accepted both
// answer Unauthenticated or PermissionDenied, and nothing in the response
// distinguishes them. Both are retried: the cost of waiting out the budget on
// a namespace that will never accept the key is a slower response and a
// warning, while the cost of giving up early on one that would have accepted
// it is the false alarm this whole feature exists to prevent.
func retryableProbeCode(code codes.Code) bool {
	switch code {
	case codes.Unauthenticated, codes.PermissionDenied, codes.NotFound:
		// The propagation window itself.
		return true
	case codes.Unavailable, codes.DeadlineExceeded:
		// Ordinary transient failure reaching the frontend.
		return true
	default:
		return false
	}
}

// ProbeNamespace reports whether a namespace frontend accepts token and
// honours the grant it carries.
//
// It returns nil once DescribeNamespace succeeds, and an error if the context
// ends first or the frontend answers with something no amount of waiting will
// clear. Callers treat the error as advisory: this never decides whether a
// credential is issued.
//
// DescribeNamespace is used rather than the cheaper GetSystemInfo because what
// propagates across cells is not only the key but the key's permission set.
// GetSystemInfo would prove the frontend accepts the token; DescribeNamespace
// proves it also carries the namespace grant the caller was promised, which is
// what a worker actually needs.
func ProbeNamespace(ctx context.Context, token, namespace string) error {
	// Dial once and retry the RPC on this connection. gRPC carries the bearer
	// token as per-RPC metadata, so an authentication rejection does not
	// poison the channel — re-dialling per attempt would mean a fresh TLS
	// handshake every probePollInterval for no benefit.
	conn, err := grpc.NewClient(
		namespaceEndpoint(namespace),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})),
	)
	if err != nil {
		return fmt.Errorf("%w: dialling %s: %s", ErrUnavailable, namespace, err)
	}
	defer func() {
		// Close errors are not actionable: the probe is advisory and the
		// connection is being discarded either way.
		_ = conn.Close()
	}()

	svc := workflowservicev1.NewWorkflowServiceClient(conn)
	authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)

	var lastErr error
	for {
		_, err := svc.DescribeNamespace(authCtx, &workflowservicev1.DescribeNamespaceRequest{
			Namespace: namespace,
		})
		if err == nil {
			return nil
		}
		lastErr = err

		if code := status.Code(err); !retryableProbeCode(code) {
			// Not a propagation symptom — something else is wrong with the
			// request or the frontend. MapGRPCError sorts the code into the
			// right category instead of assuming a permission problem: an
			// Unimplemented from an RPC version mismatch is not the same
			// failure as a rejected grant, and callers above this package
			// (backend.go's respondCloudErr) give very different operator
			// guidance for each.
			return fmt.Errorf("probing %s: %w", namespace, MapGRPCError(err))
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %s did not accept the new api key in time; "+
				"the key may not have propagated to its cell yet, or the namespace "+
				"may not have API key authentication enabled (last response: %s)",
				ErrUnavailable, namespace, status.Convert(lastErr).Message())
		case <-time.After(probePollInterval):
		}
	}
}
