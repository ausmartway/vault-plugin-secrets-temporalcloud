package client

import (
	"context"
	"errors"
	"testing"
	"time"

	workflowservicev1 "go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestProbePollInterval(t *testing.T) {
	if probePollInterval != 100*time.Millisecond {
		t.Fatalf("probePollInterval = %s, want 100ms", probePollInterval)
	}
	if requiredProbeSuccesses != 5 {
		t.Fatalf("requiredProbeSuccesses = %d, want 5", requiredProbeSuccesses)
	}
}

func TestNamespaceEndpoint(t *testing.T) {
	// The namespace_access map key is already <namespace>.<account>, which is
	// exactly what the Temporal Cloud namespace endpoint is built from.
	got := namespaceEndpoint("prod.acct1")
	want := "prod.acct1.tmprl.cloud:7233"
	if got != want {
		t.Fatalf("namespaceEndpoint(%q) = %q, want %q", "prod.acct1", got, want)
	}
}

// A key that has not propagated and a key that will never be accepted answer
// identically, so the classification is about whether waiting could plausibly
// help — not about whether the error looks permanent.
func TestRetryableProbeCode(t *testing.T) {
	tests := []struct {
		name string
		code codes.Code
		want bool
	}{
		{"not propagated yet", codes.Unauthenticated, true},
		{"grant not propagated yet", codes.PermissionDenied, true},
		{"namespace not visible yet", codes.NotFound, true},
		{"transient", codes.Unavailable, true},
		{"transient deadline", codes.DeadlineExceeded, true},
		{"malformed request", codes.InvalidArgument, false},
		{"broken invariant", codes.Internal, false},
		{"not supported", codes.Unimplemented, false},
		{"success is not a retry", codes.OK, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryableProbeCode(tc.code); got != tc.want {
				t.Fatalf("retryableProbeCode(%v) = %v, want %v", tc.code, got, tc.want)
			}
		})
	}
}

type fakeProbeConnection struct {
	closed        bool
	method        string
	namespace     string
	authorization string
	err           error
}

func (c *fakeProbeConnection) Invoke(
	ctx context.Context,
	method string,
	args, _ interface{},
	_ ...grpc.CallOption,
) error {
	c.method = method
	if req, ok := args.(*workflowservicev1.DescribeNamespaceRequest); ok {
		c.namespace = req.GetNamespace()
	}
	if md, ok := metadata.FromOutgoingContext(ctx); ok {
		values := md.Get("authorization")
		if len(values) > 0 {
			c.authorization = values[0]
		}
	}
	return c.err
}

func (c *fakeProbeConnection) NewStream(
	context.Context,
	*grpc.StreamDesc,
	string,
	...grpc.CallOption,
) (grpc.ClientStream, error) {
	return nil, errors.New("unexpected streaming RPC")
}

func (c *fakeProbeConnection) Close() error {
	c.closed = true
	return nil
}

func TestProbeNamespaceRequiresThreeFreshConnections(t *testing.T) {
	var connections []*fakeProbeConnection
	dial := func(endpoint string) (probeConnection, error) {
		if endpoint != "prod.acct1.tmprl.cloud:7233" {
			t.Fatalf("dial endpoint = %q", endpoint)
		}
		for i, previous := range connections {
			if !previous.closed {
				t.Fatalf("connection %d was still open when the next attempt dialled", i+1)
			}
		}
		conn := &fakeProbeConnection{}
		connections = append(connections, conn)
		return conn, nil
	}

	err := probeNamespaceUntilConfirmed(
		context.Background(),
		"new-token",
		"prod.acct1",
		time.Nanosecond,
		func(ctx context.Context, token, namespace string) error {
			return probeNamespaceOnce(ctx, token, namespace, dial)
		},
	)
	if err != nil {
		t.Fatalf("probeNamespaceUntilConfirmed: %v", err)
	}
	if len(connections) != requiredProbeSuccesses {
		t.Fatalf("dialled %d connections, want %d", len(connections), requiredProbeSuccesses)
	}
	for i, conn := range connections {
		if !conn.closed {
			t.Errorf("connection %d was not closed before the next confirmation", i+1)
		}
		if conn.method != workflowservicev1.WorkflowService_DescribeNamespace_FullMethodName {
			t.Errorf("connection %d called %q", i+1, conn.method)
		}
		if conn.namespace != "prod.acct1" {
			t.Errorf("connection %d namespace = %q", i+1, conn.namespace)
		}
		if conn.authorization != "Bearer new-token" {
			t.Errorf("connection %d authorization = %q", i+1, conn.authorization)
		}
	}
}

func TestProbeNamespaceRetryableFailureResetsSuccesses(t *testing.T) {
	responses := []error{
		nil,
		status.Error(codes.PermissionDenied, "not propagated everywhere"),
		nil,
		nil,
		nil,
		nil,
		nil,
	}
	calls := 0

	err := probeNamespaceUntilConfirmed(
		context.Background(), "new-token", "prod.acct1", time.Nanosecond,
		func(context.Context, string, string) error {
			err := responses[calls]
			calls++
			return err
		},
	)
	if err != nil {
		t.Fatalf("probeNamespaceUntilConfirmed: %v", err)
	}
	if calls != len(responses) {
		t.Fatalf("made %d attempts, want %d; a failure must reset the success count", calls, len(responses))
	}
}
