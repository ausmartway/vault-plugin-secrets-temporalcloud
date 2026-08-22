package client

import (
	"testing"

	"google.golang.org/grpc/codes"
)

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
