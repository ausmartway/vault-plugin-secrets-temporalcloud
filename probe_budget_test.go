package temporalcloud

import (
	"context"
	"testing"
	"time"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

func TestProbeBudget(t *testing.T) {
	tests := []struct {
		name         string
		deadlineLeft time.Duration // 0 means "no deadline on the context"
		wantOK       bool
		wantAtMost   time.Duration
		wantAtLeast  time.Duration
	}{
		{
			// Vault always sets a deadline, but tests driving the backend
			// directly do not. Without this branch every unit test would
			// silently skip the probe and pass while testing nothing.
			name:         "no deadline uses the ceiling",
			deadlineLeft: 0,
			wantOK:       true,
			wantAtLeast:  client.MaxProbeTimeout,
			wantAtMost:   client.MaxProbeTimeout,
		},
		{
			// The common case: the stages above the probe were fast, so the
			// full ceiling is available.
			name:         "plenty of room yields the ceiling",
			deadlineLeft: 87 * time.Second,
			wantOK:       true,
			wantAtLeast:  client.MaxProbeTimeout - time.Second,
			wantAtMost:   client.MaxProbeTimeout,
		},
		{
			// A representative eight-second key creation leaves about 47 seconds
			// of the 55-second end-to-end budget. The probe must use that remainder,
			// not add its 50-second ceiling on top of the elapsed creation time.
			name:         "eight-second creation leaves about 47 seconds",
			deadlineLeft: credentialRequestTimeout - 8*time.Second,
			wantOK:       true,
			wantAtLeast:  46 * time.Second,
			wantAtMost:   47 * time.Second,
		},
		{
			// Earlier Cloud Ops work consumes the same end-to-end budget. The
			// probe gets exactly what remains because the enclosing credential
			// deadline already reserves delivery headroom.
			name:         "little room yields what is left",
			deadlineLeft: 15 * time.Second,
			wantOK:       true,
			wantAtLeast:  14 * time.Second,
			wantAtMost:   15 * time.Second,
		},
		{
			// The key is already minted. Starting a network call with less than
			// one second left risks reaching the deadline before warnings can be
			// assembled, so skip rather than gamble.
			name:         "no room means do not probe",
			deadlineLeft: 500 * time.Millisecond,
			wantOK:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.deadlineLeft > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.deadlineLeft)
				defer cancel()
			}

			got, ok := probeBudget(ctx)
			if ok != tc.wantOK {
				t.Fatalf("probeBudget ok = %v, want %v (budget %s)", ok, tc.wantOK, got)
			}
			if !tc.wantOK {
				return
			}
			if got < tc.wantAtLeast || got > tc.wantAtMost {
				t.Fatalf("probeBudget = %s, want between %s and %s",
					got, tc.wantAtLeast, tc.wantAtMost)
			}
		})
	}
}
