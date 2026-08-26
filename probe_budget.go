package temporalcloud

import (
	"context"
	"time"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

const (
	// probeSafetyMargin is held back from the request deadline so the probe
	// finishes and its warnings reach the caller, rather than Vault timing out
	// the request mid-probe.
	probeSafetyMargin = 5 * time.Second

	// minUsefulProbeBudget is the point below which probing is not worth
	// starting: one DescribeNamespace round trip would consume it.
	minUsefulProbeBudget = time.Second
)

// probeBudget reports how long the namespace probes may run, and whether
// running them at all is worthwhile.
//
// The budget is derived from the live deadline rather than fixed because the
// Cloud Ops calls above it have already consumed part of the end-to-end
// credential request budget. A fixed reservation could push the response past
// the Vault API client's timeout after the key has already been minted, leaving
// a live key with no lease. Deriving it makes MaxProbeTimeout a ceiling reached
// only when enough time actually remains, never a duration claimed up front.
func probeBudget(ctx context.Context) (time.Duration, bool) {
	deadline, ok := ctx.Deadline()
	if !ok {
		// Vault always sets a deadline; tests driving the backend directly do
		// not. Subtracting the margin from a zero deadline here would make
		// every such test skip the probe and pass without exercising it.
		return client.MaxProbeTimeout, true
	}

	budget := time.Until(deadline) - probeSafetyMargin
	if budget < minUsefulProbeBudget {
		return 0, false
	}
	if budget > client.MaxProbeTimeout {
		budget = client.MaxProbeTimeout
	}
	return budget, true
}
