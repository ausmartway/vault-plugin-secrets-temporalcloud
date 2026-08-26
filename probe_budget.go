package temporalcloud

import (
	"context"
	"time"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

const (
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
		// Vault always sets a deadline; tests driving this helper directly do
		// not. Preserve the ceiling in that case so those tests exercise the
		// probe instead of silently skipping it.
		return client.MaxProbeTimeout, true
	}

	// credentialRequestContext has already placed this deadline five seconds
	// below the Vault API client's timeout. Subtracting another safety margin
	// here would double-count that delivery headroom.
	budget := time.Until(deadline)
	if budget < minUsefulProbeBudget {
		return 0, false
	}
	if budget > client.MaxProbeTimeout {
		budget = client.MaxProbeTimeout
	}
	return budget, true
}
