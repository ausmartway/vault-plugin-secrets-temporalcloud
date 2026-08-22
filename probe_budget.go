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
// The budget is derived from the live deadline rather than fixed, because by
// this point the request has already spent up to operationTimeout awaiting the
// async operation and up to confirmTimeout on the read-back — 75s of Vault's
// 90s default between them. A fixed reservation would spend headroom those
// stages may already have consumed, and a request Vault kills after the key is
// minted leaves that key with no lease, alive until its Temporal Cloud expiry
// of at least 24 hours. Deriving it means MaxProbeTimeout is a ceiling reached
// when the stages above ran fast, never a duration claimed up front.
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
