package temporalcloud

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

// verifyPropagation waits for every namespace the entry grants to accept the
// newly minted key, and reports what did not confirm.
//
// It returns warnings rather than an error on purpose. A key that has not
// reached a cell yet is not a bad key, so failing the request would turn a slow
// cell into an outage for the whole entry and would have to delete a perfectly
// good credential to avoid orphaning it. The value of this check is in the
// waiting, which usually succeeds; the warning is what is left when it does not.
func (b *backend) verifyPropagation(
	ctx context.Context,
	entry *serviceAccountEntry,
	token string,
	settings client.ProbeSettings,
) []string {
	if len(entry.NamespaceAccess) == 0 {
		// An entry whose reach comes from account_role alone has nothing to
		// probe. Reporting that is more honest than returning silently, which
		// would read as "verified".
		return []string{
			"verify_propagation is enabled but this entry grants no namespace_access, " +
				"so nothing was verified. Account-level roles reach namespaces that are not " +
				"listed here, and this engine has no way to enumerate them.",
		}
	}

	budget, ok := probeBudget(ctx)
	if !ok {
		return []string{
			"verify_propagation is enabled but too little of the credential request budget " +
				"remained to check anything, so the key was returned unverified. Earlier " +
				"Cloud Ops calls consumed the available time; retry with a new credential.",
		}
	}

	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var (
		mu       sync.Mutex
		warnings []string
		wg       sync.WaitGroup
	)

	for namespace := range entry.NamespaceAccess {
		wg.Add(1)
		go func(namespace string) {
			defer wg.Done()

			if err := b.probeNamespace(ctx, token, namespace, settings); err != nil {
				mu.Lock()
				warnings = append(warnings, fmt.Sprintf(
					"namespace %s did not confirm the new API key: %s. The key was still "+
						"returned; a worker using it may be rejected until Temporal Cloud "+
						"finishes distributing it.", namespace, err))
				mu.Unlock()
			}
		}(namespace)
	}

	// Every namespace is waited on rather than cancelling at the first
	// failure: they are already running concurrently, and an operator needs
	// the full list of which cells are behind, not whichever failed first.
	wg.Wait()

	sort.Strings(warnings) // stable output regardless of goroutine scheduling
	return warnings
}
