// Command sweep deletes Temporal Cloud service accounts left behind by failed
// acceptance test runs. Live tests create real resources, and a test that dies
// mid-flight cannot clean up after itself.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	cloudservicev1 "go.temporal.io/cloud-sdk/api/cloudservice/v1"
	"go.temporal.io/cloud-sdk/cloudclient"
)

// acctestPrefix must match the constant in acceptance_test.go.
const acctestPrefix = "vault-acctest-"

func main() {
	apiKey := os.Getenv("TEMPORAL_CLOUD_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "TEMPORAL_CLOUD_API_KEY is not set")
		os.Exit(1)
	}

	conn, err := cloudclient.New(cloudclient.Options{
		APIKey:   apiKey,
		HostPort: os.Getenv("TEMPORAL_CLOUD_ADDRESS"),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "connecting: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	ctx := context.Background()
	svc := conn.CloudService()

	swept := 0
	pageToken := ""

	for {
		resp, err := svc.GetServiceAccounts(ctx, &cloudservicev1.GetServiceAccountsRequest{
			PageSize:  100,
			PageToken: pageToken,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "listing service accounts: %v\n", err)
			os.Exit(1)
		}

		// Note the SINGULAR getter on a repeated field: the generated method is
		// GetServiceAccount(), not GetServiceAccounts(), even though it returns a
		// slice. Verified against cloud-sdk v0.16.0 with a live call.
		for _, sa := range resp.GetServiceAccount() {
			if !strings.HasPrefix(sa.GetSpec().GetName(), acctestPrefix) {
				continue
			}

			fmt.Printf("deleting %s (%s)\n", sa.GetSpec().GetName(), sa.GetId())

			if _, err := svc.DeleteServiceAccount(ctx, &cloudservicev1.DeleteServiceAccountRequest{
				ServiceAccountId: sa.GetId(),
				ResourceVersion:  sa.GetResourceVersion(),
			}); err != nil {
				fmt.Fprintf(os.Stderr, "  could not delete: %v\n", err)
				continue
			}
			swept++
		}

		nextPageToken := resp.GetNextPageToken()
		if nextPageToken == "" {
			break
		}
		// Same non-advancing-token guard used elsewhere (client/grpc.go): a
		// server that stops advancing would otherwise spin this loop forever.
		if nextPageToken == pageToken {
			fmt.Fprintln(os.Stderr, "GetServiceAccounts page token did not advance")
			os.Exit(1)
		}
		pageToken = nextPageToken
	}

	fmt.Printf("swept %d test service account(s)\n", swept)
}
