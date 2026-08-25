// Command propagation-benchmark measures how long a newly created Temporal
// Cloud API key takes to become usable at a namespace frontend. It talks
// directly to Temporal Cloud and does not involve Vault.
package main

import (
	"context"
	"crypto/tls"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
	workflowservicev1 "go.temporal.io/api/workflowservice/v1"
	cloudservicev1 "go.temporal.io/cloud-sdk/api/cloudservice/v1"
	identityv1 "go.temporal.io/cloud-sdk/api/identity/v1"
	"go.temporal.io/cloud-sdk/cloudclient"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	cleanupTimeout  = 2 * time.Minute
	cleanupAttempts = 5
)

type config struct {
	namespace    string
	trials       int
	interval     time.Duration
	reportEvery  int
	pollInterval time.Duration
	trialTimeout time.Duration
	rpcTimeout   time.Duration
}

type result struct {
	trial       int
	startedAt   time.Time
	create      time.Duration
	propagation time.Duration
	total       time.Duration
	attempts    int
	lastCode    codes.Code
	cleanupErr  error
	err         error
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.namespace, "namespace", "vault-test.rgumq", "fully qualified Temporal Cloud namespace")
	flag.IntVar(&cfg.trials, "trials", 500, "number of sequential keys to benchmark")
	flag.DurationVar(&cfg.interval, "interval", time.Minute, "minimum interval between the start of consecutive trials (zero runs continuously)")
	flag.IntVar(&cfg.reportEvery, "report-every", 25, "write a rolling summary to stderr every N trials (zero disables)")
	flag.DurationVar(&cfg.pollInterval, "poll-interval", 100*time.Millisecond, "delay between DescribeNamespace attempts")
	flag.DurationVar(&cfg.trialTimeout, "timeout", 2*time.Minute, "maximum time per trial")
	flag.DurationVar(&cfg.rpcTimeout, "rpc-timeout", 5*time.Second, "maximum time for one DescribeNamespace call")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	apiKey := os.Getenv("TEMPORAL_CLOUD_API_KEY")
	if apiKey == "" {
		return errors.New("TEMPORAL_CLOUD_API_KEY is not set")
	}
	if cfg.namespace == "" || cfg.trials < 1 || cfg.interval < 0 || cfg.reportEvery < 0 ||
		cfg.pollInterval <= 0 || cfg.trialTimeout <= 0 || cfg.rpcTimeout <= 0 {
		return errors.New("namespace must be non-empty, counts and interval must not be negative, and trials and timeout durations must be greater than zero")
	}

	// SIGTERM is the normal way to stop a nohup/background run. Catch it as
	// well as Ctrl-C so both paths delete the temporary service account.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cloudConn, err := cloudclient.New(cloudclient.Options{
		APIKey:   apiKey,
		HostPort: os.Getenv("TEMPORAL_CLOUD_ADDRESS"),
	})
	if err != nil {
		return fmt.Errorf("connect to Cloud Ops API: %w", err)
	}
	defer func() { _ = cloudConn.Close() }()

	// Cleanup deliberately uses the repository client: it waits for the delete
	// operation and confirms the key is gone rather than trusting acceptance of
	// the deletion request.
	cleanupClient, err := client.NewGRPC(client.Config{
		APIKey:   apiKey,
		HostPort: os.Getenv("TEMPORAL_CLOUD_ADDRESS"),
	})
	if err != nil {
		return fmt.Errorf("create cleanup client: %w", err)
	}
	defer func() { _ = cleanupClient.Close() }()

	serviceAccountID, err := createBenchmarkServiceAccount(ctx, cleanupClient, cfg.namespace)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "created temporary service account %s for namespace %s\n",
		serviceAccountID, cfg.namespace)
	defer func() {
		if err := deleteServiceAccount(cleanupClient, serviceAccountID); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v; run make sweep or delete it manually\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "deleted temporary service account %s\n", serviceAccountID)
		}
	}()

	conn, err := grpc.NewClient(
		cfg.namespace+".tmprl.cloud:7233",
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})),
	)
	if err != nil {
		return fmt.Errorf("create namespace client: %w", err)
	}
	defer func() { _ = conn.Close() }()

	readyCtx, cancelReady := context.WithTimeout(ctx, 15*time.Second)
	err = waitForReady(readyCtx, conn)
	cancelReady()
	if err != nil {
		return fmt.Errorf("connect to namespace frontend: %w", err)
	}

	svc := workflowservicev1.NewWorkflowServiceClient(conn)
	results := make([]result, 0, cfg.trials)
	csvOut := csv.NewWriter(os.Stdout)
	if err := writeCSV(csvOut, []string{
		"trial", "started_at", "create_ms", "propagation_ms", "total_ms",
		"attempts", "last_code", "result",
	}); err != nil {
		return err
	}

	for trial := 1; trial <= cfg.trials; trial++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		trialStarted := time.Now()
		r := runTrial(ctx, cloudConn.CloudService(), cleanupClient, svc, cfg, serviceAccountID, trial)
		results = append(results, r)
		outcome := "accepted"
		if r.err != nil {
			outcome = r.err.Error()
		}
		if err := writeCSV(csvOut, []string{
			strconv.Itoa(r.trial),
			r.startedAt.Format(time.RFC3339Nano),
			strconv.FormatInt(r.create.Milliseconds(), 10),
			strconv.FormatInt(r.propagation.Milliseconds(), 10),
			strconv.FormatInt(r.total.Milliseconds(), 10),
			strconv.Itoa(r.attempts),
			r.lastCode.String(),
			outcome,
		}); err != nil {
			return err
		}

		if cfg.reportEvery > 0 && trial%cfg.reportEvery == 0 {
			printSummary(results)
		}
		if r.cleanupErr != nil {
			return fmt.Errorf("stopping after trial %d to avoid accumulating live keys: %w", trial, r.cleanupErr)
		}
		if trial < cfg.trials {
			if err := waitUntil(ctx, trialStarted.Add(cfg.interval)); err != nil {
				return err
			}
		}
	}

	printSummary(results)
	return nil
}

func runTrial(
	parent context.Context,
	cloudSvc cloudservicev1.CloudServiceClient,
	cleanupClient client.CloudOps,
	namespaceSvc workflowservicev1.WorkflowServiceClient,
	cfg config,
	serviceAccountID string,
	trial int,
) result {
	started := time.Now()
	trialCtx, cancel := context.WithTimeout(parent, cfg.trialTimeout)
	defer cancel()

	// Start the propagation clock at the raw CreateApiKey acknowledgment. The
	// plugin's client cannot be used here because it waits for the asynchronous
	// operation and a control-plane read-back, which could hide the delay this
	// command exists to measure.
	resp, createErr := cloudSvc.CreateApiKey(trialCtx, &cloudservicev1.CreateApiKeyRequest{
		Spec: &identityv1.ApiKeySpec{
			OwnerId:     serviceAccountID,
			OwnerType:   identityv1.OwnerType_OWNER_TYPE_SERVICE_ACCOUNT,
			DisplayName: fmt.Sprintf("propagation-benchmark-%d-%d", time.Now().UnixNano(), trial),
			Description: "Transient key created by propagation-benchmark",
			ExpiryTime:  timestamppb.New(time.Now().Add(client.MinAPIKeyExpiry + time.Hour)),
		},
	})
	createdAt := time.Now()
	var key *client.APIKey
	if resp != nil {
		key = &client.APIKey{ID: resp.GetKeyId(), Token: resp.GetToken()}
	}

	r := result{
		trial:     trial,
		startedAt: started.UTC(),
		create:    createdAt.Sub(started),
		total:     time.Since(started),
	}
	if createErr != nil {
		r.err = fmt.Errorf("create key: %w", createErr)
	} else if key == nil || key.ID == "" || key.Token == "" {
		r.err = errors.New("create key returned an incomplete key")
	} else {
		r.attempts, r.lastCode, r.err = waitForAcceptance(trialCtx, namespaceSvc, key.Token, cfg)
		r.propagation = time.Since(createdAt)
		r.total = time.Since(started)
	}

	// CreateAPIKey can return an ID with an error when the server accepted the
	// create but confirmation failed. Always clean up when an ID exists, and do
	// it before the next trial to stay well below the 20-key account limit.
	if key != nil && key.ID != "" {
		r.cleanupErr = deleteKey(cleanupClient, key.ID)
		if r.cleanupErr != nil {
			r.err = errors.Join(r.err, fmt.Errorf("cleanup: %w", r.cleanupErr))
		}
	} else if key != nil && key.Token != "" {
		// Without an ID there is no safe way to delete a token that may be live.
		// Stop the run instead of risking one unknown key per subsequent trial.
		r.cleanupErr = errors.New("created key has a token but no ID; inspect the service account before continuing")
		r.err = errors.Join(r.err, r.cleanupErr)
	}
	return r
}

func waitForAcceptance(ctx context.Context, svc workflowservicev1.WorkflowServiceClient, token string, cfg config) (int, codes.Code, error) {
	authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	attempts := 0
	lastCode := codes.OK

	for {
		attempts++
		rpcCtx, cancel := context.WithTimeout(authCtx, cfg.rpcTimeout)
		_, err := svc.DescribeNamespace(rpcCtx, &workflowservicev1.DescribeNamespaceRequest{
			Namespace: cfg.namespace,
		})
		cancel()
		if err == nil {
			return attempts, codes.OK, nil
		}
		lastCode = status.Code(err)

		switch lastCode {
		case codes.Unauthenticated, codes.PermissionDenied, codes.NotFound,
			codes.Unavailable, codes.DeadlineExceeded:
		default:
			return attempts, lastCode, fmt.Errorf("frontend stopped retrying after %s: %s", lastCode, status.Convert(err).Message())
		}

		timer := time.NewTimer(cfg.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return attempts, lastCode, fmt.Errorf("timeout after %s (last code %s)", cfg.trialTimeout, lastCode)
		case <-timer.C:
		}
	}
}

func waitForReady(ctx context.Context, conn *grpc.ClientConn) error {
	conn.Connect()
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return nil
		}
		if state == connectivity.Shutdown {
			return errors.New("connection shut down")
		}
		if !conn.WaitForStateChange(ctx, state) {
			return ctx.Err()
		}
	}
}

func createBenchmarkServiceAccount(ctx context.Context, cloudOps client.CloudOps, namespace string) (string, error) {
	name := fmt.Sprintf("vault-acctest-propagation-%d", time.Now().UnixNano())
	id, err := cloudOps.CreateServiceAccount(ctx, client.ServiceAccountSpec{
		Name:        name,
		Description: "Transient service account created by propagation-benchmark",
		// Keep account-wide access minimal. The explicit namespace grant below
		// is the permission whose propagation the benchmark needs to observe.
		AccountRole: "metrics-read",
		NamespaceAccess: map[string]string{
			namespace: "read",
		},
	})
	if err == nil {
		return id, nil
	}

	// CreateServiceAccount can return an ID when its asynchronous operation or
	// confirmation fails. Attempt cleanup before surfacing the failure.
	if id != "" {
		if cleanupErr := deleteServiceAccount(cloudOps, id); cleanupErr != nil {
			return "", errors.Join(fmt.Errorf("create temporary service account: %w", err), cleanupErr)
		}
	}
	return "", fmt.Errorf("create temporary service account: %w", err)
}

func deleteKey(cloudOps client.CloudOps, keyID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()

	var lastErr error
	for attempt := 1; attempt <= cleanupAttempts; attempt++ {
		err := cloudOps.DeleteAPIKey(ctx, keyID)
		if err == nil || errors.Is(err, client.ErrNotFound) {
			// DeleteAPIKey confirms deletion by reading the key back. A retry can
			// therefore find that an earlier attempt succeeded even when that
			// attempt's asynchronous response was lost; absent is the outcome the
			// cleanup needs, not a reason to stop an overnight run.
			return nil
		}
		lastErr = err

		timer := time.NewTimer(time.Duration(attempt) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("delete benchmark key %s: %w", keyID, errors.Join(lastErr, ctx.Err()))
		case <-timer.C:
		}
	}
	return fmt.Errorf("delete benchmark key %s after %d attempts: %w", keyID, cleanupAttempts, lastErr)
}

func deleteServiceAccount(cloudOps client.CloudOps, serviceAccountID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()

	var lastErr error
	for attempt := 1; attempt <= cleanupAttempts; attempt++ {
		if err := cloudOps.DeleteServiceAccount(ctx, serviceAccountID); err == nil {
			return nil
		} else {
			lastErr = err
		}

		timer := time.NewTimer(time.Duration(attempt) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("delete temporary service account %s: %w",
				serviceAccountID, errors.Join(lastErr, ctx.Err()))
		case <-timer.C:
		}
	}
	return fmt.Errorf("delete temporary service account %s after %d attempts: %w",
		serviceAccountID, cleanupAttempts, lastErr)
}

func waitUntil(ctx context.Context, when time.Time) error {
	delay := time.Until(when)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func writeCSV(w *csv.Writer, record []string) error {
	if err := w.Write(record); err != nil {
		return fmt.Errorf("write CSV output: %w", err)
	}
	// Flush every row so a machine interruption does not lose buffered samples
	// from a long overnight run.
	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("write CSV output: %w", err)
	}
	return nil
}

func printSummary(results []result) {
	accepted := make([]time.Duration, 0, len(results))
	for _, r := range results {
		if r.err == nil {
			accepted = append(accepted, r.propagation)
		}
	}
	if len(accepted) == 0 {
		fmt.Fprintf(os.Stderr, "no successful trials out of %d\n", len(results))
		return
	}

	sort.Slice(accepted, func(i, j int) bool { return accepted[i] < accepted[j] })
	fmt.Fprintf(os.Stderr, "after %d trials: accepted %d; propagation min=%s p50=%s p95=%s p99=%s max=%s\n",
		len(results), len(accepted), accepted[0], percentile(accepted, 0.50),
		percentile(accepted, 0.95), percentile(accepted, 0.99), accepted[len(accepted)-1])
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	index := int(float64(len(sorted)-1)*p + 0.5)
	return sorted[index]
}
