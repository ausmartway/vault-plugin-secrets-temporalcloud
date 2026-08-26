package temporalcloud

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ausmartway/vault-plugin-secrets-temporalcloud/client"
)

const (
	probeConfigStoragePath = "probe-config"
	minProbeInterval       = 50 * time.Millisecond
	maxProbeInterval       = 5 * time.Second
	minProbeSuccesses      = 1
	maxProbeSuccesses      = 20
)

// probeConfig controls the mount's data-plane confirmation behavior. It is
// separate from config because changing probe load and latency must not require
// an operator to resubmit the root API key.
type probeConfig struct {
	Interval             time.Duration `json:"interval"`
	ConsecutiveSuccesses int           `json:"consecutive_successes"`
}

func defaultProbeConfig() *probeConfig {
	settings := client.DefaultProbeSettings()
	return &probeConfig{
		Interval:             settings.Interval,
		ConsecutiveSuccesses: settings.ConsecutiveSuccesses,
	}
}

func (c *probeConfig) clientSettings() client.ProbeSettings {
	return client.ProbeSettings{
		Interval:             c.Interval,
		ConsecutiveSuccesses: c.ConsecutiveSuccesses,
	}
}

func (b *backend) pathProbeConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config/probe",
		Fields: map[string]*framework.FieldSchema{
			"interval": {
				Type:        framework.TypeString,
				Default:     client.DefaultProbeInterval.String(),
				Description: "Delay between namespace probe attempts as a duration, for example 100ms. Minimum 50ms, maximum 5s.",
			},
			"consecutive_successes": {
				Type:        framework.TypeInt,
				Default:     client.DefaultProbeSuccesses,
				Description: "Number of consecutive successful checks required on fresh gRPC connections. Minimum 1, maximum 20.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathProbeConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathProbeConfigWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathProbeConfigRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathProbeConfigDelete},
		},
		ExistenceCheck:  b.probeConfigExists,
		HelpSynopsis:    "Configure namespace propagation probe sampling for this mount.",
		HelpDescription: pathProbeConfigHelp,
	}
}

func (b *backend) probeConfigExists(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, probeConfigStoragePath)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *backend) pathProbeConfigWrite(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	cfg, err := b.getProbeConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if _, set := d.Raw["interval"]; set {
		raw := strings.TrimSpace(d.Get("interval").(string))
		interval, err := time.ParseDuration(raw)
		if err != nil {
			return logical.ErrorResponse(
				"interval %q is not a valid duration; use a value such as 100ms or 1s", raw), nil
		}
		cfg.Interval = interval
	}
	if _, set := d.Raw["consecutive_successes"]; set {
		cfg.ConsecutiveSuccesses = d.Get("consecutive_successes").(int)
	}

	if err := validateProbeConfig(cfg); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	entry, err := logical.StorageEntryJSON(probeConfigStoragePath, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathProbeConfigRead(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	cfg, err := b.getProbeConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]interface{}{
		"interval":              cfg.Interval.String(),
		"consecutive_successes": cfg.ConsecutiveSuccesses,
	}}, nil
}

func (b *backend) pathProbeConfigDelete(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, probeConfigStoragePath); err != nil {
		return nil, err
	}
	return nil, nil
}

// getProbeConfig always returns effective settings. Missing storage means an
// existing mount upgraded without this path and therefore receives the current
// defaults without migration. Zero fields in a partial legacy entry do too.
func (b *backend) getProbeConfig(ctx context.Context, storage logical.Storage) (*probeConfig, error) {
	cfg := defaultProbeConfig()
	entry, err := storage.Get(ctx, probeConfigStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return cfg, nil
	}

	var stored probeConfig
	if err := entry.DecodeJSON(&stored); err != nil {
		return nil, fmt.Errorf("decoding probe config: %w", err)
	}
	if stored.Interval != 0 {
		cfg.Interval = stored.Interval
	}
	if stored.ConsecutiveSuccesses != 0 {
		cfg.ConsecutiveSuccesses = stored.ConsecutiveSuccesses
	}
	if err := validateProbeConfig(cfg); err != nil {
		return nil, fmt.Errorf("stored probe config is invalid: %w", err)
	}
	return cfg, nil
}

func validateProbeConfig(cfg *probeConfig) error {
	if cfg.Interval < minProbeInterval || cfg.Interval > maxProbeInterval {
		return fmt.Errorf("interval must be between %s and %s, got %s",
			minProbeInterval, maxProbeInterval, cfg.Interval)
	}
	if cfg.ConsecutiveSuccesses < minProbeSuccesses || cfg.ConsecutiveSuccesses > maxProbeSuccesses {
		return fmt.Errorf("consecutive_successes must be between %d and %d, got %d",
			minProbeSuccesses, maxProbeSuccesses, cfg.ConsecutiveSuccesses)
	}

	minimumWindow := time.Duration(cfg.ConsecutiveSuccesses-1) * cfg.Interval
	if minimumWindow >= client.MaxProbeTimeout {
		return fmt.Errorf("consecutive_successes and interval require a minimum confirmation window of %s, "+
			"which must be less than the %s probe budget", minimumWindow, client.MaxProbeTimeout)
	}
	return nil
}

const pathProbeConfigHelp = `
Configure how this mount verifies a newly minted API key against namespace
frontends. The settings apply to every service-accounts entry on the mount that
has verify_propagation enabled.

Each attempt uses a fresh gRPC connection. A failure resets the consecutive
success count. Updates merge: omit a field to retain its stored value. Delete
this path to restore the defaults.
`
