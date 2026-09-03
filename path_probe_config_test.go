package temporalcloud

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestProbeConfigDefaultsWithoutStoredEntry(t *testing.T) {
	b, storage := newTestBackend(t)
	resp := readProbeConfig(t, b, storage)

	if got := resp.Data["interval"]; got != "50ms" {
		t.Fatalf("interval = %v, want 50ms", got)
	}
	if got := resp.Data["consecutive_successes"]; got != 10 {
		t.Fatalf("consecutive_successes = %v, want 10", got)
	}
}

func TestProbeConfigUpdateMergesFields(t *testing.T) {
	b, storage := newTestBackend(t)
	writeProbeConfig(t, b, storage, map[string]interface{}{
		"interval":              "250ms",
		"consecutive_successes": 8,
	})
	writeProbeConfig(t, b, storage, map[string]interface{}{
		"interval": "500ms",
	})

	resp := readProbeConfig(t, b, storage)
	if got := resp.Data["interval"]; got != "500ms" {
		t.Errorf("interval = %v, want 500ms", got)
	}
	if got := resp.Data["consecutive_successes"]; got != 8 {
		t.Errorf("consecutive_successes = %v after unrelated update, want 8", got)
	}
}

func TestProbeConfigDeleteRestoresDefaults(t *testing.T) {
	b, storage := newTestBackend(t)
	writeProbeConfig(t, b, storage, map[string]interface{}{
		"interval":              "1s",
		"consecutive_successes": 7,
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/probe",
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("delete config/probe: err=%v resp=%v", err, resp)
	}

	got := readProbeConfig(t, b, storage)
	if got.Data["interval"] != "50ms" || got.Data["consecutive_successes"] != 10 {
		t.Fatalf("settings after delete = %v, want defaults", got.Data)
	}
}

func TestProbeConfigRejectsInvalidSettings(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]interface{}
		message string
	}{
		{"malformed interval", map[string]interface{}{"interval": "quickly"}, "valid duration"},
		{"interval too short", map[string]interface{}{"interval": "49ms"}, "between 50ms and 5s"},
		{"interval too long", map[string]interface{}{"interval": "6s"}, "between 50ms and 5s"},
		{"no successes", map[string]interface{}{"consecutive_successes": 0}, "between 1 and 20"},
		{"too many successes", map[string]interface{}{"consecutive_successes": 21}, "between 1 and 20"},
		{
			"minimum window exhausts budget",
			map[string]interface{}{"interval": "5s", "consecutive_successes": 20},
			"minimum confirmation window",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := newTestBackend(t)
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config/probe",
				Storage:   storage,
				Data:      tc.data,
			})
			if err != nil {
				t.Fatalf("write config/probe: %v", err)
			}
			if resp == nil || !resp.IsError() {
				t.Fatalf("expected an error response, got %v", resp)
			}
			if msg := resp.Error().Error(); !strings.Contains(msg, tc.message) {
				t.Fatalf("error = %q, want it to contain %q", msg, tc.message)
			}
		})
	}
}

func TestProbeConfigRejectedUpdatePreservesStoredSettings(t *testing.T) {
	b, storage := newTestBackend(t)
	writeProbeConfig(t, b, storage, map[string]interface{}{
		"interval":              "300ms",
		"consecutive_successes": 7,
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/probe",
		Storage:   storage,
		Data:      map[string]interface{}{"interval": "10ms"},
	})
	if err != nil || resp == nil || !resp.IsError() {
		t.Fatalf("invalid update: err=%v resp=%v", err, resp)
	}

	got := readProbeConfig(t, b, storage)
	if got.Data["interval"] != "300ms" || got.Data["consecutive_successes"] != 7 {
		t.Fatalf("settings after rejected update = %v", got.Data)
	}
}

func TestGetProbeConfigFillsMissingLegacyFields(t *testing.T) {
	b, storage := newTestBackend(t)
	entry, err := logical.StorageEntryJSON(probeConfigStoragePath, &probeConfig{
		Interval: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	cfg, err := b.getProbeConfig(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interval != 300*time.Millisecond || cfg.ConsecutiveSuccesses != 10 {
		t.Fatalf("effective legacy config = %+v", cfg)
	}
}

func writeProbeConfig(t *testing.T, b *backend, storage logical.Storage, data map[string]interface{}) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/probe",
		Storage:   storage,
		Data:      data,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write config/probe: err=%v resp=%v", err, resp)
	}
}

func readProbeConfig(t *testing.T, b *backend, storage logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/probe",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read config/probe: err=%v resp=%v", err, resp)
	}
	return resp
}
