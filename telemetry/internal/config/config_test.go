package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/telemetry/internal/config"
)

const validTOML = `
[backend]
url = "wss://api.pmxcloud.example/ws/agent/telemetry"
ca_cert = "/etc/pmx-cloud/backend-ca.crt"

[identity]
cert = "/etc/pmx-cloud/pmx-telemetry/client.crt"
key  = "/etc/pmx-cloud/pmx-telemetry/client.key"

[keyset]
path = "/etc/pmx-cloud/keyset.pub"

[collection]
metrics_interval_seconds = 10
events_buffer_seconds    = 60

[features]
proxmox_status = true
`

func TestConfig_ParseValid(t *testing.T) {
	cfg, err := config.Parse([]byte(validTOML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Backend.URL == "" {
		t.Fatal("URL must not be empty")
	}
	if cfg.Collection.MetricsInterval().Seconds() != 10 {
		t.Fatalf("expected 10s interval")
	}
}

func TestConfig_RejectsInvalidScheme(t *testing.T) {
	bad := `
[backend]
url = "http://insecure"
`
	_, err := config.Parse([]byte(bad))
	if err == nil {
		t.Fatal("expected error for non-wss/ws")
	}
}

func TestConfig_RejectsUnknownKey(t *testing.T) {
	_, err := config.Parse([]byte(validTOML + "\n[bad]\nfoo=\"bar\"\n"))
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestConfig_Defaults(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.Collection.MetricsInterval().Seconds() != 10 {
		t.Fatal("expected 10s default interval")
	}
	if cfg.Collection.EventsBuffer().Seconds() != 60 {
		t.Fatal("expected 60s default buffer")
	}
}

func TestConfig_ExampleFileParses(t *testing.T) {
	data, err := os.ReadFile("../../pmx-telemetry.conf.example")
	if err != nil {
		t.Skip("example file not found (expected in repo root):", err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatalf("example file must parse cleanly: %v", err)
	}
	if !strings.HasPrefix(cfg.Backend.URL, "wss://") {
		t.Fatalf("backend.url must start with wss://, got %q", cfg.Backend.URL)
	}
	if cfg.Collection.MetricsIntervalSeconds != 15 {
		t.Fatalf("expected metrics_interval_seconds=15, got %d", cfg.Collection.MetricsIntervalSeconds)
	}
}
