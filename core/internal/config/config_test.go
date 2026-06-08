package config_test

import (
	"testing"

	"github.com/pmx-cloud/agents/core/internal/config"
)

const validTOML = `
[backend]
url = "wss://api.pmxcloud.example/ws/agent/core"
ca_cert = "/etc/pmx-cloud/backend-ca.crt"
auth_token = "pmxagent_example_token"

[identity]
cert = "/etc/pmx-cloud/pmx-core/client.crt"
key  = "/etc/pmx-cloud/pmx-core/client.key"
host_fingerprint_file = "/etc/pmx-cloud/host-fingerprint"

[keyset]
path = "/etc/pmx-cloud/keyset.pub"

[state]
dir = "/var/lib/pmx-cloud/core"

[siblings]
allowed = [
  "pmx-telemetry.service",
  "pmx-hypervisor.service",
]
ephemeral_templates = [
  "pmx-hardware-installer@.service",
]

[heartbeat]
interval_seconds = 15
timeout_seconds  = 45
`

func TestConfig_ParseValid(t *testing.T) {
	cfg, err := config.Parse([]byte(validTOML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Backend.URL != "wss://api.pmxcloud.example/ws/agent/core" {
		t.Fatalf("unexpected URL: %q", cfg.Backend.URL)
	}
	if cfg.Backend.AuthToken != "pmxagent_example_token" {
		t.Fatalf("unexpected auth token: %q", cfg.Backend.AuthToken)
	}
	if len(cfg.Siblings.Allowed) != 2 {
		t.Fatalf("expected 2 siblings, got %d", len(cfg.Siblings.Allowed))
	}
}

func TestConfig_RejectsInvalidScheme(t *testing.T) {
	bad := `
[backend]
url = "http://insecure/ws/agent/core"

[siblings]
allowed = ["pmx-telemetry.service"]
`
	_, err := config.Parse([]byte(bad))
	if err == nil {
		t.Fatal("expected error for non-wss/ws:// URL")
	}
}

func TestConfig_RejectsUnknownKey(t *testing.T) {
	bad := validTOML + "\n[unknown_section]\nfoo = \"bar\"\n"
	_, err := config.Parse([]byte(bad))
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestConfig_RejectsEmptySiblings(t *testing.T) {
	bad := `
[backend]
url = "wss://api.example/ws/agent/core"

[siblings]
allowed = []
`
	_, err := config.Parse([]byte(bad))
	if err == nil {
		t.Fatal("expected error for empty siblings list")
	}
}

func TestConfig_RejectsMissingURL(t *testing.T) {
	bad := `
[backend]
ca_cert = "/etc/pmx-cloud/backend-ca.crt"

[siblings]
allowed = ["pmx-telemetry.service"]
`
	_, err := config.Parse([]byte(bad))
	if err == nil {
		t.Fatal("expected error for missing URL")
	}
}

func TestConfig_HeartbeatDurations(t *testing.T) {
	cfg, err := config.Parse([]byte(validTOML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Heartbeat.HeartbeatInterval().Seconds() != 15 {
		t.Fatalf("expected 15s heartbeat interval")
	}
	if cfg.Heartbeat.HeartbeatTimeout().Seconds() != 45 {
		t.Fatalf("expected 45s heartbeat timeout")
	}
}

func TestConfig_DefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.Backend.URL == "" {
		t.Fatal("default config must have a backend URL")
	}
	if len(cfg.Siblings.Allowed) == 0 {
		t.Fatal("default config must have siblings")
	}
}
