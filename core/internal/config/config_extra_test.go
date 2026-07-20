package config_test

import (
	"testing"

	"github.com/pmx-cloud/agents/core/internal/config"
)

func TestConfig_EmptySiblings(t *testing.T) {
	toml := `
[backend]
url = "wss://api.example.com/ws/agent/core"
[siblings]
allowed = []
`
	_, err := config.Parse([]byte(toml))
	if err == nil {
		t.Fatal("expected error for empty siblings.allowed")
	}
}

func TestConfig_HeartbeatDefaults(t *testing.T) {
	cfg, err := config.Parse([]byte(validTOML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Heartbeat.IntervalSeconds != 15 {
		t.Fatalf("expected interval_seconds=15, got %d", cfg.Heartbeat.IntervalSeconds)
	}
	if cfg.Heartbeat.TimeoutSeconds != 45 {
		t.Fatalf("expected timeout_seconds=45, got %d", cfg.Heartbeat.TimeoutSeconds)
	}
}

func TestConfig_EphemeralTemplates(t *testing.T) {
	cfg, err := config.Parse([]byte(validTOML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Siblings.EphemeralTemplates) == 0 {
		t.Fatal("expected at least one ephemeral template")
	}
}

func TestConfig_RejectsExtraSection(t *testing.T) {
	_, err := config.Parse([]byte(validTOML + "\n[extra]\nfoo = \"bar\"\n"))
	if err == nil {
		t.Fatal("expected error for unknown config key")
	}
}

func TestConfig_ParseEmptyTOML(t *testing.T) {
	_, err := config.Parse([]byte(""))
	if err == nil {
		t.Fatal("expected error for empty TOML (missing required backend.url)")
	}
}
