package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pmx-cloud/agents/core/internal/config"
)

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pmx-core.conf")
	if err := os.WriteFile(path, []byte(validTOML), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Backend.URL == "" {
		t.Fatal("URL must not be empty")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := config.Load("/no/such/file/pmx-core.conf")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.conf")
	os.WriteFile(path, []byte("not toml [[["), 0o600)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

func TestHeartbeatInterval_DefaultWhenZero(t *testing.T) {
	h := &config.HeartbeatConfig{IntervalSeconds: 0}
	if h.HeartbeatInterval().Seconds() != 15 {
		t.Fatalf("expected default 15s, got %v", h.HeartbeatInterval())
	}
}

func TestHeartbeatTimeout_DefaultWhenZero(t *testing.T) {
	h := &config.HeartbeatConfig{TimeoutSeconds: 0}
	if h.HeartbeatTimeout().Seconds() != 45 {
		t.Fatalf("expected default 45s, got %v", h.HeartbeatTimeout())
	}
}

func TestHeartbeatInterval_ExplicitValue(t *testing.T) {
	h := &config.HeartbeatConfig{IntervalSeconds: 30}
	if h.HeartbeatInterval().Seconds() != 30 {
		t.Fatalf("expected 30s, got %v", h.HeartbeatInterval())
	}
}

func TestHeartbeatTimeout_ExplicitValue(t *testing.T) {
	h := &config.HeartbeatConfig{TimeoutSeconds: 90}
	if h.HeartbeatTimeout().Seconds() != 90 {
		t.Fatalf("expected 90s, got %v", h.HeartbeatTimeout())
	}
}

func TestValidate_DefaultKeysetPath(t *testing.T) {
	// When keyset.path is empty, it defaults to /etc/pmx-cloud/keyset.pub.
	toml := `
[backend]
url = "wss://api.example.com/ws/agent/core"
[siblings]
allowed = ["pmx-telemetry.service"]
`
	cfg, err := config.Parse([]byte(toml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Keyset.Path != "/etc/pmx-cloud/keyset.pub" {
		t.Fatalf("expected default keyset path, got %q", cfg.Keyset.Path)
	}
}

func TestValidate_DefaultStateDir(t *testing.T) {
	toml := `
[backend]
url = "wss://api.example.com/ws/agent/core"
[siblings]
allowed = ["pmx-telemetry.service"]
`
	cfg, err := config.Parse([]byte(toml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.State.Dir != "/var/lib/pmx-cloud/core" {
		t.Fatalf("expected default state dir, got %q", cfg.State.Dir)
	}
}
