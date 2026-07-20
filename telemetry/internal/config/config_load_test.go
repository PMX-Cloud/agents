package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pmx-cloud/agents/telemetry/internal/config"
)

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pmx-telemetry.conf")
	os.WriteFile(path, []byte(validTOML), 0o600)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Backend.URL == "" {
		t.Fatal("URL must not be empty")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := config.Load("/no/such/file.conf")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.conf")
	os.WriteFile(path, []byte("not [[[toml"), 0o600)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

func TestMetricsInterval_DefaultWhenZero(t *testing.T) {
	c := &config.CollectionConfig{MetricsIntervalSeconds: 0}
	if c.MetricsInterval().Seconds() != 10 {
		t.Fatalf("expected 10s default, got %v", c.MetricsInterval())
	}
}

func TestMetricsInterval_ExplicitValue(t *testing.T) {
	c := &config.CollectionConfig{MetricsIntervalSeconds: 30}
	if c.MetricsInterval().Seconds() != 30 {
		t.Fatalf("expected 30s, got %v", c.MetricsInterval())
	}
}

func TestEventsBuffer_DefaultWhenZero(t *testing.T) {
	c := &config.CollectionConfig{EventsBufferSeconds: 0}
	if c.EventsBuffer().Seconds() != 60 {
		t.Fatalf("expected 60s default, got %v", c.EventsBuffer())
	}
}

func TestEventsBuffer_ExplicitValue(t *testing.T) {
	c := &config.CollectionConfig{EventsBufferSeconds: 120}
	if c.EventsBuffer().Seconds() != 120 {
		t.Fatalf("expected 120s, got %v", c.EventsBuffer())
	}
}

func TestValidate_DefaultKeysetPath(t *testing.T) {
	toml := `
[backend]
url = "wss://api.example.com/ws/agent/telemetry"
`
	cfg, err := config.Parse([]byte(toml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Keyset.Path != "/etc/pmx-cloud/keyset.pub" {
		t.Fatalf("expected default keyset path, got %q", cfg.Keyset.Path)
	}
}
