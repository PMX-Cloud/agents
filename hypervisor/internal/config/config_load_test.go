package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/config"
)

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pmx-hypervisor.conf")
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

func TestValidate_DefaultKeysetPath(t *testing.T) {
	cfg, err := config.Parse([]byte(validTOML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Keyset.Path == "" {
		t.Fatal("keyset path must not be empty")
	}
}

func TestValidate_DefaultPaths(t *testing.T) {
	cfg, err := config.Parse([]byte(validTOML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Proxmox.QmPath == "" {
		t.Fatal("qm_path should be set")
	}
}

func TestValidate_MissingURL(t *testing.T) {
	_, err := config.Parse([]byte(""))
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}
