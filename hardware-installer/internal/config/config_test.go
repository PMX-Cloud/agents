package config_test

import (
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/hardware-installer/internal/config"
)

func TestParseDefaults(t *testing.T) {
	t.Parallel()

	raw := `
[identity]
cert = "/etc/pmx-cloud/pmx-hardware-installer/client.crt"
key = "/etc/pmx-cloud/pmx-hardware-installer/client.key"
`

	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Paths.AptGet != "/usr/bin/apt-get" {
		t.Fatalf("apt-get default mismatch: %q", cfg.Paths.AptGet)
	}
	if !cfg.UtilityAllowed("htop") {
		t.Fatal("expected default utility allowlist to include htop")
	}
}

func TestParseRejectsRelativePolicyPath(t *testing.T) {
	t.Parallel()

	raw := `
[identity]
cert = "/etc/pmx-cloud/pmx-hardware-installer/client.crt"
key = "/etc/pmx-cloud/pmx-hardware-installer/client.key"

[policy]
allowed_script_write_roots = ["tmp"]
`

	_, err := config.Parse([]byte(raw))
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("expected absolute path error, got %v", err)
	}
}

func TestParseRejectsUnknownKey(t *testing.T) {
	t.Parallel()

	raw := `
[identity]
cert = "/etc/pmx-cloud/pmx-hardware-installer/client.crt"
key = "/etc/pmx-cloud/pmx-hardware-installer/client.key"

[unknown]
a = 1
`

	_, err := config.Parse([]byte(raw))
	if err == nil {
		t.Fatal("expected unknown key error")
	}
}
