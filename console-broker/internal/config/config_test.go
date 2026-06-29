package config_test

import (
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/console-broker/internal/config"
)

func TestParse_Defaults(t *testing.T) {
	t.Parallel()

	raw := `
[identity]
cert = "/etc/pmx-cloud/pmx-console-broker/client.crt"
key = "/etc/pmx-cloud/pmx-console-broker/client.key"

[keyset]
path = "/etc/pmx-cloud/keyset.pub"
`

	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Console.QMBinary != "/usr/sbin/qm" {
		t.Fatalf("qm binary default mismatch: %q", cfg.Console.QMBinary)
	}
	if cfg.Limits.DefaultRateLimitMbps != 100 {
		t.Fatalf("rate default mismatch: %d", cfg.Limits.DefaultRateLimitMbps)
	}
	if cfg.State.ReplayCachePath != "/var/lib/pmx-cloud/console-broker/replay.log" {
		t.Fatalf("replay cache default mismatch: %q", cfg.State.ReplayCachePath)
	}
}

func TestParse_RejectsRelativeQemuRunDir(t *testing.T) {
	t.Parallel()

	raw := `
[identity]
cert = "/etc/pmx-cloud/pmx-console-broker/client.crt"
key = "/etc/pmx-cloud/pmx-console-broker/client.key"

[console]
qemu_run_dir = "relative/path"
`

	_, err := config.Parse([]byte(raw))
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("expected absolute-path error, got %v", err)
	}
}
