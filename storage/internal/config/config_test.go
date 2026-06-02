package config_test

import (
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/storage/internal/config"
)

const validConfig = `
[backend]
url = "wss://api.pmxcloud.example/ws/agent/storage"

[identity]
cert = "/etc/pmx-cloud/pmx-storage/client.crt"
key = "/etc/pmx-cloud/pmx-storage/client.key"

[keyset]
path = "/etc/pmx-cloud/keyset.pub"
`

func TestParseRejectsNonWSSBackendURL(t *testing.T) {
	_, err := config.Parse([]byte(strings.Replace(validConfig, "wss://", "https://", 1)))
	if err == nil || !strings.Contains(err.Error(), "wss://") {
		t.Fatalf("expected wss validation error, got %v", err)
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	_, err := config.Parse([]byte(validConfig + "\n[unknown]\nvalue = true\n"))
	if err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("expected unknown key error, got %v", err)
	}
}

func TestParseAppliesCommandDefaults(t *testing.T) {
	cfg, err := config.Parse([]byte(validConfig))
	if err != nil {
		t.Fatalf("parse valid config: %v", err)
	}
	if cfg.Commands.LsblkPath != "/sbin/lsblk" || cfg.Commands.ZpoolPath != "/sbin/zpool" {
		t.Fatalf("expected default command paths, got %+v", cfg.Commands)
	}
}
