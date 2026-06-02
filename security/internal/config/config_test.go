package config_test

import (
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/security/internal/config"
)

const validConfig = `
[backend]
url = "wss://api.pmxcloud.example/ws/agent/security"

[identity]
cert = "/etc/pmx-cloud/pmx-security/client.crt"
key = "/etc/pmx-cloud/pmx-security/client.key"

[keyset]
path = "/etc/pmx-cloud/keyset.pub"

[cve]
db_path = "/var/lib/pmx-cloud/security/cve.db"

[lynis]
binary = "/usr/sbin/lynis"
profile = "/etc/lynis/default.prf"
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

func TestParseAppliesDefaults(t *testing.T) {
	cfg, err := config.Parse([]byte(`
[backend]
url = "wss://api.pmxcloud.example/ws/agent/security"
[identity]
cert = "c"
key = "k"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.CVE.DBPath == "" || cfg.State.Dir == "" || cfg.Lynis.Binary == "" {
		t.Fatalf("expected defaults, got %+v", cfg)
	}
	if cfg.CVE.SignatureKeysetPath == cfg.Keyset.Path || cfg.CVE.SignatureKeysetPath == "" {
		t.Fatalf("expected separate CVE signature keyset default, got %+v", cfg.CVE)
	}
}
