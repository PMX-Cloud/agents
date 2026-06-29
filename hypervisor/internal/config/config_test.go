package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/config"
)

const validTOML = `
[backend]
url = "wss://api.pmxcloud.example/ws/agent/hypervisor"
ca_cert = "/etc/pmx-cloud/backend-ca.crt"

[identity]
cert = "/etc/pmx-cloud/pmx-hypervisor/client.crt"
key  = "/etc/pmx-cloud/pmx-hypervisor/client.key"

[keyset]
path = "/etc/pmx-cloud/keyset.pub"

[proxmox]
pvesh_path = "/usr/bin/pvesh"
qm_path    = "/usr/sbin/qm"
pct_path   = "/usr/sbin/pct"

[limits]
max_concurrent_vm_create  = 4
max_concurrent_migrations = 2
`

func TestConfig_ParseValid(t *testing.T) {
	cfg, err := config.Parse([]byte(validTOML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Proxmox.QmPath != "/usr/sbin/qm" {
		t.Fatalf("wrong qm_path: %q", cfg.Proxmox.QmPath)
	}
	if cfg.Limits.MaxConcurrentVMCreate != 4 {
		t.Fatalf("wrong limit: %d", cfg.Limits.MaxConcurrentVMCreate)
	}
}

func TestConfig_RejectsInvalidScheme(t *testing.T) {
	bad := `
[backend]
url = "http://insecure"
`
	_, err := config.Parse([]byte(bad))
	if err == nil {
		t.Fatal("expected error for non-wss/ws URL")
	}
}

func TestConfig_RejectsUnknownKey(t *testing.T) {
	_, err := config.Parse([]byte(validTOML + "\n[evil]\nfoo=\"bar\"\n"))
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestConfig_Defaults(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.Proxmox.PveshPath == "" {
		t.Fatal("pvesh_path must not be empty")
	}
	if cfg.Limits.MaxConcurrentVMCreate != 4 {
		t.Fatal("expected default limit 4")
	}
}

func TestConfig_ExampleFileParses(t *testing.T) {
	data, err := os.ReadFile("../../pmx-hypervisor.conf.example")
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
	if cfg.Proxmox.QmPath != "/usr/sbin/qm" {
		t.Fatalf("expected qm_path=/usr/sbin/qm, got %q", cfg.Proxmox.QmPath)
	}
	if cfg.Limits.MaxConcurrentVMCreate != 4 {
		t.Fatalf("expected max_concurrent_vm_create=4, got %d", cfg.Limits.MaxConcurrentVMCreate)
	}
}
