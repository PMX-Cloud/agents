// Package config implements the TOML configuration schema for pmx-hypervisor.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the root configuration for pmx-hypervisor.
type Config struct {
	Backend  BackendConfig  `toml:"backend"`
	Identity IdentityConfig `toml:"identity"`
	Keyset   KeysetConfig   `toml:"keyset"`
	Proxmox  ProxmoxConfig  `toml:"proxmox"`
	Limits   LimitsConfig   `toml:"limits"`
}

type BackendConfig struct {
	URL    string `toml:"url"`
	CACert string `toml:"ca_cert"`
}

type IdentityConfig struct {
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

type KeysetConfig struct {
	Path string `toml:"path"`
}

// ProxmoxConfig holds paths to the Proxmox CLI tools.
type ProxmoxConfig struct {
	PveshPath string `toml:"pvesh_path"`
	QmPath    string `toml:"qm_path"`
	PctPath   string `toml:"pct_path"`
	PvesmPath string `toml:"pvesm_path"`
	PvecmPath string `toml:"pvecm_path"`
}

// LimitsConfig holds concurrency limits.
type LimitsConfig struct {
	MaxConcurrentVMCreate  int `toml:"max_concurrent_vm_create"`
	MaxConcurrentMigration int `toml:"max_concurrent_migrations"`
}

// Load reads and validates the TOML config at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	return Parse(data)
}

// Parse decodes a TOML config from raw bytes. Exposed for testing.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	for _, key := range md.Undecoded() {
		return nil, fmt.Errorf("config: unknown key %q", key.String())
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Backend.URL == "" {
		return fmt.Errorf("config: backend.url is required")
	}
	if !strings.HasPrefix(c.Backend.URL, "wss://") {
		return fmt.Errorf("config: backend.url must start with wss://, got %q", c.Backend.URL)
	}
	if c.Keyset.Path == "" {
		c.Keyset.Path = "/etc/pmx-cloud/keyset.pub"
	}
	// Apply defaults for Proxmox tool paths.
	if c.Proxmox.PveshPath == "" {
		c.Proxmox.PveshPath = "/usr/bin/pvesh"
	}
	if c.Proxmox.QmPath == "" {
		c.Proxmox.QmPath = "/usr/sbin/qm"
	}
	if c.Proxmox.PctPath == "" {
		c.Proxmox.PctPath = "/usr/sbin/pct"
	}
	if c.Proxmox.PvesmPath == "" {
		c.Proxmox.PvesmPath = "/usr/sbin/pvesm"
	}
	if c.Proxmox.PvecmPath == "" {
		c.Proxmox.PvecmPath = "/usr/sbin/pvecm"
	}
	// Concurrency limits.
	if c.Limits.MaxConcurrentVMCreate <= 0 {
		c.Limits.MaxConcurrentVMCreate = 4
	}
	if c.Limits.MaxConcurrentMigration <= 0 {
		c.Limits.MaxConcurrentMigration = 2
	}
	return nil
}

// DefaultConfig returns a dev-ready default config.
func DefaultConfig() *Config {
	return &Config{
		Backend: BackendConfig{
			URL:    "wss://localhost:8443/ws/agent/hypervisor",
			CACert: "/etc/pmx-cloud/backend-ca.crt",
		},
		Identity: IdentityConfig{
			Cert: "/etc/pmx-cloud/pmx-hypervisor/client.crt",
			Key:  "/etc/pmx-cloud/pmx-hypervisor/client.key",
		},
		Keyset: KeysetConfig{Path: "/etc/pmx-cloud/keyset.pub"},
		Proxmox: ProxmoxConfig{
			PveshPath: "/usr/bin/pvesh",
			QmPath:    "/usr/sbin/qm",
			PctPath:   "/usr/sbin/pct",
			PvesmPath: "/usr/sbin/pvesm",
			PvecmPath: "/usr/sbin/pvecm",
		},
		Limits: LimitsConfig{
			MaxConcurrentVMCreate:  4,
			MaxConcurrentMigration: 2,
		},
	}
}
