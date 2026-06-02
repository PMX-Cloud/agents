/*
Package config implements the TOML configuration schema for pmx-core.

File: /etc/pmx-cloud/pmx-core.conf
Loaded once at startup; validated strictly (no unknown keys, URL must be wss://).
*/
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the root configuration for pmx-core.
type Config struct {
	Backend   BackendConfig   `toml:"backend"`
	Identity  IdentityConfig  `toml:"identity"`
	Keyset    KeysetConfig    `toml:"keyset"`
	State     StateConfig     `toml:"state"`
	Siblings  SiblingsConfig  `toml:"siblings"`
	Heartbeat HeartbeatConfig `toml:"heartbeat"`
}

// BackendConfig holds connection parameters for the backend WS gateway.
type BackendConfig struct {
	URL       string `toml:"url"`
	CACert    string `toml:"ca_cert"`
	AuthToken string `toml:"auth_token"`
}

// IdentityConfig holds mTLS cert paths and the host fingerprint file.
type IdentityConfig struct {
	Cert                string `toml:"cert"`
	Key                 string `toml:"key"`
	HostFingerprintFile string `toml:"host_fingerprint_file"`
}

// KeysetConfig holds the keyset file path.
type KeysetConfig struct {
	Path string `toml:"path"`
}

// StateConfig holds the persistent-state directory.
type StateConfig struct {
	Dir string `toml:"dir"`
}

// SiblingsConfig holds the allow-list for sibling unit lifecycle operations.
type SiblingsConfig struct {
	Allowed            []string `toml:"allowed"`
	EphemeralTemplates []string `toml:"ephemeral_templates"`
}

// HeartbeatConfig holds heartbeat timing parameters.
type HeartbeatConfig struct {
	IntervalSeconds int `toml:"interval_seconds"`
	TimeoutSeconds  int `toml:"timeout_seconds"`
}

// HeartbeatInterval converts IntervalSeconds to a duration.
func (h *HeartbeatConfig) HeartbeatInterval() time.Duration {
	if h.IntervalSeconds <= 0 {
		return 15 * time.Second
	}
	return time.Duration(h.IntervalSeconds) * time.Second
}

// HeartbeatTimeout converts TimeoutSeconds to a duration.
func (h *HeartbeatConfig) HeartbeatTimeout() time.Duration {
	if h.TimeoutSeconds <= 0 {
		return 45 * time.Second
	}
	return time.Duration(h.TimeoutSeconds) * time.Second
}

// Load reads and validates the TOML config at path.
// Returns an error if any required field is missing, the URL is not wss://,
// or the file contains an unknown key.
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

	// Check for unknown keys.
	for _, key := range md.Undecoded() {
		return nil, fmt.Errorf("config: unknown key %q", key.String())
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// validate performs semantic validation on the loaded config.
func (c *Config) validate() error {
	// Backend URL must be wss://.
	if c.Backend.URL == "" {
		return fmt.Errorf("config: backend.url is required")
	}
	if !strings.HasPrefix(c.Backend.URL, "wss://") {
		return fmt.Errorf("config: backend.url must start with wss://, got %q", c.Backend.URL)
	}

	// Keyset path.
	if c.Keyset.Path == "" {
		c.Keyset.Path = "/etc/pmx-cloud/keyset.pub"
	}

	// State dir.
	if c.State.Dir == "" {
		c.State.Dir = "/var/lib/pmx-cloud/core"
	}

	// Siblings must have at least the standard set.
	if len(c.Siblings.Allowed) == 0 {
		return fmt.Errorf("config: siblings.allowed must not be empty")
	}

	// Heartbeat defaults.
	if c.Heartbeat.IntervalSeconds <= 0 {
		c.Heartbeat.IntervalSeconds = 15
	}
	if c.Heartbeat.TimeoutSeconds <= 0 {
		c.Heartbeat.TimeoutSeconds = 45
	}

	return nil
}

// DefaultConfig returns a well-formed default config suitable for development.
func DefaultConfig() *Config {
	return &Config{
		Backend: BackendConfig{
			URL:    "wss://localhost:8443/ws/agent/core",
			CACert: "/etc/pmx-cloud/backend-ca.crt",
		},
		Identity: IdentityConfig{
			Cert:                "/etc/pmx-cloud/pmx-core/client.crt",
			Key:                 "/etc/pmx-cloud/pmx-core/client.key",
			HostFingerprintFile: "/etc/pmx-cloud/host-fingerprint",
		},
		Keyset: KeysetConfig{
			Path: "/etc/pmx-cloud/keyset.pub",
		},
		State: StateConfig{
			Dir: "/var/lib/pmx-cloud/core",
		},
		Siblings: SiblingsConfig{
			Allowed: []string{
				"pmx-telemetry.service",
				"pmx-hypervisor.service",
				"pmx-storage.service",
				"pmx-network.service",
				"pmx-security.service",
				"pmx-backup.service",
			},
			EphemeralTemplates: []string{
				"pmx-hardware-installer@.service",
				"pmx-updater@.service",
				"pmx-console-broker@.service",
			},
		},
		Heartbeat: HeartbeatConfig{
			IntervalSeconds: 15,
			TimeoutSeconds:  45,
		},
	}
}
