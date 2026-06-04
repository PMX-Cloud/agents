// Package config implements the TOML configuration schema for pmx-telemetry.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the root configuration for pmx-telemetry.
type Config struct {
	Backend    BackendConfig    `toml:"backend"`
	Identity   IdentityConfig   `toml:"identity"`
	Keyset     KeysetConfig     `toml:"keyset"`
	Collection CollectionConfig `toml:"collection"`
	Features   FeaturesConfig   `toml:"features"`
}

type BackendConfig struct {
	URL       string `toml:"url"`
	CACert    string `toml:"ca_cert"`
	AuthToken string `toml:"auth_token"`
}

type IdentityConfig struct {
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

type KeysetConfig struct {
	Path string `toml:"path"`
}

type CollectionConfig struct {
	MetricsIntervalSeconds int `toml:"metrics_interval_seconds"`
	EventsBufferSeconds    int `toml:"events_buffer_seconds"`
}

type FeaturesConfig struct {
	ProxmoxStatus bool `toml:"proxmox_status"`
}

// MetricsInterval returns the collection interval as a Duration.
func (c *CollectionConfig) MetricsInterval() time.Duration {
	if c.MetricsIntervalSeconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.MetricsIntervalSeconds) * time.Second
}

// EventsBuffer returns the buffer duration.
func (c *CollectionConfig) EventsBuffer() time.Duration {
	if c.EventsBufferSeconds <= 0 {
		return 60 * time.Second
	}
	return time.Duration(c.EventsBufferSeconds) * time.Second
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
	if c.Collection.MetricsIntervalSeconds <= 0 {
		c.Collection.MetricsIntervalSeconds = 10
	}
	if c.Collection.EventsBufferSeconds <= 0 {
		c.Collection.EventsBufferSeconds = 60
	}
	return nil
}

// DefaultConfig returns a well-formed default config.
func DefaultConfig() *Config {
	return &Config{
		Backend: BackendConfig{
			URL:    "wss://localhost:8443/ws/agent/telemetry",
			CACert: "/etc/pmx-cloud/backend-ca.crt",
		},
		Identity: IdentityConfig{
			Cert: "/etc/pmx-cloud/pmx-telemetry/client.crt",
			Key:  "/etc/pmx-cloud/pmx-telemetry/client.key",
		},
		Keyset: KeysetConfig{Path: "/etc/pmx-cloud/keyset.pub"},
		Collection: CollectionConfig{
			MetricsIntervalSeconds: 10,
			EventsBufferSeconds:    60,
		},
		Features: FeaturesConfig{ProxmoxStatus: true},
	}
}
