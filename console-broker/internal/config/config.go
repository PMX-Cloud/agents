// Package config implements TOML loading/validation for pmx-console-broker.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Identity IdentityConfig `toml:"identity"`
	Keyset   KeysetConfig   `toml:"keyset"`
	Console  ConsoleConfig  `toml:"console"`
	Policy   PolicyConfig   `toml:"policy"`
	Limits   LimitsConfig   `toml:"limits"`
	State    StateConfig    `toml:"state"`
}

type IdentityConfig struct {
	Cert                string `toml:"cert"`
	Key                 string `toml:"key"`
	HostFingerprintFile string `toml:"host_fingerprint_file"`
}

type KeysetConfig struct {
	Path string `toml:"path"`
}

type ConsoleConfig struct {
	QMBinary   string `toml:"qm_binary"`
	QemuRunDir string `toml:"qemu_run_dir"`
}

type PolicyConfig struct {
	AllowedBackendHostSuffixes []string `toml:"allowed_backend_host_suffixes"`
}

type LimitsConfig struct {
	DefaultRateLimitMbps int `toml:"default_rate_limit_mbps"`
}

type StateConfig struct {
	ReplayCachePath string `toml:"replay_cache_path"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	return Parse(data)
}

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
	if strings.TrimSpace(c.Identity.Cert) == "" || strings.TrimSpace(c.Identity.Key) == "" {
		return fmt.Errorf("config: identity.cert and identity.key are required")
	}
	if strings.TrimSpace(c.Identity.HostFingerprintFile) == "" {
		c.Identity.HostFingerprintFile = "/etc/pmx-cloud/host-fingerprint"
	}
	if strings.TrimSpace(c.Keyset.Path) == "" {
		c.Keyset.Path = "/etc/pmx-cloud/keyset.pub"
	}
	if strings.TrimSpace(c.Console.QMBinary) == "" {
		c.Console.QMBinary = "/usr/sbin/qm"
	}
	if strings.TrimSpace(c.Console.QemuRunDir) == "" {
		c.Console.QemuRunDir = "/var/run/qemu-server"
	}
	c.Console.QemuRunDir = filepath.Clean(c.Console.QemuRunDir)
	if !filepath.IsAbs(c.Console.QemuRunDir) {
		return fmt.Errorf("config: console.qemu_run_dir must be absolute, got %q", c.Console.QemuRunDir)
	}
	if c.Limits.DefaultRateLimitMbps <= 0 {
		c.Limits.DefaultRateLimitMbps = 100
	}
	if strings.TrimSpace(c.State.ReplayCachePath) == "" {
		c.State.ReplayCachePath = "/var/lib/pmx-cloud/console-broker/replay.log"
	}
	c.State.ReplayCachePath = filepath.Clean(c.State.ReplayCachePath)
	if !filepath.IsAbs(c.State.ReplayCachePath) {
		return fmt.Errorf("config: state.replay_cache_path must be absolute, got %q", c.State.ReplayCachePath)
	}

	suffixes := make([]string, 0, len(c.Policy.AllowedBackendHostSuffixes))
	seen := map[string]struct{}{}
	for _, suffix := range c.Policy.AllowedBackendHostSuffixes {
		norm := strings.ToLower(strings.TrimSpace(suffix))
		if norm == "" {
			continue
		}
		if !strings.HasPrefix(norm, ".") {
			norm = "." + norm
		}
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		suffixes = append(suffixes, norm)
	}
	c.Policy.AllowedBackendHostSuffixes = suffixes
	return nil
}
