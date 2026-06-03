// Package config implements TOML loading/validation for pmx-security.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Backend  BackendConfig  `toml:"backend"`
	Identity IdentityConfig `toml:"identity"`
	Keyset   KeysetConfig   `toml:"keyset"`
	CVE      CVEConfig      `toml:"cve"`
	Lynis    LynisConfig    `toml:"lynis"`
	State    StateConfig    `toml:"state"`
}

type BackendConfig struct {
	URL    string `toml:"url"`
	CACert string `toml:"ca_cert"`
	AuthToken string `toml:"auth_token"`
}

type IdentityConfig struct {
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

type KeysetConfig struct {
	Path string `toml:"path"`
}

type CVEConfig struct {
	DBPath              string `toml:"db_path"`
	SignatureKeysetPath string `toml:"signature_keyset_path"`
}

type LynisConfig struct {
	Binary  string `toml:"binary"`
	Profile string `toml:"profile"`
}

type StateConfig struct {
	Dir string `toml:"dir"`
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
	if c.Backend.URL == "" {
		return fmt.Errorf("config: backend.url is required")
	}
	if !strings.HasPrefix(c.Backend.URL, "wss://") {
		return fmt.Errorf("config: backend.url must start with wss://, got %q", c.Backend.URL)
	}
	if c.Identity.Cert == "" || c.Identity.Key == "" {
		return fmt.Errorf("config: identity.cert and identity.key are required")
	}
	if c.Keyset.Path == "" {
		c.Keyset.Path = "/etc/pmx-cloud/keyset.pub"
	}
	if c.CVE.DBPath == "" {
		c.CVE.DBPath = "/var/lib/pmx-cloud/security/cve.db"
	}
	if c.CVE.SignatureKeysetPath == "" {
		c.CVE.SignatureKeysetPath = "/etc/pmx-cloud/release-keyset.pub"
	}
	if c.Lynis.Binary == "" {
		c.Lynis.Binary = "/usr/sbin/lynis"
	}
	if c.Lynis.Profile == "" {
		c.Lynis.Profile = "/etc/lynis/default.prf"
	}
	if c.State.Dir == "" {
		c.State.Dir = "/var/lib/pmx-cloud/security"
	}
	return nil
}
