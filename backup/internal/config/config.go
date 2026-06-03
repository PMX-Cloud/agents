// Package config implements TOML loading/validation for pmx-backup.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Backend  BackendConfig  `toml:"backend"`
	Identity IdentityConfig `toml:"identity"`
	Keyset   KeysetConfig   `toml:"keyset"`
	Storage  StorageConfig  `toml:"storage"`
	VZDump   VZDumpConfig   `toml:"vzdump"`
	Limits   LimitsConfig   `toml:"limits"`
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

type StorageConfig struct {
	ArchiveRoots []string `toml:"archive_roots"`
}

type VZDumpConfig struct {
	Binary          string `toml:"binary"`
	QMBinary        string `toml:"qm_binary"`
	QMRestoreBinary string `toml:"qmrestore_binary"`
	TarBinary       string `toml:"tar_binary"`
	PBSBinary       string `toml:"pbs_binary"`
}

type LimitsConfig struct {
	MaxConcurrentJobs  int `toml:"max_concurrent_jobs"`
	MaxConcurrentSyncs int `toml:"max_concurrent_syncs"`
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
	if strings.TrimSpace(c.Identity.Cert) == "" || strings.TrimSpace(c.Identity.Key) == "" {
		return fmt.Errorf("config: identity.cert and identity.key are required")
	}
	if c.Keyset.Path == "" {
		c.Keyset.Path = "/etc/pmx-cloud/keyset.pub"
	}
	if len(c.Storage.ArchiveRoots) == 0 {
		return fmt.Errorf("config: storage.archive_roots is required")
	}

	roots := make([]string, 0, len(c.Storage.ArchiveRoots))
	seen := map[string]struct{}{}
	for _, root := range c.Storage.ArchiveRoots {
		norm := strings.TrimSpace(root)
		if norm == "" {
			continue
		}
		if !filepath.IsAbs(norm) {
			return fmt.Errorf("config: storage.archive_roots must contain absolute paths, got %q", root)
		}
		norm = filepath.Clean(norm)
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		roots = append(roots, norm)
	}
	if len(roots) == 0 {
		return fmt.Errorf("config: storage.archive_roots must contain at least one absolute path")
	}
	c.Storage.ArchiveRoots = roots

	if c.VZDump.Binary == "" {
		c.VZDump.Binary = "/usr/sbin/vzdump"
	}
	if c.VZDump.QMBinary == "" {
		c.VZDump.QMBinary = "/usr/sbin/qm"
	}
	if c.VZDump.QMRestoreBinary == "" {
		c.VZDump.QMRestoreBinary = "/usr/sbin/qmrestore"
	}
	if c.VZDump.TarBinary == "" {
		c.VZDump.TarBinary = "/usr/bin/tar"
	}
	if c.VZDump.PBSBinary == "" {
		c.VZDump.PBSBinary = "/usr/bin/proxmox-backup-client"
	}

	if c.Limits.MaxConcurrentJobs <= 0 {
		c.Limits.MaxConcurrentJobs = 2
	}
	if c.Limits.MaxConcurrentSyncs <= 0 {
		c.Limits.MaxConcurrentSyncs = 4
	}

	return nil
}
