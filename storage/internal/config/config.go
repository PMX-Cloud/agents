// Package config implements the TOML configuration schema for pmx-storage.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the root pmx-storage configuration.
type Config struct {
	Backend  BackendConfig  `toml:"backend"`
	Identity IdentityConfig `toml:"identity"`
	Keyset   KeysetConfig   `toml:"keyset"`
	Commands CommandsConfig `toml:"commands"`
	State    StateConfig    `toml:"state"`
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

type StateConfig struct {
	Dir string `toml:"dir"`
}

// CommandsConfig holds absolute paths for storage CLI binaries.
type CommandsConfig struct {
	LsblkPath   string `toml:"lsblk_path"`
	PartedPath  string `toml:"parted_path"`
	WipefsPath  string `toml:"wipefs_path"`
	MkfsExt4    string `toml:"mkfs_ext4_path"`
	MkfsXfs     string `toml:"mkfs_xfs_path"`
	MkfsBtrfs   string `toml:"mkfs_btrfs_path"`
	ZpoolPath   string `toml:"zpool_path"`
	ZfsPath     string `toml:"zfs_path"`
	Smartctl    string `toml:"smartctl_path"`
	Exportfs    string `toml:"exportfs_path"`
	NetPath     string `toml:"net_path"`
	NvmePath    string `toml:"nvme_path"`
	QemuImgPath string `toml:"qemu_img_path"`
}

// Load reads and validates configuration from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	return Parse(data)
}

// Parse decodes and validates configuration bytes.
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
	if c.State.Dir == "" {
		c.State.Dir = "/var/lib/pmx-cloud/storage"
	}

	if c.Commands.LsblkPath == "" {
		c.Commands.LsblkPath = "/sbin/lsblk"
	}
	if c.Commands.PartedPath == "" {
		c.Commands.PartedPath = "/sbin/parted"
	}
	if c.Commands.WipefsPath == "" {
		c.Commands.WipefsPath = "/sbin/wipefs"
	}
	if c.Commands.MkfsExt4 == "" {
		c.Commands.MkfsExt4 = "/sbin/mkfs.ext4"
	}
	if c.Commands.MkfsXfs == "" {
		c.Commands.MkfsXfs = "/sbin/mkfs.xfs"
	}
	if c.Commands.MkfsBtrfs == "" {
		c.Commands.MkfsBtrfs = "/sbin/mkfs.btrfs"
	}
	if c.Commands.ZpoolPath == "" {
		c.Commands.ZpoolPath = "/sbin/zpool"
	}
	if c.Commands.ZfsPath == "" {
		c.Commands.ZfsPath = "/sbin/zfs"
	}
	if c.Commands.Smartctl == "" {
		c.Commands.Smartctl = "/usr/sbin/smartctl"
	}
	if c.Commands.Exportfs == "" {
		c.Commands.Exportfs = "/usr/sbin/exportfs"
	}
	if c.Commands.NetPath == "" {
		c.Commands.NetPath = "/usr/bin/net"
	}
	if c.Commands.NvmePath == "" {
		c.Commands.NvmePath = "/usr/sbin/nvme"
	}
	if c.Commands.QemuImgPath == "" {
		c.Commands.QemuImgPath = "/usr/bin/qemu-img"
	}
	return nil
}
