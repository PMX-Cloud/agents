// Package config implements TOML loading and validation for pmx-hardware-installer.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Identity IdentityConfig `toml:"identity"`
	Keyset   KeysetConfig   `toml:"keyset"`
	Paths    PathsConfig    `toml:"paths"`
	Files    FilesConfig    `toml:"files"`
	Policy   PolicyConfig   `toml:"policy"`
}

type IdentityConfig struct {
	Cert                string `toml:"cert"`
	Key                 string `toml:"key"`
	HostFingerprintFile string `toml:"host_fingerprint_file"`
}

type KeysetConfig struct {
	Path string `toml:"path"`
}

type PathsConfig struct {
	AptGet     string `toml:"apt_get"`
	AptCache   string `toml:"apt_cache"`
	LSPCI      string `toml:"lspci"`
	DKMS       string `toml:"dkms"`
	UpdateGrub string `toml:"update_grub"`
	PVEUpgrade string `toml:"pveupgrade"`
	Modprobe   string `toml:"modprobe"`
	SystemdRun string `toml:"systemd_run"`
	QM         string `toml:"qm"`
	Systemctl  string `toml:"systemctl"`
}

type FilesConfig struct {
	GrubDefaultPath         string `toml:"grub_default_path"`
	CPUInfoPath             string `toml:"cpuinfo_path"`
	SriovModprobeConfigPath string `toml:"sriov_modprobe_config_path"`
	LXCConfigDir            string `toml:"lxc_config_dir"`
	AptTuneConfigDir        string `toml:"apt_tune_config_dir"`
	KSMTuneConfigPath       string `toml:"ksm_tune_config_path"`
	CommunityReleaseKeyPath string `toml:"community_release_key_path"`
}

type PolicyConfig struct {
	AllowedKernelModules      []string `toml:"allowed_kernel_modules"`
	AllowedUtilityPackages    []string `toml:"allowed_utility_packages"`
	AllowedScriptInterpreters []string `toml:"allowed_script_interpreters"`
	AllowedScriptWriteRoots   []string `toml:"allowed_script_write_roots"`
	CommunityOutputLimitBytes int64    `toml:"community_output_limit_bytes"`
	CommunityMaxTimeoutSec    int      `toml:"community_max_timeout_seconds"`
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

	applyPathDefaults(&c.Paths)
	applyFileDefaults(&c.Files)
	if err := validateAbsolutePathFields(c.Files); err != nil {
		return err
	}
	applyPolicyDefaults(&c.Policy)
	if err := normalizePolicy(&c.Policy); err != nil {
		return err
	}
	return nil
}

func applyPathDefaults(p *PathsConfig) {
	if strings.TrimSpace(p.AptGet) == "" {
		p.AptGet = "/usr/bin/apt-get"
	}
	if strings.TrimSpace(p.AptCache) == "" {
		p.AptCache = "/usr/bin/apt-cache"
	}
	if strings.TrimSpace(p.LSPCI) == "" {
		p.LSPCI = "/usr/bin/lspci"
	}
	if strings.TrimSpace(p.DKMS) == "" {
		p.DKMS = "/usr/sbin/dkms"
	}
	if strings.TrimSpace(p.UpdateGrub) == "" {
		p.UpdateGrub = "/usr/sbin/update-grub"
	}
	if strings.TrimSpace(p.PVEUpgrade) == "" {
		p.PVEUpgrade = "/usr/bin/pveupgrade"
	}
	if strings.TrimSpace(p.Modprobe) == "" {
		p.Modprobe = "/usr/sbin/modprobe"
	}
	if strings.TrimSpace(p.SystemdRun) == "" {
		p.SystemdRun = "/usr/bin/systemd-run"
	}
	if strings.TrimSpace(p.QM) == "" {
		p.QM = "/usr/sbin/qm"
	}
	if strings.TrimSpace(p.Systemctl) == "" {
		p.Systemctl = "/usr/bin/systemctl"
	}
}

func applyFileDefaults(f *FilesConfig) {
	if strings.TrimSpace(f.GrubDefaultPath) == "" {
		f.GrubDefaultPath = "/etc/default/grub"
	}
	if strings.TrimSpace(f.CPUInfoPath) == "" {
		f.CPUInfoPath = "/proc/cpuinfo"
	}
	if strings.TrimSpace(f.SriovModprobeConfigPath) == "" {
		f.SriovModprobeConfigPath = "/etc/modprobe.d/sriov.conf"
	}
	if strings.TrimSpace(f.LXCConfigDir) == "" {
		f.LXCConfigDir = "/etc/pve/lxc"
	}
	if strings.TrimSpace(f.AptTuneConfigDir) == "" {
		f.AptTuneConfigDir = "/etc/apt/apt.conf.d"
	}
	if strings.TrimSpace(f.KSMTuneConfigPath) == "" {
		f.KSMTuneConfigPath = "/etc/ksmtuned.conf"
	}
	if strings.TrimSpace(f.CommunityReleaseKeyPath) == "" {
		f.CommunityReleaseKeyPath = "/etc/pmx-cloud/community-script-release.pub"
	}
}

func validateAbsolutePathFields(f FilesConfig) error {
	fields := map[string]string{
		"files.grub_default_path":          f.GrubDefaultPath,
		"files.cpuinfo_path":               f.CPUInfoPath,
		"files.sriov_modprobe_config_path": f.SriovModprobeConfigPath,
		"files.lxc_config_dir":             f.LXCConfigDir,
		"files.apt_tune_config_dir":        f.AptTuneConfigDir,
		"files.ksm_tune_config_path":       f.KSMTuneConfigPath,
		"files.community_release_key_path": f.CommunityReleaseKeyPath,
	}
	for field, value := range fields {
		if !filepath.IsAbs(value) {
			return fmt.Errorf("config: %s must be absolute, got %q", field, value)
		}
	}
	return nil
}

func applyPolicyDefaults(p *PolicyConfig) {
	if len(p.AllowedKernelModules) == 0 {
		p.AllowedKernelModules = []string{"vfio", "vfio_pci", "vfio_iommu_type1", "vfio_virqfd", "apex", "kvm", "kvm_intel", "kvm_amd"}
	}
	if len(p.AllowedUtilityPackages) == 0 {
		p.AllowedUtilityPackages = []string{"axel", "htop", "btop", "iftop", "iotop", "iperf3", "tmux", "dialog", "msr-tools", "net-tools", "libguestfs-tools", "s-tui", "intel-gpu-tools", "lsof"}
	}
	if len(p.AllowedScriptInterpreters) == 0 {
		p.AllowedScriptInterpreters = []string{"/bin/bash", "/bin/sh", "/usr/bin/python3"}
	}
	if len(p.AllowedScriptWriteRoots) == 0 {
		p.AllowedScriptWriteRoots = []string{"/tmp", "/var/tmp"}
	}
	if p.CommunityOutputLimitBytes <= 0 {
		p.CommunityOutputLimitBytes = 10 * 1024 * 1024
	}
	if p.CommunityMaxTimeoutSec <= 0 {
		p.CommunityMaxTimeoutSec = 600
	}
}

func normalizePolicy(p *PolicyConfig) error {
	normSet := func(in []string, absolute bool) ([]string, error) {
		out := make([]string, 0, len(in))
		seen := map[string]struct{}{}
		for _, raw := range in {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				continue
			}
			if absolute {
				if !filepath.IsAbs(trimmed) {
					return nil, fmt.Errorf("config: policy path %q must be absolute", trimmed)
				}
				trimmed = filepath.Clean(trimmed)
			}
			if _, ok := seen[trimmed]; ok {
				continue
			}
			seen[trimmed] = struct{}{}
			out = append(out, trimmed)
		}
		sort.Strings(out)
		return out, nil
	}

	var err error
	p.AllowedKernelModules, err = normSet(p.AllowedKernelModules, false)
	if err != nil {
		return err
	}
	p.AllowedUtilityPackages, err = normSet(p.AllowedUtilityPackages, false)
	if err != nil {
		return err
	}
	p.AllowedScriptInterpreters, err = normSet(p.AllowedScriptInterpreters, true)
	if err != nil {
		return err
	}
	p.AllowedScriptWriteRoots, err = normSet(p.AllowedScriptWriteRoots, true)
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) UtilityAllowed(name string) bool {
	for _, candidate := range c.Policy.AllowedUtilityPackages {
		if candidate == name {
			return true
		}
	}
	return false
}

func (c *Config) KernelModuleAllowed(name string) bool {
	for _, candidate := range c.Policy.AllowedKernelModules {
		if candidate == name {
			return true
		}
	}
	return false
}

func (c *Config) InterpreterAllowed(path string) bool {
	for _, candidate := range c.Policy.AllowedScriptInterpreters {
		if candidate == path {
			return true
		}
	}
	return false
}
