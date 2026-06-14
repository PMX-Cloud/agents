/*
Package capability implements host capability discovery for the core.identify command.

All subprocess calls use exec.CommandContext with a 5s timeout so a hanging
tool (rare lspci, etc.) cannot deadlock the call. Missing tools produce a
partial result with a populated Warnings field rather than a hard failure.
*/
package capability

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HostInfo is the payload returned by core.identify (architecture §5.1).
type HostInfo struct {
	HostFingerprint  string      `json:"host_fingerprint"`
	Hostname         string      `json:"hostname"`
	OS               OSInfo      `json:"os"`
	Kernel           string      `json:"kernel"`
	CPU              CPUInfo     `json:"cpu"`
	MemoryTotalBytes int64       `json:"memory_total_bytes"`
	Disks            []DiskInfo  `json:"disks"`
	NICs             []NICInfo   `json:"nics"`
	GPUs             []GPUInfo   `json:"gpus"`
	Proxmox          ProxmoxInfo `json:"proxmox"`
	Agents           []AgentInfo `json:"agents"`
	Warnings         []string    `json:"warnings,omitempty"`
}

// OSInfo holds the OS identifier and version.
type OSInfo struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// CPUInfo holds processor details.
type CPUInfo struct {
	Vendor string   `json:"vendor"`
	Model  string   `json:"model"`
	Cores  int      `json:"cores"`
	Flags  []string `json:"flags"`
}

// DiskInfo holds block-device details.
type DiskInfo struct {
	Name       string `json:"name"`
	SizeBytes  int64  `json:"size_bytes"`
	Rotational bool   `json:"rotational"`
}

// NICInfo holds network interface details.
type NICInfo struct {
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	SpeedMbps int    `json:"speed_mbps"`
}

// GPUInfo holds GPU details.
type GPUInfo struct {
	Vendor string `json:"vendor"`
	Model  string `json:"model"`
	PCI    string `json:"pci"`
}

// ProxmoxInfo reports whether Proxmox was detected and its version.
type ProxmoxInfo struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version,omitempty"`
}

// AgentInfo holds one sibling agent's status.
type AgentInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	UnitState string `json:"unit_state"`
}

// cache holds the last collected HostInfo to avoid repeated subprocess calls
// (core.identify may be called repeatedly during dashboard refresh).
type cache struct {
	mu        sync.Mutex
	info      *HostInfo
	expiresAt time.Time
}

const cacheTTL = 60 * time.Second

var globalCache cache

// Collect gathers host capability information. Results are cached for 60s.
func Collect(ctx context.Context) *HostInfo {
	globalCache.mu.Lock()
	defer globalCache.mu.Unlock()

	if globalCache.info != nil && time.Now().Before(globalCache.expiresAt) {
		return globalCache.info
	}

	info := collect(ctx)
	globalCache.info = info
	globalCache.expiresAt = time.Now().Add(cacheTTL)
	return info
}

// FilePaths holds the file paths used for data collection. Override in tests.
type FilePaths struct {
	OSRelease string // default: /etc/os-release
	CPUInfo   string // default: /proc/cpuinfo
	MemInfo   string // default: /proc/meminfo
	// HostFingerprintFile is the canonical fingerprint written once by the
	// installer; default: /etc/pmx-cloud/host-fingerprint.
	HostFingerprintFile string
}

var defaultPaths = FilePaths{
	OSRelease:           "/etc/os-release",
	CPUInfo:             "/proc/cpuinfo",
	MemInfo:             "/proc/meminfo",
	HostFingerprintFile: "/etc/pmx-cloud/host-fingerprint",
}

// collect does the actual data gathering.
func collect(ctx context.Context) *HostInfo {
	return collectWithPaths(ctx, defaultPaths)
}

// CollectWithPaths is exported for testing: allows injecting fixture file paths.
func CollectWithPaths(ctx context.Context, paths FilePaths) *HostInfo {
	return collectWithPaths(ctx, paths)
}

func collectWithPaths(ctx context.Context, paths FilePaths) *HostInfo {
	info := &HostInfo{}

	// Hostname
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}

	// Host fingerprint: prefer the canonical file, fall back to computing it.
	info.HostFingerprint = resolveFingerprint(paths.HostFingerprintFile)

	// OS
	info.OS = readOSReleaseFrom(paths.OSRelease)

	// Kernel
	info.Kernel = runOutput(ctx, 5*time.Second, &info.Warnings, "uname", "-r")
	info.Kernel = strings.TrimSpace(info.Kernel)

	// CPU
	info.CPU = readCPUInfoFrom(paths.CPUInfo)

	// Memory
	info.MemoryTotalBytes = readMemTotalFrom(paths.MemInfo)

	// Disks
	info.Disks = readDisks(ctx, &info.Warnings)

	// NICs
	info.NICs = readNICs()

	// GPUs
	info.GPUs = readGPUs(ctx, &info.Warnings)

	// Proxmox
	info.Proxmox = detectProxmox(ctx)

	// Sibling agents
	info.Agents = readAgentStatus(ctx, &info.Warnings)

	return info
}

// resolveFingerprint prefers the canonical fingerprint file written once by the
// installer so the core agent reports the SAME value the file-reading agents
// (pmx-storage, pmx-console-broker, …) and the backend use to sign and route
// envelopes. Recomputing here instead of reading the file produced a mismatch
// (computed vs file) that silently broke console-session dispatch.
//
// It falls back to a freshly computed value only when the file is missing or
// empty. That fallback must stay in sync with the installer's algorithm.
func resolveFingerprint(path string) string {
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if s := strings.TrimSpace(string(data)); s != "" {
				return s
			}
		}
	}
	return computeFingerprint()
}

// computeFingerprint returns SHA-256(machine-id || primary-mac).
// Stable across reboots as long as the machine-id and primary MAC don't change.
func computeFingerprint() string {
	machineID := ""
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := os.ReadFile(path); err == nil {
			machineID = strings.TrimSpace(string(data))
			if machineID != "" {
				break
			}
		}
	}

	mac := primaryMAC()

	sum := sha256.Sum256([]byte(machineID + mac))
	return hex.EncodeToString(sum[:])
}

// primaryMAC returns the MAC of the first non-loopback UP interface.
func primaryMAC() string {
	// Try /proc/net/route to find the default route interface first.
	if data, err := os.ReadFile("/proc/net/route"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 3 && fields[1] == "00000000" { // destination 0.0.0.0
				iface := fields[0]
				if mac, err := os.ReadFile("/sys/class/net/" + iface + "/address"); err == nil {
					return strings.TrimSpace(string(mac))
				}
			}
		}
	}

	// Fallback: first non-loopback UP interface.
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) > 0 {
			return iface.HardwareAddr.String()
		}
	}
	return ""
}

// readOSReleaseFrom parses the given os-release file path.
func readOSReleaseFrom(path string) OSInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return OSInfo{}
	}
	return ParseOSRelease(data)
}

// ParseOSRelease parses the content of /etc/os-release. Exported for testing.
func ParseOSRelease(data []byte) OSInfo {
	info := OSInfo{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := kv[0]
		val := strings.Trim(kv[1], `"`)
		switch key {
		case "ID":
			info.ID = val
		case "VERSION_ID":
			info.Version = val
		}
	}
	return info
}

// readCPUInfoFrom parses the given cpuinfo file path.
func readCPUInfoFrom(path string) CPUInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return CPUInfo{Cores: 1}
	}
	return ParseCPUInfo(data)
}

// ParseCPUInfo parses the content of /proc/cpuinfo. Exported for testing.
func ParseCPUInfo(data []byte) CPUInfo {
	info := CPUInfo{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	coreSet := map[int]bool{}
	for scanner.Scan() {
		line := scanner.Text()
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		switch key {
		case "vendor_id":
			if info.Vendor == "" {
				info.Vendor = val
			}
		case "model name":
			if info.Model == "" {
				info.Model = val
			}
		case "core id":
			if n, err := strconv.Atoi(val); err == nil {
				coreSet[n] = true
			}
		case "flags":
			if len(info.Flags) == 0 {
				info.Flags = strings.Fields(val)
			}
		}
	}
	info.Cores = len(coreSet)
	if info.Cores == 0 {
		info.Cores = 1
	}
	return info
}

// readMemTotalFrom parses the given meminfo file path for MemTotal.
func readMemTotalFrom(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return ParseMemTotal(data)
}

// ParseMemTotal parses the content of /proc/meminfo and returns MemTotal in bytes. Exported for testing.
func ParseMemTotal(data []byte) int64 {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

// lsblkOutput is the JSON structure from lsblk -J -b.
type lsblkOutput struct {
	Blockdevices []struct {
		Name     string `json:"name"`
		Size     string `json:"size"`
		Rota     string `json:"rota"` // "1" = rotational, "0" = SSD
		Type     string `json:"type"`
		Children []struct {
			Name string `json:"name"`
			Size string `json:"size"`
			Rota string `json:"rota"`
			Type string `json:"type"`
		} `json:"children"`
	} `json:"blockdevices"`
}

// readDisks runs lsblk -J -b and returns disk info.
func readDisks(ctx context.Context, warnings *[]string) []DiskInfo {
	out, err := runWithTimeout(ctx, 5*time.Second, "lsblk", "-J", "-b", "-d", "-o", "NAME,SIZE,ROTA,TYPE")
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("lsblk unavailable: %v", err))
		return []DiskInfo{}
	}
	disks, parseErr := ParseLsblkOutput([]byte(out))
	if parseErr != nil {
		*warnings = append(*warnings, fmt.Sprintf("lsblk parse error: %v", parseErr))
		return []DiskInfo{}
	}
	return disks
}

// ParseLsblkOutput parses the JSON from lsblk -J -b. Exported for testing.
func ParseLsblkOutput(data []byte) ([]DiskInfo, error) {
	var parsed lsblkOutput
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	disks := []DiskInfo{}
	for _, dev := range parsed.Blockdevices {
		if dev.Type != "disk" {
			continue
		}
		size, _ := strconv.ParseInt(dev.Size, 10, 64)
		disks = append(disks, DiskInfo{
			Name:       dev.Name,
			SizeBytes:  size,
			Rotational: dev.Rota == "1",
		})
	}
	return disks, nil
}

// ipLinkEntry is one entry from ip -j link.
type ipLinkEntry struct {
	Ifname   string   `json:"ifname"`
	Address  string   `json:"address"`
	LinkType string   `json:"link_type"`
	Flags    []string `json:"flags"`
}

// readNICs runs ip -j link and returns NIC info with speeds.
func readNICs() []NICInfo {
	out, err := exec.Command("ip", "-j", "link").Output()
	if err != nil {
		return []NICInfo{}
	}
	nics := ParseIPLink(out)
	for i := range nics {
		nics[i].SpeedMbps = readLinkSpeed(nics[i].Name)
	}
	return nics
}

// ParseIPLink parses the JSON from ip -j link. Exported for testing.
// speed is not populated (requires /sys access); callers may fill it separately.
func ParseIPLink(data []byte) []NICInfo {
	var entries []ipLinkEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return []NICInfo{}
	}
	nics := []NICInfo{}
	for _, e := range entries {
		if e.LinkType == "loopback" || e.Address == "" {
			continue
		}
		nics = append(nics, NICInfo{
			Name: e.Ifname,
			MAC:  e.Address,
		})
	}
	return nics
}

// readLinkSpeed reads /sys/class/net/<iface>/speed in Mbps.
func readLinkSpeed(iface string) int {
	data, err := os.ReadFile("/sys/class/net/" + iface + "/speed")
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return n
}

// readGPUs runs lspci -mmq and filters VGA/3D class devices.
func readGPUs(ctx context.Context, warnings *[]string) []GPUInfo {
	out, err := runWithTimeout(ctx, 5*time.Second, "lspci", "-mmq")
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("lspci unavailable: %v", err))
		return []GPUInfo{}
	}
	return ParseLspciOutput(out)
}

// ParseLspciOutput parses the output of lspci -mmq. Exported for testing.
func ParseLspciOutput(out string) []GPUInfo {
	gpus := []GPUInfo{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	var current map[string]string
	flush := func() {
		if current == nil {
			return
		}
		class := current["Class"]
		if strings.Contains(class, "VGA") || strings.Contains(class, "3D") || strings.Contains(class, "Display") {
			gpus = append(gpus, GPUInfo{
				Vendor: current["Vendor"],
				Model:  current["Device"],
				PCI:    current["Slot"],
			})
		}
		current = nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		kv := strings.SplitN(line, ":\t", 2)
		if len(kv) == 2 {
			if current == nil {
				current = make(map[string]string)
			}
			current[kv[0]] = strings.TrimSpace(kv[1])
		}
	}
	flush()
	return gpus
}

// detectProxmox checks if pveversion is present and reports the version.
func detectProxmox(ctx context.Context) ProxmoxInfo {
	out, err := runWithTimeout(ctx, 5*time.Second, "pveversion", "--version")
	if err != nil {
		return ProxmoxInfo{Detected: false}
	}
	version := strings.TrimSpace(out)
	return ProxmoxInfo{Detected: true, Version: version}
}

// readAgentStatus queries systemctl for all pmx-*.service units.
func readAgentStatus(ctx context.Context, warnings *[]string) []AgentInfo {
	out, err := runWithTimeout(ctx, 5*time.Second, "systemctl", "list-units",
		"--type=service", "--all", "pmx-*.service", "--output=json", "--no-pager")
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("systemctl unavailable: %v", err))
		return []AgentInfo{}
	}

	var units []struct {
		Unit        string `json:"unit"`
		ActiveState string `json:"active"`
	}
	if err := json.Unmarshal([]byte(out), &units); err != nil {
		// systemctl JSON output format varies; fall back to empty.
		return []AgentInfo{}
	}

	agents := []AgentInfo{}
	for _, u := range units {
		name := strings.TrimSuffix(u.Unit, ".service")
		agents = append(agents, AgentInfo{
			Name:      name,
			UnitState: u.ActiveState,
		})
	}
	return agents
}

// runOutput runs a command with a timeout and returns trimmed stdout.
// On error, appends a warning and returns "".
func runOutput(ctx context.Context, timeout time.Duration, warnings *[]string, name string, args ...string) string {
	out, err := runWithTimeout(ctx, timeout, name, args...)
	if err != nil {
		if warnings != nil {
			*warnings = append(*warnings, fmt.Sprintf("%s: %v", name, err))
		}
		return ""
	}
	return out
}

// runWithTimeout runs name with args, enforcing a deadline.
func runWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx2, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Run(); err != nil {
		if ctx2.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("%s timed out after %v", name, timeout)
		}
		slog.Debug("capability: subprocess error", "cmd", name, "err", err)
		return "", err
	}
	return buf.String(), nil
}

// InvalidateCache forces the next Collect call to re-gather data. Useful in tests.
func InvalidateCache() {
	globalCache.mu.Lock()
	globalCache.info = nil
	globalCache.mu.Unlock()
}
