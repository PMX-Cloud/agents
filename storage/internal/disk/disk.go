// Package disk implements disk.inventory, disk.format, disk.passthrough, disk.import-image.
package disk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pmx-cloud/agents/storage/internal/storageexec"
)

var supportedFSTypes = map[string]bool{
	"ext4":  true,
	"xfs":   true,
	"btrfs": true,
}

var byIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._:-]+$`)
var importIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// InventoryResult is the stable return shape for disk.inventory.
type InventoryResult struct {
	Disks []Disk `json:"disks"`
}

// Disk is one host block disk.
type Disk struct {
	Name        string      `json:"name"`
	Device      string      `json:"device"`
	SizeBytes   uint64      `json:"size_bytes"`
	Rotational  bool        `json:"rotational"`
	Removable   bool        `json:"removable"`
	Type        string      `json:"type"`
	Mountpoint  string      `json:"mountpoint,omitempty"`
	FSType      string      `json:"fstype,omitempty"`
	Serial      string      `json:"serial,omitempty"`
	Model       string      `json:"model,omitempty"`
	Vendor      string      `json:"vendor,omitempty"`
	WWN         string      `json:"wwn,omitempty"`
	SmartStatus string      `json:"smart_status,omitempty"`
	Encrypted   bool        `json:"encrypted"`
	Locked      bool        `json:"locked"`
	Partitions  []Partition `json:"partitions,omitempty"`
}

// Partition represents an lsblk child partition.
type Partition struct {
	Name       string `json:"name"`
	Device     string `json:"device"`
	SizeBytes  uint64 `json:"size_bytes"`
	Type       string `json:"type"`
	Mountpoint string `json:"mountpoint,omitempty"`
	FSType     string `json:"fstype,omitempty"`
}

type lsblkOut struct {
	BlockDevices []lsblkNode `json:"blockdevices"`
}

type lsblkNode struct {
	Name       string      `json:"name"`
	Size       interface{} `json:"size"`
	Rota       interface{} `json:"rota"`
	RM         interface{} `json:"rm"`
	Type       string      `json:"type"`
	Mountpoint interface{} `json:"mountpoint"`
	FSType     interface{} `json:"fstype"`
	Serial     interface{} `json:"serial"`
	Model      interface{} `json:"model"`
	Vendor     interface{} `json:"vendor"`
	WWN        interface{} `json:"wwn"`
	Children   []lsblkNode `json:"children"`
}

type smartStatusOut struct {
	SmartStatus struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
}

// FormatParams controls disk.format.
type FormatParams struct {
	Device     string
	FSType     string
	Force      bool
	MountsPath string
	FstabPath  string
}

// PassthroughParams controls disk.passthrough.
type PassthroughParams struct {
	WWN     string
	ByIDDir string
}

// PassthroughResult returns the stable canonical device path.
type PassthroughResult struct {
	WWN           string `json:"wwn"`
	ByIDPath      string `json:"by_id_path"`
	CanonicalPath string `json:"canonical_path"`
}

// ImportImageParams controls disk.import-image.
type ImportImageParams struct {
	ID             string   `json:"id"`
	SourceURL      string   `json:"source_url"`
	AllowedHosts   []string `json:"allowed_hosts"`
	SourceFormat   string   `json:"source_format"`
	Destination    string   `json:"destination"`
	StorageRoot    string   `json:"storage_root"`
	HTTPTimeoutSec int      `json:"http_timeout_seconds"`
}

// ImportImageResult describes the imported image artifact.
type ImportImageResult struct {
	DownloadedPath string `json:"downloaded_path"`
	Destination    string `json:"destination"`
	SHA256         string `json:"sha256"`
	Resumed        bool   `json:"resumed"`
}

// Inventory returns all host disks from lsblk + SMART summary.
func Inventory(ctx context.Context, ex storageexec.Interface) (*InventoryResult, error) {
	res, err := ex.Lsblk(ctx, "-J", "-b", "-o", "NAME,SIZE,ROTA,RM,TYPE,MOUNTPOINT,FSTYPE,SERIAL,MODEL,VENDOR,WWN")
	if err != nil {
		return nil, fmt.Errorf("disk.inventory lsblk: %w", err)
	}

	var out lsblkOut
	if err := json.Unmarshal(res.Stdout, &out); err != nil {
		return nil, fmt.Errorf("disk.inventory parse lsblk: %w", err)
	}

	result := &InventoryResult{Disks: make([]Disk, 0, len(out.BlockDevices))}
	for _, node := range out.BlockDevices {
		if node.Type != "disk" {
			continue
		}
		d := Disk{
			Name:       node.Name,
			Device:     "/dev/" + node.Name,
			SizeBytes:  toUint64(node.Size),
			Rotational: toBool(node.Rota),
			Removable:  toBool(node.RM),
			Type:       node.Type,
			Mountpoint: toString(node.Mountpoint),
			FSType:     toString(node.FSType),
			Serial:     toString(node.Serial),
			Model:      toString(node.Model),
			Vendor:     toString(node.Vendor),
			WWN:        toString(node.WWN),
		}

		for _, child := range node.Children {
			if child.Type == "crypt" || strings.Contains(strings.ToLower(toString(child.FSType)), "crypto") {
				d.Encrypted = true
			}
			if child.Type != "part" {
				continue
			}
			d.Partitions = append(d.Partitions, Partition{
				Name:       child.Name,
				Device:     "/dev/" + child.Name,
				SizeBytes:  toUint64(child.Size),
				Type:       child.Type,
				Mountpoint: toString(child.Mountpoint),
				FSType:     toString(child.FSType),
			})
		}
		if strings.Contains(strings.ToLower(d.FSType), "crypto") {
			d.Encrypted = true
		}
		if d.Encrypted && d.Mountpoint == "" {
			d.Locked = true
		}

		smart, smartErr := ex.Smartctl(ctx, "-j", "-H", d.Device)
		switch {
		case smartErr == nil:
			d.SmartStatus = parseSmartStatus(smart.Stdout)
		case strings.Contains(strings.ToLower(string(smart.Stderr)), "unavailable"),
			strings.Contains(strings.ToLower(string(smart.Stderr)), "unsupported"):
			d.SmartStatus = "unsupported"
		default:
			d.SmartStatus = "unknown"
		}

		result.Disks = append(result.Disks, d)
	}

	sort.Slice(result.Disks, func(i, j int) bool {
		return result.Disks[i].Name < result.Disks[j].Name
	})
	return result, nil
}

// Format runs wipefs -> parted -> mkfs while enforcing mounted/fstab/children guards.
func Format(ctx context.Context, ex storageexec.Interface, p FormatParams) error {
	if !strings.HasPrefix(p.Device, "/dev/") || strings.Contains(p.Device, "..") {
		return fmt.Errorf("disk.format: device must be absolute /dev path")
	}
	fs := strings.ToLower(strings.TrimSpace(p.FSType))
	if !supportedFSTypes[fs] {
		return fmt.Errorf("disk.format: unsupported fstype %q", p.FSType)
	}
	if p.MountsPath == "" {
		p.MountsPath = "/proc/mounts"
	}
	if p.FstabPath == "" {
		p.FstabPath = "/etc/fstab"
	}

	directDevices := []string{p.Device}
	mounted, mountedDev, err := isAnyMounted(p.MountsPath, directDevices)
	if err != nil {
		return err
	}
	if mounted {
		return fmt.Errorf("disk.format: refused: %s is mounted", mountedDev)
	}
	inFstab, fstabDev, err := listedAnyInFstab(p.FstabPath, directDevices)
	if err != nil {
		return err
	}
	if inFstab {
		return fmt.Errorf("disk.format: refused: %s is still present in /etc/fstab", fstabDev)
	}

	children, err := listChildren(ctx, ex)
	if err != nil {
		return err
	}

	blockedDevices := relatedDevices(p.Device, children[p.Device])
	if len(blockedDevices) > 1 {
		descendants := blockedDevices[1:]
		descMounted, descMountedDev, err := isAnyMounted(p.MountsPath, descendants)
		if err != nil {
			return err
		}
		if descMounted {
			return fmt.Errorf("disk.format: refused: descendant %s is mounted", descMountedDev)
		}

		descInFstab, descFstabDev, err := listedAnyInFstab(p.FstabPath, descendants)
		if err != nil {
			return err
		}
		if descInFstab {
			return fmt.Errorf("disk.format: refused: descendant %s is present in /etc/fstab", descFstabDev)
		}
	}
	if len(children[p.Device]) > 0 && !p.Force {
		return fmt.Errorf("disk.format: refused: %s has child partitions; force=true required", p.Device)
	}

	if _, err := ex.Wipefs(ctx, "-a", p.Device); err != nil {
		return fmt.Errorf("disk.format wipefs: %w", err)
	}
	if _, err := ex.Parted(ctx, "-s", p.Device, "mklabel", "gpt", "mkpart", "primary", "0%", "100%"); err != nil {
		return fmt.Errorf("disk.format parted: %w", err)
	}
	target := firstPartitionDevice(ctx, ex, p.Device)

	switch fs {
	case "ext4":
		if _, err := ex.Mkfs(ctx, "ext4", "-F", target); err != nil {
			return fmt.Errorf("disk.format mkfs.ext4: %w", err)
		}
	case "xfs":
		if _, err := ex.Mkfs(ctx, "xfs", "-f", target); err != nil {
			return fmt.Errorf("disk.format mkfs.xfs: %w", err)
		}
	case "btrfs":
		if _, err := ex.Mkfs(ctx, "btrfs", "-f", target); err != nil {
			return fmt.Errorf("disk.format mkfs.btrfs: %w", err)
		}
	}

	return nil
}

func listChildren(ctx context.Context, ex storageexec.Interface) (map[string][]string, error) {
	res, err := ex.Lsblk(ctx, "-J", "-o", "NAME,TYPE")
	if err != nil {
		return nil, fmt.Errorf("disk.format lsblk: %w", err)
	}
	var out lsblkOut
	if err := json.Unmarshal(res.Stdout, &out); err != nil {
		return nil, fmt.Errorf("disk.format parse lsblk: %w", err)
	}
	children := map[string][]string{}
	for _, node := range out.BlockDevices {
		if node.Type != "disk" {
			continue
		}
		key := "/dev/" + node.Name
		for _, child := range node.Children {
			children[key] = append(children[key], child.Name)
		}
	}
	return children, nil
}

func firstPartitionDevice(ctx context.Context, ex storageexec.Interface, diskDevice string) string {
	res, err := ex.Lsblk(ctx, "-J", "-o", "NAME,TYPE")
	if err == nil {
		var out lsblkOut
		if json.Unmarshal(res.Stdout, &out) == nil {
			diskName := strings.TrimPrefix(diskDevice, "/dev/")
			for _, node := range out.BlockDevices {
				if node.Name != diskName || node.Type != "disk" {
					continue
				}
				for _, child := range node.Children {
					if child.Type == "part" && child.Name != "" {
						return "/dev/" + child.Name
					}
				}
				break
			}
		}
	}

	// Partition naming differs on NVMe/mmc (p1 suffix) and sdX (1 suffix).
	if strings.HasPrefix(diskDevice, "/dev/nvme") || strings.HasPrefix(diskDevice, "/dev/mmcblk") {
		return diskDevice + "p1"
	}
	return diskDevice + "1"
}

func isAnyMounted(path string, devices []string) (bool, string, error) {
	deviceSet := make(map[string]bool, len(devices))
	for _, d := range devices {
		deviceSet[d] = true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("disk.format: read mounts: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && deviceSet[fields[0]] {
			return true, fields[0], nil
		}
	}
	return false, "", nil
}

func listedAnyInFstab(path string, devices []string) (bool, string, error) {
	deviceSet := make(map[string]bool, len(devices))
	for _, d := range devices {
		deviceSet[d] = true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("disk.format: read fstab: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && deviceSet[fields[0]] {
			return true, fields[0], nil
		}
	}
	return false, "", nil
}

// Passthrough validates stable /dev/disk/by-id mapping and returns canonical path.
func Passthrough(p PassthroughParams) (*PassthroughResult, error) {
	if !byIDPattern.MatchString(p.WWN) {
		return nil, fmt.Errorf("disk.passthrough: invalid wwn")
	}
	dir := p.ByIDDir
	if dir == "" {
		dir = "/dev/disk/by-id"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("disk.passthrough: read by-id dir: %w", err)
	}

	needle := strings.ToLower(p.WWN)
	needleTrimmed := strings.TrimPrefix(strings.TrimPrefix(needle, "wwn-"), "0x")
	for _, entry := range entries {
		name := entry.Name()
		nameLower := strings.ToLower(name)
		if !strings.HasPrefix(nameLower, "wwn-") || strings.Contains(nameLower, "-part") {
			continue
		}
		candidate := strings.TrimPrefix(strings.TrimPrefix(nameLower, "wwn-"), "0x")
		if candidate != needleTrimmed && nameLower != needle {
			continue
		}
		link := filepath.Join(dir, name)
		target, err := filepath.EvalSymlinks(link)
		if err != nil {
			return nil, fmt.Errorf("disk.passthrough: resolve %s: %w", link, err)
		}
		if !strings.HasPrefix(target, "/dev/") {
			return nil, fmt.Errorf("disk.passthrough: resolved target is not /dev path: %s", target)
		}
		return &PassthroughResult{WWN: p.WWN, ByIDPath: link, CanonicalPath: target}, nil
	}

	return nil, fmt.Errorf("disk.passthrough: no by-id entry found for %s", p.WWN)
}

// ImportImage downloads an allowlisted image with resume support and optional qemu-img convert.
func ImportImage(ctx context.Context, ex storageexec.Interface, p ImportImageParams) (*ImportImageResult, error) {
	if p.SourceURL == "" || p.Destination == "" {
		return nil, fmt.Errorf("disk.import-image: source_url and destination are required")
	}
	if err := validateAllowlistedURL(p.SourceURL, p.AllowedHosts); err != nil {
		return nil, err
	}
	if p.StorageRoot == "" {
		p.StorageRoot = "/var/lib/pmx-cloud/storage"
	}
	if p.HTTPTimeoutSec <= 0 {
		p.HTTPTimeoutSec = 300
	}
	if err := os.MkdirAll(p.StorageRoot, 0o700); err != nil {
		return nil, fmt.Errorf("disk.import-image: mkdir storage_root: %w", err)
	}

	id, err := sanitizeImportID(p.ID)
	if err != nil {
		return nil, err
	}
	importsDir := filepath.Join(p.StorageRoot, "imports")
	if err := os.MkdirAll(importsDir, 0o700); err != nil {
		return nil, fmt.Errorf("disk.import-image: mkdir imports dir: %w", err)
	}
	partialPath := filepath.Join(importsDir, id+".part")
	destinationPath, err := resolvePathWithinRoot(p.StorageRoot, p.Destination)
	if err != nil {
		return nil, err
	}

	hash, resumed, err := resumeDownload(ctx, p.SourceURL, partialPath, time.Duration(p.HTTPTimeoutSec)*time.Second)
	if err != nil {
		return nil, err
	}

	src := partialPath
	if fmtLower(p.SourceFormat) != "" && fmtLower(p.SourceFormat) != "raw" {
		if _, err := ex.QemuImg(ctx, "convert", "-f", fmtLower(p.SourceFormat), "-O", "raw", partialPath, destinationPath); err != nil {
			return nil, fmt.Errorf("disk.import-image qemu-img convert: %w", err)
		}
		src = destinationPath
	} else if partialPath != destinationPath {
		if err := os.Rename(partialPath, destinationPath); err != nil {
			return nil, fmt.Errorf("disk.import-image move destination: %w", err)
		}
		src = destinationPath
	}

	return &ImportImageResult{
		DownloadedPath: src,
		Destination:    destinationPath,
		SHA256:         hash,
		Resumed:        resumed,
	}, nil
}

func sanitizeImportID(value string) (string, error) {
	id := strings.TrimSpace(value)
	if id == "" {
		id = fmt.Sprintf("import-%d", time.Now().Unix())
	}
	if !importIDPattern.MatchString(id) {
		return "", fmt.Errorf("disk.import-image: id contains unsafe characters")
	}
	return id, nil
}

func resolvePathWithinRoot(root, requested string) (string, error) {
	rootClean := filepath.Clean(strings.TrimSpace(root))
	if rootClean == "." || !filepath.IsAbs(rootClean) {
		return "", fmt.Errorf("disk.import-image: storage_root must be an absolute path")
	}
	req := strings.TrimSpace(requested)
	if req == "" {
		return "", fmt.Errorf("disk.import-image: destination is required")
	}

	var candidate string
	if filepath.IsAbs(req) {
		candidate = filepath.Clean(req)
	} else {
		candidate = filepath.Clean(filepath.Join(rootClean, req))
	}
	rel, err := filepath.Rel(rootClean, candidate)
	if err != nil {
		return "", fmt.Errorf("disk.import-image: resolve destination: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("disk.import-image: destination escapes storage root")
	}
	if strings.HasPrefix(candidate, "/dev/") {
		return "", fmt.Errorf("disk.import-image: destination cannot target /dev")
	}
	if err := os.MkdirAll(filepath.Dir(candidate), 0o700); err != nil {
		return "", fmt.Errorf("disk.import-image: mkdir destination parent: %w", err)
	}
	return candidate, nil
}

func relatedDevices(diskDevice string, childNames []string) []string {
	out := []string{diskDevice}
	for _, child := range childNames {
		child = strings.TrimSpace(child)
		if child == "" {
			continue
		}
		if strings.HasPrefix(child, "/dev/") {
			out = append(out, child)
			continue
		}
		out = append(out, "/dev/"+child)
	}
	return out
}

func resumeDownload(ctx context.Context, rawURL, path string, timeout time.Duration) (string, bool, error) {
	var offset int64
	if st, err := os.Stat(path); err == nil {
		offset = st.Size()
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return "", false, fmt.Errorf("disk.import-image open target: %w", err)
	}
	defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return "", false, fmt.Errorf("disk.import-image seek: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", false, fmt.Errorf("disk.import-image build request: %w", err)
	}
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("disk.import-image download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return "", false, fmt.Errorf("disk.import-image unexpected http status %d", resp.StatusCode)
	}
	if offset > 0 && resp.StatusCode == http.StatusOK {
		// Server ignored Range and sent the full object; restart cleanly.
		if err := file.Truncate(0); err != nil {
			return "", false, fmt.Errorf("disk.import-image reset partial: %w", err)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return "", false, fmt.Errorf("disk.import-image rewind after reset: %w", err)
		}
		offset = 0
	}
	if _, err := io.Copy(file, resp.Body); err != nil {
		return "", false, fmt.Errorf("disk.import-image write body: %w", err)
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", false, fmt.Errorf("disk.import-image rewind: %w", err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", false, fmt.Errorf("disk.import-image checksum: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), offset > 0 && resp.StatusCode == http.StatusPartialContent, nil
}

func validateAllowlistedURL(rawURL string, allowlist []string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("disk.import-image invalid source_url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("disk.import-image source_url scheme must be http/https")
	}
	if len(allowlist) == 0 {
		return fmt.Errorf("disk.import-image allowlist required")
	}
	host := strings.ToLower(u.Hostname())
	for _, allowed := range allowlist {
		if host == strings.ToLower(strings.TrimSpace(allowed)) {
			return nil
		}
	}
	return fmt.Errorf("disk.import-image source_url host %q not in allowlist", host)
}

func parseSmartStatus(data []byte) string {
	var out smartStatusOut
	if err := json.Unmarshal(data, &out); err != nil {
		return "unknown"
	}
	if out.SmartStatus.Passed {
		return "passed"
	}
	return "failed"
}

func toString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		return ""
	}
}

func toUint64(v interface{}) uint64 {
	switch t := v.(type) {
	case float64:
		if t < 0 {
			return 0
		}
		return uint64(t)
	case int64:
		if t < 0 {
			return 0
		}
		return uint64(t)
	case uint64:
		return t
	case json.Number:
		u, _ := strconv.ParseUint(t.String(), 10, 64)
		return u
	case string:
		u, _ := strconv.ParseUint(strings.TrimSpace(t), 10, 64)
		return u
	default:
		return 0
	}
}

func toBool(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t != 0
	case int:
		return t != 0
	case string:
		t = strings.TrimSpace(strings.ToLower(t))
		return t == "1" || t == "true" || t == "yes"
	default:
		return false
	}
}

func fmtLower(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}
