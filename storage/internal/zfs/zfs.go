// Package zfs implements zfs.* commands for pmx-storage.
package zfs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pmx-cloud/agents/storage/internal/storageexec"
)

var (
	allowedTopologies = map[string]bool{
		"mirror": true,
		"raidz1": true,
		"raidz2": true,
		"raidz3": true,
		"stripe": true,
	}
	allowedProps = map[string]bool{
		"compression": true,
		"atime":       true,
		"recordsize":  true,
		"sync":        true,
		"dedup":       true,
	}
)

type PoolCreateParams struct {
	Name     string   `json:"name"`
	Topology string   `json:"topology"`
	Devices  []string `json:"devices"`
}

type PoolDestroyParams struct {
	Name  string `json:"name"`
	Force bool   `json:"force"`
}

type DatasetCreateParams struct {
	Dataset    string         `json:"dataset"`
	Options    map[string]any `json:"options"`
	AllowDedup bool           `json:"allow_dedup"`
}

type DatasetDestroyParams struct {
	Dataset   string `json:"dataset"`
	Recursive bool   `json:"recursive"`
}

type SnapshotCreateParams struct {
	Snapshot string `json:"snapshot"`
}

type SnapshotSendParams struct {
	Snapshot    string `json:"snapshot"`
	Destination string `json:"destination"`
}

type ScrubParams struct {
	Pool string `json:"pool"`
}

type TuneParams struct {
	Dataset    string `json:"dataset"`
	Property   string `json:"property"`
	Value      string `json:"value"`
	AllowDedup bool   `json:"allow_dedup"`
}

// PoolStatus is the structured zfs.status payload the backend consumes.
type PoolStatus struct {
	Pools []PoolInfo `json:"pools"`
}

// PoolInfo describes one pool: capacity + health from `zpool list`, vdev
// topology (best-effort) from `zpool status -j`.
type PoolInfo struct {
	Name        string     `json:"name"`
	State       string     `json:"state"`
	SizeBytes   int64      `json:"size_bytes"`
	AllocBytes  int64      `json:"alloc_bytes"`
	FreeBytes   int64      `json:"free_bytes"`
	FragPercent *float64   `json:"frag_percent,omitempty"`
	DedupRatio  *float64   `json:"dedup_ratio,omitempty"`
	Vdevs       []VdevInfo `json:"vdevs"`
}

// VdevInfo is a node in the pool's vdev tree.
type VdevInfo struct {
	Name     string     `json:"name"`
	Type     string     `json:"type"`
	State    string     `json:"state"`
	Children []VdevInfo `json:"children,omitempty"`
}

// Status returns a structured snapshot of every ZFS pool. Capacity, health and
// fragmentation come from `zpool list -Hp` (exact byte values); vdev topology is
// merged best-effort from `zpool status -j`. A host with no pools returns an
// empty list (not an error) so the backend never fabricates pools. If ZFS is not
// installed at all, `zpool list` fails and we also return an empty list.
func Status(ctx context.Context, ex storageexec.Interface) (json.RawMessage, error) {
	listRes, err := ex.Zpool(ctx, "list", "-Hp", "-o", "name,size,alloc,free,frag,dedup,health")
	if err != nil {
		// No ZFS / no pools -> empty, not an error. The UI shows an empty state.
		return json.Marshal(PoolStatus{Pools: []PoolInfo{}})
	}
	pools := parseZpoolList(listRes.StdoutString())

	// Best-effort vdev topology. Failure leaves Vdevs empty but keeps capacity.
	if statusRes, statusErr := ex.Zpool(ctx, "status", "-j"); statusErr == nil {
		vdevsByPool := parseZpoolStatusVdevs(statusRes.Stdout)
		for i := range pools {
			if v, ok := vdevsByPool[pools[i].Name]; ok {
				pools[i].Vdevs = v
			}
		}
	}

	for i := range pools {
		if pools[i].Vdevs == nil {
			pools[i].Vdevs = []VdevInfo{}
		}
	}
	return json.Marshal(PoolStatus{Pools: pools})
}

// parseZpoolList parses tab-separated `zpool list -Hp -o name,size,alloc,free,frag,dedup,health`.
func parseZpoolList(out string) []PoolInfo {
	pools := []PoolInfo{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}
		info := PoolInfo{
			Name:       fields[0],
			SizeBytes:  parseInt64(fields[1]),
			AllocBytes: parseInt64(fields[2]),
			FreeBytes:  parseInt64(fields[3]),
			State:      strings.ToUpper(strings.TrimSpace(fields[6])),
			Vdevs:      []VdevInfo{},
		}
		if frag := parsePercent(fields[4]); frag != nil {
			info.FragPercent = frag
		}
		if dedup := parseRatio(fields[5]); dedup != nil {
			info.DedupRatio = dedup
		}
		pools = append(pools, info)
	}
	return pools
}

// zpoolStatusJSON mirrors the OpenZFS 2.2+ `zpool status -j` shape (nested
// vdev maps keyed by name). Older ZFS without -j simply yields no topology.
type zpoolStatusJSON struct {
	Pools map[string]struct {
		Name  string                  `json:"name"`
		State string                  `json:"state"`
		Vdevs map[string]zpoolVdevRaw `json:"vdevs"`
	} `json:"pools"`
}

type zpoolVdevRaw struct {
	Name     string                  `json:"name"`
	VdevType string                  `json:"vdev_type"`
	State    string                  `json:"state"`
	Vdevs    map[string]zpoolVdevRaw `json:"vdevs"`
}

// parseZpoolStatusVdevs returns the vdev children of each pool's root vdev.
func parseZpoolStatusVdevs(raw []byte) map[string][]VdevInfo {
	out := map[string][]VdevInfo{}
	var parsed zpoolStatusJSON
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return out
	}
	for poolName, pool := range parsed.Pools {
		children := []VdevInfo{}
		// The top-level vdev map is keyed by the pool name (the root vdev); its
		// children are the real vdevs (mirror-0, raidz1-0, bare disks, ...).
		for _, root := range pool.Vdevs {
			for _, child := range sortedVdevs(root.Vdevs) {
				children = append(children, convertVdev(child))
			}
		}
		out[poolName] = children
	}
	return out
}

func convertVdev(v zpoolVdevRaw) VdevInfo {
	info := VdevInfo{
		Name:  v.Name,
		Type:  normalizeVdevType(v.VdevType),
		State: strings.ToUpper(strings.TrimSpace(v.State)),
	}
	for _, child := range sortedVdevs(v.Vdevs) {
		info.Children = append(info.Children, convertVdev(child))
	}
	return info
}

func sortedVdevs(m map[string]zpoolVdevRaw) []zpoolVdevRaw {
	out := make([]zpoolVdevRaw, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func normalizeVdevType(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	switch {
	case t == "disk" || t == "file":
		return "disk"
	case t == "mirror":
		return "mirror"
	case strings.HasPrefix(t, "raidz3"):
		return "raidz2"
	case strings.HasPrefix(t, "raidz2"):
		return "raidz2"
	case strings.HasPrefix(t, "raidz"):
		return "raidz1"
	case t == "spare":
		return "spare"
	case t == "cache" || t == "l2cache":
		return "cache"
	case t == "log" || t == "slog":
		return "log"
	default:
		return "disk"
	}
}

func parseInt64(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func parsePercent(s string) *float64 {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	if s == "" || s == "-" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &v
}

func parseRatio(s string) *float64 {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "x"))
	if s == "" || s == "-" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &v
}

func PoolCreate(ctx context.Context, ex storageexec.Interface, p PoolCreateParams) error {
	if !isSafeToken(p.Name) {
		return fmt.Errorf("zfs.pool.create: invalid pool name")
	}
	topology := strings.ToLower(strings.TrimSpace(p.Topology))
	if !allowedTopologies[topology] {
		return fmt.Errorf("zfs.pool.create: topology %q is not allowed", p.Topology)
	}
	if len(p.Devices) == 0 {
		return fmt.Errorf("zfs.pool.create: at least one device is required")
	}
	for _, dev := range p.Devices {
		if !isDevicePath(dev) {
			return fmt.Errorf("zfs.pool.create: invalid device %q", dev)
		}
	}

	args := []string{"create", p.Name}
	if topology != "stripe" {
		args = append(args, topology)
	}
	args = append(args, p.Devices...)
	if _, err := ex.Zpool(ctx, args...); err != nil {
		return fmt.Errorf("zfs.pool.create: %w", err)
	}
	return nil
}

func PoolDestroy(ctx context.Context, ex storageexec.Interface, p PoolDestroyParams) error {
	if !isSafeToken(p.Name) {
		return fmt.Errorf("zfs.pool.destroy: invalid pool name")
	}
	if !p.Force {
		res, err := ex.Zfs(ctx, "list", "-H", "-t", "snapshot", "-o", "name", "-r", p.Name)
		if err != nil {
			return fmt.Errorf("zfs.pool.destroy: failed to verify snapshots before destroy: %w", err)
		}
		if strings.TrimSpace(res.StdoutString()) != "" {
			return fmt.Errorf("zfs.pool.destroy: pool has snapshots; force=true required")
		}
	}
	if _, err := ex.Zpool(ctx, "destroy", p.Name); err != nil {
		return fmt.Errorf("zfs.pool.destroy: %w", err)
	}
	return nil
}

func DatasetCreate(ctx context.Context, ex storageexec.Interface, p DatasetCreateParams) error {
	if !isSafeDataset(p.Dataset) {
		return fmt.Errorf("zfs.dataset.create: invalid dataset")
	}
	args := []string{"create"}
	keys := make([]string, 0, len(p.Options))
	for k := range p.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !allowedProps[key] {
			return fmt.Errorf("zfs.dataset.create: property %q is not allowed", key)
		}
		value := fmt.Sprintf("%v", p.Options[key])
		if key == "dedup" && strings.EqualFold(strings.TrimSpace(value), "on") && !p.AllowDedup {
			return fmt.Errorf("zfs.dataset.create: dedup=on requires allow_dedup=true")
		}
		if !isSafeValue(value) {
			return fmt.Errorf("zfs.dataset.create: unsafe value for %q", key)
		}
		args = append(args, "-o", key+"="+value)
	}
	args = append(args, p.Dataset)
	if _, err := ex.Zfs(ctx, args...); err != nil {
		return fmt.Errorf("zfs.dataset.create: %w", err)
	}
	return nil
}

func DatasetDestroy(ctx context.Context, ex storageexec.Interface, p DatasetDestroyParams) error {
	if !isSafeDataset(p.Dataset) {
		return fmt.Errorf("zfs.dataset.destroy: invalid dataset")
	}
	if !p.Recursive {
		return fmt.Errorf("zfs.dataset.destroy: recursive=true required")
	}
	if _, err := ex.Zfs(ctx, "destroy", "-r", p.Dataset); err != nil {
		return fmt.Errorf("zfs.dataset.destroy: %w", err)
	}
	return nil
}

func SnapshotCreate(ctx context.Context, ex storageexec.Interface, p SnapshotCreateParams) error {
	if !isSafeSnapshot(p.Snapshot) {
		return fmt.Errorf("zfs.snapshot.create: invalid snapshot")
	}
	if _, err := ex.Zfs(ctx, "snapshot", p.Snapshot); err != nil {
		return fmt.Errorf("zfs.snapshot.create: %w", err)
	}
	return nil
}

func SnapshotSend(ctx context.Context, ex storageexec.Interface, p SnapshotSendParams) error {
	if !isSafeSnapshot(p.Snapshot) {
		return fmt.Errorf("zfs.snapshot.send: invalid snapshot")
	}
	destinationPath, err := resolveSnapshotDestination(p.Destination)
	if err != nil {
		return err
	}
	res, err := ex.Zfs(ctx, "send", "-R", p.Snapshot)
	if err != nil {
		return fmt.Errorf("zfs.snapshot.send: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destinationPath), 0o700); err != nil {
		return fmt.Errorf("zfs.snapshot.send: create destination parent: %w", err)
	}
	if err := os.WriteFile(destinationPath, res.Stdout, 0o600); err != nil {
		return fmt.Errorf("zfs.snapshot.send: write destination: %w", err)
	}
	return nil
}

func ScrubStart(ctx context.Context, ex storageexec.Interface, p ScrubParams) error {
	if !isSafeToken(p.Pool) {
		return fmt.Errorf("zfs.scrub.start: invalid pool")
	}
	if _, err := ex.Zpool(ctx, "scrub", p.Pool); err != nil {
		return fmt.Errorf("zfs.scrub.start: %w", err)
	}
	return nil
}

func ScrubStatus(ctx context.Context, ex storageexec.Interface, p ScrubParams) (json.RawMessage, error) {
	if !isSafeToken(p.Pool) {
		return nil, fmt.Errorf("zfs.scrub.status: invalid pool")
	}
	res, err := ex.Zpool(ctx, "status", p.Pool)
	if err != nil {
		return nil, fmt.Errorf("zfs.scrub.status: %w", err)
	}
	status := "unknown"
	s := strings.ToLower(res.StdoutString())
	switch {
	case strings.Contains(s, "scrub in progress"):
		status = "running"
	case strings.Contains(s, "scrub repaired") || strings.Contains(s, "scrub completed"):
		status = "completed"
	}
	payload, _ := json.Marshal(map[string]string{"pool": p.Pool, "status": status})
	return payload, nil
}

func Tune(ctx context.Context, ex storageexec.Interface, p TuneParams) error {
	if !isSafeDataset(p.Dataset) {
		return fmt.Errorf("zfs.tune: invalid dataset")
	}
	prop := strings.TrimSpace(p.Property)
	if !allowedProps[prop] {
		return fmt.Errorf("zfs.tune: property %q is not allowed", prop)
	}
	if prop == "dedup" && strings.EqualFold(strings.TrimSpace(p.Value), "on") && !p.AllowDedup {
		return fmt.Errorf("zfs.tune: dedup=on requires allow_dedup=true")
	}
	if !isSafeValue(p.Value) {
		return fmt.Errorf("zfs.tune: invalid property value")
	}
	if _, err := ex.Zfs(ctx, "set", prop+"="+p.Value, p.Dataset); err != nil {
		return fmt.Errorf("zfs.tune: %w", err)
	}
	return nil
}

func isSafeToken(v string) bool {
	if strings.TrimSpace(v) == "" {
		return false
	}
	for _, c := range v {
		if !(c == '-' || c == '_' || c == '.' || c == ':' || c == '/' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func isSafeDataset(v string) bool {
	return strings.Contains(v, "/") && isSafeToken(v)
}

func isSafeSnapshot(v string) bool {
	if !strings.Contains(v, "@") {
		return false
	}
	for _, c := range v {
		if !(c == '-' || c == '_' || c == '.' || c == ':' || c == '/' || c == '@' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func isSafeValue(v string) bool {
	return !strings.ContainsAny(v, "\n\r\x00;&|`$")
}

func isDevicePath(v string) bool {
	return strings.HasPrefix(v, "/dev/") && !strings.Contains(v, "..")
}

func resolveSnapshotDestination(raw string) (string, error) {
	dest := strings.TrimSpace(raw)
	if dest == "" {
		return "", fmt.Errorf("zfs.snapshot.send: destination is required")
	}
	if strings.HasPrefix(dest, "ssh://") {
		return "", fmt.Errorf("zfs.snapshot.send: ssh destinations are not supported by this command path")
	}
	if strings.HasPrefix(dest, "file://") {
		dest = strings.TrimPrefix(dest, "file://")
	}
	if !filepath.IsAbs(dest) {
		return "", fmt.Errorf("zfs.snapshot.send: destination must be an absolute path or file:// URL")
	}
	clean := filepath.Clean(dest)
	if !isSafeToken(clean) || strings.Contains(clean, "..") {
		return "", fmt.Errorf("zfs.snapshot.send: destination failed validation")
	}
	if strings.HasPrefix(clean, "/dev/") {
		return "", fmt.Errorf("zfs.snapshot.send: destination cannot target /dev")
	}
	return clean, nil
}
