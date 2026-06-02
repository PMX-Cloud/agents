// filesystem.go calls statfs on each non-pseudo mount in /proc/mounts.
package collectors

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// FilesystemCollector reads /proc/mounts and calls statfs on each real filesystem.
type FilesystemCollector struct{ mountsPath string }

func NewFilesystemCollector() *FilesystemCollector {
	return &FilesystemCollector{mountsPath: "/proc/mounts"}
}
func NewFilesystemCollectorWithPath(p string) *FilesystemCollector {
	return &FilesystemCollector{mountsPath: p}
}
func (c *FilesystemCollector) Name() string { return "filesystem" }

// pseudo filesystems that carry no meaningful disk usage.
var pseudoFS = map[string]bool{
	"sysfs": true, "proc": true, "devtmpfs": true, "devpts": true, "tmpfs": true,
	"cgroup": true, "cgroup2": true, "pstore": true, "bpf": true, "hugetlbfs": true,
	"mqueue": true, "debugfs": true, "tracefs": true, "securityfs": true,
	"fusectl": true, "fuse": true,
}

func (c *FilesystemCollector) Collect(_ context.Context) ([]Metric, error) {
	data, err := os.ReadFile(c.mountsPath)
	if err != nil {
		return nil, fmt.Errorf("filesystem: read %s: %w", c.mountsPath, err)
	}

	now := time.Now()
	var metrics []Metric
	seen := map[string]bool{}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		mountpoint := fields[1]
		fstype := fields[2]
		if pseudoFS[fstype] {
			continue
		}
		if seen[mountpoint] {
			continue
		}
		seen[mountpoint] = true

		var stat unix.Statfs_t
		if err := unix.Statfs(mountpoint, &stat); err != nil {
			continue // skip unreadable mounts (e.g. network mounts that went away)
		}

		blockSize := float64(stat.Bsize)
		total := float64(stat.Blocks) * blockSize
		avail := float64(stat.Bavail) * blockSize
		used := total - avail

		lbl := map[string]string{"mount": mountpoint, "fstype": fstype}
		metrics = append(metrics,
			Metric{Name: "host_fs_total_bytes", Value: total, Timestamp: now, Labels: lbl},
			Metric{Name: "host_fs_used_bytes", Value: used, Timestamp: now, Labels: lbl},
			Metric{Name: "host_fs_available_bytes", Value: avail, Timestamp: now, Labels: lbl},
		)
	}
	return metrics, nil
}
