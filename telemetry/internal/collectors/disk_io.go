// disk_io.go parses /proc/diskstats and emits per-device byte-rate metrics.
package collectors

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DiskIOCollector reads /proc/diskstats.
type DiskIOCollector struct {
	mu   sync.Mutex
	prev map[string]diskStat
	path string
}

type diskStat struct {
	readBytes  float64
	writeBytes float64
	ts         time.Time
}

func NewDiskIOCollector() *DiskIOCollector { return &DiskIOCollector{path: "/proc/diskstats"} }
func NewDiskIOCollectorWithPath(p string) *DiskIOCollector {
	return &DiskIOCollector{path: p}
}
func (c *DiskIOCollector) Name() string { return "disk_io" }

func (c *DiskIOCollector) Collect(_ context.Context) ([]Metric, error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, fmt.Errorf("disk_io: read %s: %w", c.path, err)
	}

	now := time.Now()
	cur := map[string]diskStat{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 14 {
			continue
		}
		name := fields[2]
		// Skip loopbacks (loop*), ram disks (ram*), and device-mapper (dm-*).
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
			continue
		}
		readSectors, _ := strconv.ParseFloat(fields[5], 64)
		writeSectors, _ := strconv.ParseFloat(fields[9], 64)
		cur[name] = diskStat{
			readBytes:  readSectors * 512,
			writeBytes: writeSectors * 512,
			ts:         now,
		}
	}

	c.mu.Lock()
	prev := c.prev
	c.prev = cur
	c.mu.Unlock()

	var metrics []Metric
	for name, stat := range cur {
		metrics = append(metrics,
			Metric{Name: "host_disk_read_bytes_total", Value: stat.readBytes, Timestamp: now,
				Labels: map[string]string{"device": name}},
			Metric{Name: "host_disk_write_bytes_total", Value: stat.writeBytes, Timestamp: now,
				Labels: map[string]string{"device": name}},
		)
		if prev != nil {
			if p, ok := prev[name]; ok {
				dt := now.Sub(p.ts).Seconds()
				if dt > 0 {
					metrics = append(metrics,
						Metric{Name: "host_disk_read_bytes_rate", Value: (stat.readBytes - p.readBytes) / dt,
							Timestamp: now, Labels: map[string]string{"device": name}},
						Metric{Name: "host_disk_write_bytes_rate", Value: (stat.writeBytes - p.writeBytes) / dt,
							Timestamp: now, Labels: map[string]string{"device": name}},
					)
				}
			}
		}
	}
	return metrics, nil
}
