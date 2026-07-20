// memory.go parses /proc/meminfo.
package collectors

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// MemoryCollector reads /proc/meminfo.
type MemoryCollector struct{ path string }

// NewMemoryCollector creates a MemoryCollector.
func NewMemoryCollector() *MemoryCollector { return &MemoryCollector{path: "/proc/meminfo"} }

// NewMemoryCollectorWithPath creates a MemoryCollector for testing.
func NewMemoryCollectorWithPath(p string) *MemoryCollector { return &MemoryCollector{path: p} }

func (c *MemoryCollector) Name() string { return "memory" }

func (c *MemoryCollector) Collect(_ context.Context) ([]Metric, error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, fmt.Errorf("memory: read %s: %w", c.path, err)
	}

	fields := map[string]int64{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		valStr := strings.TrimSpace(kv[1])
		// Values are in kB; strip " kB".
		valStr = strings.TrimSuffix(valStr, " kB")
		v, err := strconv.ParseInt(valStr, 10, 64)
		if err != nil {
			continue
		}
		fields[key] = v * 1024 // convert to bytes
	}

	now := time.Now()
	toF := func(key string) float64 { return float64(fields[key]) }

	return []Metric{
		{Name: "host_memory_total_bytes", Value: toF("MemTotal"), Timestamp: now},
		{Name: "host_memory_available_bytes", Value: toF("MemAvailable"), Timestamp: now},
		{Name: "host_memory_cached_bytes", Value: toF("Cached"), Timestamp: now},
		{Name: "host_memory_swap_used_bytes", Value: toF("SwapTotal") - toF("SwapFree"), Timestamp: now},
	}, nil
}
