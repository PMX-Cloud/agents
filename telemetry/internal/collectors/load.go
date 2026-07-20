// load.go reads /proc/loadavg and emits load1/5/15 metrics.
package collectors

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// LoadCollector reads /proc/loadavg.
type LoadCollector struct{ path string }

func NewLoadCollector() *LoadCollector                 { return &LoadCollector{path: "/proc/loadavg"} }
func NewLoadCollectorWithPath(p string) *LoadCollector { return &LoadCollector{path: p} }
func (c *LoadCollector) Name() string                  { return "load" }

func (c *LoadCollector) Collect(_ context.Context) ([]Metric, error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, fmt.Errorf("load: read %s: %w", c.path, err)
	}
	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) < 3 {
		return nil, fmt.Errorf("load: unexpected format: %q", string(data))
	}
	parse := func(s string) float64 { v, _ := strconv.ParseFloat(s, 64); return v }
	now := time.Now()
	return []Metric{
		{Name: "host_load1", Value: parse(fields[0]), Timestamp: now},
		{Name: "host_load5", Value: parse(fields[1]), Timestamp: now},
		{Name: "host_load15", Value: parse(fields[2]), Timestamp: now},
	}, nil
}
