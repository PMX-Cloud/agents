// cpu.go parses /proc/stat and emits per-total CPU time counters.
// Rates (user%, system%, etc.) are computed by the push layer via diff.
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

// CPUCollector reads /proc/stat.
type CPUCollector struct {
	mu   sync.Mutex
	prev cpuStat
	path string // override for testing
}

type cpuStat struct {
	user    float64
	nice    float64
	system  float64
	idle    float64
	iowait  float64
	irq     float64
	softirq float64
	steal   float64
	ts      time.Time
}

func (s *cpuStat) total() float64 {
	return s.user + s.nice + s.system + s.idle + s.iowait + s.irq + s.softirq + s.steal
}

// NewCPUCollector creates a CPUCollector.
func NewCPUCollector() *CPUCollector { return &CPUCollector{path: "/proc/stat"} }

// NewCPUCollectorWithPath creates a CPUCollector reading from a custom path (tests).
func NewCPUCollectorWithPath(p string) *CPUCollector { return &CPUCollector{path: p} }

func (c *CPUCollector) Name() string { return "cpu" }

func (c *CPUCollector) Collect(_ context.Context) ([]Metric, error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, fmt.Errorf("cpu: read %s: %w", c.path, err)
	}
	cur, err := parseCPUStat(data)
	if err != nil {
		return nil, fmt.Errorf("cpu: parse: %w", err)
	}

	now := time.Now()
	c.mu.Lock()
	prev := c.prev
	c.prev = cur
	c.prev.ts = now
	c.mu.Unlock()

	metrics := []Metric{
		{Name: "host_cpu_user_seconds", Value: cur.user, Timestamp: now},
		{Name: "host_cpu_system_seconds", Value: cur.system, Timestamp: now},
		{Name: "host_cpu_idle_seconds", Value: cur.idle, Timestamp: now},
		{Name: "host_cpu_iowait_seconds", Value: cur.iowait, Timestamp: now},
	}

	// Emit CPU core count on every sample so the backend can populate nodes.cpuCores.
	if count := parseCPUCount(data); count > 0 {
		metrics = append(metrics, Metric{Name: "host_cpu_count", Value: float64(count), Timestamp: now})
	}

	// Emit usage percentage if we have a previous sample.
	if !prev.ts.IsZero() {
		dt := now.Sub(prev.ts).Seconds()
		if dt > 0 {
			dtUser := (cur.user - prev.user) / dt
			dtSystem := (cur.system - prev.system) / dt
			dtIdle := (cur.idle - prev.idle) / dt
			dtIowait := (cur.iowait - prev.iowait) / dt
			metrics = append(metrics,
				Metric{Name: "host_cpu_user_rate", Value: dtUser, Timestamp: now},
				Metric{Name: "host_cpu_system_rate", Value: dtSystem, Timestamp: now},
				Metric{Name: "host_cpu_idle_rate", Value: dtIdle, Timestamp: now},
				Metric{Name: "host_cpu_iowait_rate", Value: dtIowait, Timestamp: now},
			)
		}
	}
	return metrics, nil
}

// parseCPUStat extracts the "cpu" (total) line from /proc/stat content.
func parseCPUStat(data []byte) (cpuStat, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			return cpuStat{}, fmt.Errorf("cpu: unexpected field count: %d", len(fields))
		}
		parse := func(s string) float64 {
			v, _ := strconv.ParseFloat(s, 64)
			return v / 100.0 // jiffies → approximate seconds (USER_HZ=100)
		}
		return cpuStat{
			user:    parse(fields[1]),
			nice:    parse(fields[2]),
			system:  parse(fields[3]),
			idle:    parse(fields[4]),
			iowait:  parse(fields[5]),
			irq:     parse(fields[6]),
			softirq: parse(fields[7]),
		}, nil
	}
	return cpuStat{}, fmt.Errorf("cpu: 'cpu' line not found in %d bytes", len(data))
}

// parseCPUCount counts the number of individual CPU lines (cpu0, cpu1, …)
// in /proc/stat content. This is the logical core count seen by the kernel.
func parseCPUCount(data []byte) int {
	count := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		// Individual CPU lines start with "cpuN " where N is a digit.
		if len(line) > 3 && strings.HasPrefix(line, "cpu") && line[3] >= '0' && line[3] <= '9' {
			count++
		}
	}
	return count
}
