// net_io.go parses /proc/net/dev and emits per-NIC rx/tx byte-rate metrics.
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

// NetIOCollector reads /proc/net/dev.
type NetIOCollector struct {
	mu   sync.Mutex
	prev map[string]netStat
	path string
}

type netStat struct {
	rxBytes float64
	txBytes float64
	ts      time.Time
}

func NewNetIOCollector() *NetIOCollector                 { return &NetIOCollector{path: "/proc/net/dev"} }
func NewNetIOCollectorWithPath(p string) *NetIOCollector { return &NetIOCollector{path: p} }
func (c *NetIOCollector) Name() string                   { return "net_io" }

func (c *NetIOCollector) Collect(_ context.Context) ([]Metric, error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, fmt.Errorf("net_io: read %s: %w", c.path, err)
	}

	now := time.Now()
	cur := map[string]netStat{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Skip header lines (first two).
	scanner.Scan()
	scanner.Scan()
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, _ := strconv.ParseFloat(fields[0], 64)
		tx, _ := strconv.ParseFloat(fields[8], 64)
		cur[name] = netStat{rxBytes: rx, txBytes: tx, ts: now}
	}

	c.mu.Lock()
	prev := c.prev
	c.prev = cur
	c.mu.Unlock()

	var metrics []Metric
	for name, stat := range cur {
		lbl := map[string]string{"iface": name}
		metrics = append(metrics,
			Metric{Name: "host_net_rx_bytes_total", Value: stat.rxBytes, Timestamp: now, Labels: lbl},
			Metric{Name: "host_net_tx_bytes_total", Value: stat.txBytes, Timestamp: now, Labels: lbl},
		)
		if prev != nil {
			if p, ok := prev[name]; ok {
				dt := now.Sub(p.ts).Seconds()
				if dt > 0 {
					metrics = append(metrics,
						Metric{Name: "host_net_rx_bytes_rate", Value: (stat.rxBytes - p.rxBytes) / dt,
							Timestamp: now, Labels: lbl},
						Metric{Name: "host_net_tx_bytes_rate", Value: (stat.txBytes - p.txBytes) / dt,
							Timestamp: now, Labels: lbl},
					)
				}
			}
		}
	}
	return metrics, nil
}
