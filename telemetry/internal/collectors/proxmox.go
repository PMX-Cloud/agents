// proxmox.go runs pvesh to collect VM/CT status counts every 30s.
// Read-only: no pvesh set, no pvesh create. Five-second timeout per call.
package collectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// ProxmoxCollector runs pvesh get /cluster/resources every 30s.
type ProxmoxCollector struct {
	mu      sync.Mutex
	last    []Metric
	lastRun time.Time
	enabled bool
}

func NewProxmoxCollector(enabled bool) *ProxmoxCollector {
	return &ProxmoxCollector{enabled: enabled}
}
func (c *ProxmoxCollector) Name() string { return "proxmox" }

const proxmoxInterval = 30 * time.Second

func (c *ProxmoxCollector) Collect(ctx context.Context) ([]Metric, error) {
	if !c.enabled {
		return nil, nil
	}

	c.mu.Lock()
	if time.Since(c.lastRun) < proxmoxInterval && len(c.last) > 0 {
		cached := c.last
		c.mu.Unlock()
		return cached, nil
	}
	c.mu.Unlock()

	metrics, err := c.fetchFromPVesh(ctx)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.last = metrics
	c.lastRun = time.Now()
	c.mu.Unlock()

	return metrics, nil
}

type pveshResource struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

func (c *ProxmoxCollector) fetchFromPVesh(ctx context.Context) ([]Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx2, "pvesh", "get", "/cluster/resources", "--output-format", "json")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &bytes.Buffer{}

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("proxmox: pvesh: %w", err)
	}

	var resources []pveshResource
	if err := json.Unmarshal(out.Bytes(), &resources); err != nil {
		return nil, fmt.Errorf("proxmox: parse: %w", err)
	}

	// Count by type + status.
	counts := map[string]map[string]float64{}
	for _, r := range resources {
		if counts[r.Type] == nil {
			counts[r.Type] = map[string]float64{}
		}
		counts[r.Type][r.Status]++
	}

	now := time.Now()
	var metrics []Metric
	for rtype, statuses := range counts {
		for status, count := range statuses {
			metrics = append(metrics, Metric{
				Name:      "proxmox_resource_count",
				Value:     count,
				Timestamp: now,
				Labels:    map[string]string{"type": rtype, "status": status},
			})
		}
	}
	return metrics, nil
}
