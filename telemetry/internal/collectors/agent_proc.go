// agent_proc.go reads /proc/<pid>/status for each pmx-* sibling process.
package collectors

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// AgentProcCollector monitors sibling pmx-* processes via /proc/<pid>/status.
type AgentProcCollector struct{ procPath string }

func NewAgentProcCollector() *AgentProcCollector { return &AgentProcCollector{procPath: "/proc"} }
func NewAgentProcCollectorWithPath(p string) *AgentProcCollector {
	return &AgentProcCollector{procPath: p}
}
func (c *AgentProcCollector) Name() string { return "agent_proc" }

func (c *AgentProcCollector) Collect(_ context.Context) ([]Metric, error) {
	entries, err := os.ReadDir(c.procPath)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var metrics []Metric

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only numeric directories (PIDs).
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		pid := entry.Name()
		statusPath := filepath.Join(c.procPath, pid, "status")

		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue // Process may have exited.
		}

		name := ""
		vmRSS := int64(0)
		threads := int64(0)
		fdSize := int64(0)

		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := scanner.Text()
			kv := strings.SplitN(line, ":", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.TrimSpace(kv[0])
			val := strings.TrimSpace(kv[1])
			switch key {
			case "Name":
				name = val
			case "VmRSS":
				// Value is in kB.
				v, _ := strconv.ParseInt(strings.Fields(val)[0], 10, 64)
				vmRSS = v * 1024
			case "Threads":
				threads, _ = strconv.ParseInt(val, 10, 64)
			case "FDSize":
				fdSize, _ = strconv.ParseInt(val, 10, 64)
			}
		}

		// Only report pmx-* processes.
		if !strings.HasPrefix(name, "pmx-") {
			continue
		}

		lbl := map[string]string{"agent": name, "pid": pid}
		metrics = append(metrics,
			Metric{Name: "agent_rss_bytes", Value: float64(vmRSS), Timestamp: now, Labels: lbl},
			Metric{Name: "agent_threads", Value: float64(threads), Timestamp: now, Labels: lbl},
			Metric{Name: "agent_fds", Value: float64(fdSize), Timestamp: now, Labels: lbl},
		)
	}
	return metrics, nil
}
