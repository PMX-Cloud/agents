// kernel_events.go tails /dev/kmsg and emits structured host.events entries
// for OOMs, IO errors, and link-state changes.
package collectors

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// KernelEventsCollector tails /dev/kmsg for notable kernel events.
type KernelEventsCollector struct {
	path   string
	offset uint64
}

func NewKernelEventsCollector() *KernelEventsCollector {
	return &KernelEventsCollector{path: "/dev/kmsg"}
}
func NewKernelEventsCollectorWithPath(p string) *KernelEventsCollector {
	return &KernelEventsCollector{path: p}
}
func (c *KernelEventsCollector) Name() string { return "kernel_events" }

// eventPattern is a regex + event name pair.
type eventPattern struct {
	re        *regexp.Regexp
	eventType string
}

// eventPatterns is the documented set of kernel event patterns we care about.
// OOM killer, IO errors, and network link state changes.
var eventPatterns = []eventPattern{
	{regexp.MustCompile(`(?i)oom[_-]?killer`), "oom"},
	{regexp.MustCompile(`(?i)Out of memory`), "oom"},
	{regexp.MustCompile(`(?i)(I/O error|io error|EXT4-fs error|XFS.*error)`), "io_error"},
	{regexp.MustCompile(`(?i)Link is (Up|Down)`), "link_state"},
	{regexp.MustCompile(`(?i)NIC Link is (Up|Down)`), "link_state"},
	{regexp.MustCompile(`(?i)(SCSI|ata)\d+.*error`), "io_error"},
}

// KernelEvent is emitted as a host.event metric.
type KernelEvent struct {
	EventType string
	Message   string
	Timestamp time.Time
}

func (c *KernelEventsCollector) Collect(ctx context.Context) ([]Metric, error) {
	f, err := os.Open(c.path)
	if err != nil {
		return nil, fmt.Errorf("kernel_events: open %s: %w", c.path, err)
	}
	defer f.Close()

	// /dev/kmsg lines: "<priority>,<seq>,<timestamp_us>,-;<message>"
	var metrics []Metric
	scanner := bufio.NewScanner(f)
	// Non-blocking read: set deadline via context.
	if dl, ok := ctx.Deadline(); ok {
		_ = dl // advisory only for this scanner approach
	}

	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount > 4096 { // cap to avoid blocking forever
			break
		}
		line := scanner.Text()
		msg := parseKmsgMessage(line)
		if msg == "" {
			continue
		}
		ts := parseKmsgTimestamp(line)
		for _, p := range eventPatterns {
			if p.re.MatchString(msg) {
				metrics = append(metrics, Metric{
					Name:      "host_kernel_event",
					Value:     1,
					Timestamp: ts,
					Labels:    map[string]string{"event_type": p.eventType, "message": truncate(msg, 120)},
				})
				break
			}
		}
	}
	return metrics, nil
}

// parseKmsgMessage extracts the human-readable message from a /dev/kmsg line.
func parseKmsgMessage(line string) string {
	// Format: "<pri>,<seq>,<ts_us>,-;<msg>"
	parts := strings.SplitN(line, ";", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// parseKmsgTimestamp extracts the monotonic timestamp (microseconds) from a kmsg line.
func parseKmsgTimestamp(line string) time.Time {
	parts := strings.SplitN(line, ",", 4)
	if len(parts) >= 3 {
		us, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err == nil {
			return time.Now().Add(-time.Duration(us) * time.Microsecond)
		}
	}
	return time.Now()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
