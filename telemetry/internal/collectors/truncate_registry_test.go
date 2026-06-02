package collectors_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/telemetry/internal/collectors"
)

// TestKernelEvents_LongMessage exercises the truncate branch (message > 120 chars).
func TestKernelEvents_LongMessage(t *testing.T) {
	long := strings.Repeat("A", 200) // 200 chars > 120
	content := "6,100,500000,-;Out of memory: " + long + "\n"

	tmpFile := filepath.Join(t.TempDir(), "kmsg")
	os.WriteFile(tmpFile, []byte(content), 0o644)

	c := collectors.NewKernelEventsCollectorWithPath(tmpFile)
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, m := range metrics {
		if label := m.Labels["message"]; len(label) > 120 {
			t.Errorf("message was not truncated: len=%d", len(label))
		}
	}
}

// TestKernelEvents_NoSemicolon tests the parseKmsgMessage empty path
// (line without ';' separator).
func TestKernelEvents_NoSemicolon(t *testing.T) {
	content := "6,100,500000,-\n" // no semicolon → message is empty → should produce no metric
	tmpFile := filepath.Join(t.TempDir(), "kmsg")
	os.WriteFile(tmpFile, []byte(content), 0o644)

	c := collectors.NewKernelEventsCollectorWithPath(tmpFile)
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics for line without semicolon, got %d", len(metrics))
	}
}

// TestRegistry_Collect_ChannelFullPath exercises the drop-on-full channel path.
// We fill the output channel to capacity (256) then trigger a collect.
func TestRegistry_Collect_ChannelFullPath(t *testing.T) {
	// Use a very short interval; we'll run just enough to fill the channel.
	r := collectors.NewRegistry(false, 5*time.Millisecond, nil)
	ch := r.Out()

	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)

	// Drain nothing — let the channel fill until capacity.
	// Once full, the next collect call takes the drop path.
	time.Sleep(50 * time.Millisecond) // ~10 ticks to fill 256-cap channel
	cancel()

	// Drain remaining items to avoid blocking goroutine.
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// TestFilesystem_Collect_SkipsPseudoFS exercises the pseudo-fs skip branch.
func TestFilesystem_Collect_SkipsPseudoFS(t *testing.T) {
	// Write a mounts file with only pseudo filesystems — all must be skipped.
	mountsFile := filepath.Join(t.TempDir(), "mounts")
	content := "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n" +
		"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n" +
		"devtmpfs /dev devtmpfs rw 0 0\n"
	os.WriteFile(mountsFile, []byte(content), 0o644)

	c := collectors.NewFilesystemCollectorWithPath(mountsFile)
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// All pseudo mounts should be skipped, yielding 0 metrics.
	for _, m := range metrics {
		if m.Labels["mount"] == "/sys" || m.Labels["mount"] == "/proc" {
			t.Errorf("pseudo-fs mount must be skipped: %v", m.Labels)
		}
	}
}
