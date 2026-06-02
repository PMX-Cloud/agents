package collectors_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/telemetry/internal/collectors"
)

// ── Registry ──────────────────────────────────────────────────────────────────

func TestRegistry_Out_NonNil(t *testing.T) {
	r := collectors.NewRegistry(false, 10*time.Second, nil)
	ch := r.Out()
	if ch == nil {
		t.Fatal("Out() must return a non-nil channel")
	}
}

func TestRegistry_Run_CancelledContext(t *testing.T) {
	r := collectors.NewRegistry(false, 100*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Run must return quickly when context is already cancelled.
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not return promptly after context cancel")
	}
}

func TestRegistry_Run_OneTickThenCancel(t *testing.T) {
	// Use a short interval so a tick fires before we cancel.
	r := collectors.NewRegistry(false, 10*time.Millisecond, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r.Run(ctx) // blocks until context expires
}

func TestRegistry_CollectOnce_NilLoggerOK(t *testing.T) {
	r := collectors.NewRegistry(false, 10*time.Second, nil)
	metrics := r.CollectOnce(context.Background())
	_ = metrics // may be empty on macOS; must not panic
}

// ── ProxmoxCollector ──────────────────────────────────────────────────────────

func TestProxmoxCollector_Name(t *testing.T) {
	c := collectors.NewProxmoxCollector(true)
	if c.Name() == "" {
		t.Fatal("Name() must not be empty")
	}
}

func TestProxmoxCollector_EnabledButNoPvesh(t *testing.T) {
	// On macOS (no pvesh), must return empty metrics without panic.
	c := collectors.NewProxmoxCollector(true)
	metrics, err := c.Collect(context.Background())
	if err != nil {
		// An error is acceptable; what matters is no panic.
		t.Logf("Collect error (expected on macOS): %v", err)
	}
	_ = metrics
}

// ── AgentProcCollector ────────────────────────────────────────────────────────

func TestAgentProcCollector_WithFakeProcDir(t *testing.T) {
	// Create a fake /proc directory structure with one "pmx-telemetry" process.
	procDir := t.TempDir()
	pidDir := filepath.Join(procDir, "12345")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	statusContent := `Name:	pmx-telemetry
State:	S (sleeping)
Pid:	12345
VmRSS:	  12288 kB
Threads:	4
FDSize:	64
`
	os.WriteFile(filepath.Join(pidDir, "status"), []byte(statusContent), 0o644)

	c := collectors.NewAgentProcCollectorWithPath(procDir)
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Should have metrics for agent_rss_bytes, agent_threads, agent_fds
	if len(metrics) == 0 {
		t.Fatal("expected metrics for fake pmx-telemetry process")
	}
	names := metricNames(metrics)
	for _, want := range []string{"agent_rss_bytes", "agent_threads", "agent_fds"} {
		if !names[want] {
			t.Errorf("missing metric %q, got %v", want, metricsAsList(metrics))
		}
	}
}

func TestAgentProcCollector_SkipsNonPmxProcesses(t *testing.T) {
	procDir := t.TempDir()
	// Create a non-pmx process.
	pidDir := filepath.Join(procDir, "999")
	os.MkdirAll(pidDir, 0o755)
	os.WriteFile(filepath.Join(pidDir, "status"), []byte("Name:\tbash\nVmRSS:\t1024 kB\n"), 0o644)

	c := collectors.NewAgentProcCollectorWithPath(procDir)
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// bash is not a pmx-* process; no metrics should be emitted.
	for _, m := range metrics {
		if m.Labels["process"] == "bash" {
			t.Errorf("non-pmx process must be excluded, got metric with bash label")
		}
	}
}

func TestAgentProcCollector_NonExistentDir(t *testing.T) {
	c := collectors.NewAgentProcCollectorWithPath("/nonexistent/proc")
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error for non-existent proc path")
	}
}

func TestAgentProcCollector_Name(t *testing.T) {
	c := collectors.NewAgentProcCollector()
	if c.Name() == "" {
		t.Fatal("Name() must not be empty")
	}
}

// ── FilesystemCollector ───────────────────────────────────────────────────────

func TestFilesystemCollector_Name(t *testing.T) {
	c := collectors.NewFilesystemCollector()
	if c.Name() == "" {
		t.Fatal("Name() must not be empty")
	}
}

func TestFilesystemCollector_WithFakeMountsFile(t *testing.T) {
	// Create a fake /proc/mounts pointing at tmpfs only (always present).
	procDir := t.TempDir()
	mountsFile := filepath.Join(procDir, "mounts")
	// Write a fake mounts file with a tmpfs entry.
	os.WriteFile(mountsFile, []byte("tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"), 0o644)

	c := collectors.NewFilesystemCollectorWithPath(mountsFile)
	_, err := c.Collect(context.Background())
	// May fail on macOS (no statfs on /tmp as a tmpfs), but must not panic.
	_ = err
}

func TestFilesystemCollector_WithNonExistentMountsFile(t *testing.T) {
	c := collectors.NewFilesystemCollectorWithPath("/nonexistent/mounts")
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error for non-existent mounts file")
	}
}

// ── KernelEventsCollector ────────────────────────────────────────────────────

func TestKernelEventsCollector_Name(t *testing.T) {
	c := collectors.NewKernelEventsCollector()
	if c.Name() == "" {
		t.Fatal("Name() must not be empty")
	}
}

func TestKernelEventsCollector_WithFakeKmsgFile(t *testing.T) {
	// Create a fake kmsg file with some OOM and IO error messages.
	tmpFile := filepath.Join(t.TempDir(), "kmsg")
	// Format: "<priority>,<seq>,<timestamp_us>,-;<message>"
	content := "6,1234,1000000,-;Out of memory: Kill process foo\n" +
		"6,1235,2000000,-;I/O error reading sector 12345\n" +
		"6,1236,3000000,-;Normal log message, no pattern\n"
	os.WriteFile(tmpFile, []byte(content), 0o644)

	c := collectors.NewKernelEventsCollectorWithPath(tmpFile)
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	names := metricNames(metrics)
	if !names["host_kernel_event"] {
		t.Errorf("expected host_kernel_event metrics, got %v", metricsAsList(metrics))
	}
	// Verify both oom and io_error events are present.
	foundOOM, foundIO := false, false
	for _, m := range metrics {
		switch m.Labels["event_type"] {
		case "oom":
			foundOOM = true
		case "io_error":
			foundIO = true
		}
	}
	if !foundOOM {
		t.Error("expected oom event metric")
	}
	if !foundIO {
		t.Error("expected io_error event metric")
	}
}

func TestKernelEventsCollector_NonExistentFile(t *testing.T) {
	c := collectors.NewKernelEventsCollectorWithPath("/nonexistent/dev/kmsg")
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error for non-existent kmsg file")
	}
}

func TestKernelEventsCollector_LinkStateEvent(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "kmsg")
	content := "6,100,500000,-;NIC Link is Up\n"
	os.WriteFile(tmpFile, []byte(content), 0o644)

	c := collectors.NewKernelEventsCollectorWithPath(tmpFile)
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	found := false
	for _, m := range metrics {
		if m.Labels["event_type"] == "link_state" {
			found = true
		}
	}
	if !found {
		t.Error("expected link_state event metric")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func metricsAsList(metrics []collectors.Metric) []string {
	names := make([]string, len(metrics))
	for i, m := range metrics {
		names[i] = m.Name
	}
	return names
}
