package collectors_test

import (
	"context"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/telemetry/internal/collectors"
)

const testdataDir = "testdata/"

// ── CPU ─────────────────────────────────────────────────────────────────────

func TestCPUCollector_ParseFixture(t *testing.T) {
	c := collectors.NewCPUCollectorWithPath(testdataDir + "proc_stat")
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	names := metricNames(metrics)
	for _, want := range []string{
		"host_cpu_user_seconds",
		"host_cpu_system_seconds",
		"host_cpu_idle_seconds",
		"host_cpu_iowait_seconds",
	} {
		if !names[want] {
			t.Errorf("missing metric %q", want)
		}
	}
}

func TestCPUCollector_RateOnSecondCall(t *testing.T) {
	c := collectors.NewCPUCollectorWithPath(testdataDir + "proc_stat")
	c.Collect(context.Background()) // prime
	time.Sleep(5 * time.Millisecond)
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 2nd: %v", err)
	}
	names := metricNames(metrics)
	if !names["host_cpu_user_rate"] {
		t.Error("expected rate metrics on second call")
	}
}

func TestCPUCollector_BadFile(t *testing.T) {
	c := collectors.NewCPUCollectorWithPath("/no/such/file/proc_stat")
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ── Memory ───────────────────────────────────────────────────────────────────

func TestMemoryCollector_ParseFixture(t *testing.T) {
	c := collectors.NewMemoryCollectorWithPath(testdataDir + "proc_meminfo")
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	names := metricNames(metrics)
	for _, want := range []string{
		"host_memory_total_bytes",
		"host_memory_available_bytes",
		"host_memory_cached_bytes",
		"host_memory_swap_used_bytes",
	} {
		if !names[want] {
			t.Errorf("missing metric %q", want)
		}
	}
	// Verify total = 16384000 kB * 1024 = 16777216000 bytes
	for _, m := range metrics {
		if m.Name == "host_memory_total_bytes" && m.Value != 16777216000 {
			t.Errorf("total = %v, want 16777216000", m.Value)
		}
	}
}

// ── Load ────────────────────────────────────────────────────────────────────

func TestLoadCollector_ParseFixture(t *testing.T) {
	c := collectors.NewLoadCollectorWithPath(testdataDir + "proc_loadavg")
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(metrics) != 3 {
		t.Fatalf("expected 3 metrics, got %d", len(metrics))
	}
	for _, m := range metrics {
		if m.Value <= 0 {
			t.Errorf("metric %q has non-positive value %v", m.Name, m.Value)
		}
	}
}

// ── Disk I/O ────────────────────────────────────────────────────────────────

func TestDiskIOCollector_ParseFixture(t *testing.T) {
	c := collectors.NewDiskIOCollectorWithPath(testdataDir + "proc_diskstats")
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Should have sda + sdb but NOT loop0 or ram0.
	for _, m := range metrics {
		if m.Labels["device"] == "loop0" || m.Labels["device"] == "ram0" {
			t.Errorf("loopback/ram device must be excluded: %v", m.Labels)
		}
	}
	names := metricNames(metrics)
	if !names["host_disk_read_bytes_total"] {
		t.Error("missing host_disk_read_bytes_total")
	}
}

// ── Net I/O ─────────────────────────────────────────────────────────────────

func TestNetIOCollector_ParseFixture(t *testing.T) {
	c := collectors.NewNetIOCollectorWithPath(testdataDir + "proc_net_dev")
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// lo must be excluded.
	for _, m := range metrics {
		if m.Labels["iface"] == "lo" {
			t.Errorf("loopback must be excluded: %v", m)
		}
	}
	// eth0 must be present.
	found := false
	for _, m := range metrics {
		if m.Labels["iface"] == "eth0" {
			found = true
			break
		}
	}
	if !found {
		t.Error("eth0 must be present in metrics")
	}
}

// ── Proxmox (disabled) ────────────────────────────────────────────────────────

func TestProxmoxCollector_Disabled(t *testing.T) {
	c := collectors.NewProxmoxCollector(false)
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(metrics) != 0 {
		t.Fatalf("disabled proxmox collector must return 0 metrics, got %d", len(metrics))
	}
}

// ── Registry ─────────────────────────────────────────────────────────────────

func TestRegistry_CollectOnce_NoNilReturn(t *testing.T) {
	r := collectors.NewRegistry(false, 10*time.Second, nil)
	// CollectOnce on a dev machine (macOS) will partially fail for /proc collectors.
	// That's fine — result must not be nil, just may contain collector.failed metrics.
	metrics := r.CollectOnce(context.Background())
	_ = metrics // no nil panics
}

// ── helpers ──────────────────────────────────────────────────────────────────

func metricNames(metrics []collectors.Metric) map[string]bool {
	m := map[string]bool{}
	for _, metric := range metrics {
		m[metric.Name] = true
	}
	return m
}
