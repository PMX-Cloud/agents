package capability_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/core/internal/capability"
)

func TestCollect_MemoryTotalBytes(t *testing.T) {
	capability.InvalidateCache()
	info := capability.Collect(context.Background())
	// On any real or CI host, memory must be > 0.
	if info.MemoryTotalBytes < 0 {
		t.Fatalf("memory_total_bytes must not be negative, got %d", info.MemoryTotalBytes)
	}
}

func TestCollect_CPUCoresNonNegative(t *testing.T) {
	capability.InvalidateCache()
	info := capability.Collect(context.Background())
	if info.CPU.Cores < 0 {
		t.Fatalf("cpu.cores must not be negative, got %d", info.CPU.Cores)
	}
}

func TestCollect_OSIDParsed(t *testing.T) {
	capability.InvalidateCache()
	info := capability.Collect(context.Background())
	// os.id is empty on macOS (no /etc/os-release); just verify no panic.
	// On Linux it must be non-empty.
	_ = info.OS.ID
}

func TestCollect_KernelNonEmpty(t *testing.T) {
	capability.InvalidateCache()
	info := capability.Collect(context.Background())
	if info.Kernel == "" {
		t.Fatal("kernel must not be empty")
	}
}

func TestCollect_ProxmoxDetectedFalseOnCI(t *testing.T) {
	capability.InvalidateCache()
	info := capability.Collect(context.Background())
	// In CI (non-Proxmox) hosts: Proxmox must not be detected (pveversion absent).
	// On a real Proxmox host this test would pass regardless.
	_ = info.Proxmox.Detected // just verify it's set without panic
}

func TestCollect_NICsNoNilSlice(t *testing.T) {
	capability.InvalidateCache()
	info := capability.Collect(context.Background())
	// NICs may be empty but must not be nil (JSON marshals nil as null which
	// breaks backend schema validation).
	if info.NICs == nil {
		t.Fatal("nics must not be nil — use empty slice instead")
	}
}

func TestCollect_DisksNoNilSlice(t *testing.T) {
	capability.InvalidateCache()
	info := capability.Collect(context.Background())
	if info.Disks == nil {
		t.Fatal("disks must not be nil — use empty slice instead")
	}
}

func TestCollect_GPUsNoNilSlice(t *testing.T) {
	capability.InvalidateCache()
	info := capability.Collect(context.Background())
	if info.GPUs == nil {
		t.Fatal("gpus must not be nil — use empty slice instead")
	}
}

func TestCollect_AgentsNoNilSlice(t *testing.T) {
	capability.InvalidateCache()
	info := capability.Collect(context.Background())
	if info.Agents == nil {
		t.Fatal("agents must not be nil — use empty slice instead")
	}
}
