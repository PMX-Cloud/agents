package capability_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/core/internal/capability"
)

// TestCollectWithPaths exercises the injectable path variant, covering the
// success branches of readOSReleaseFrom, readCPUInfoFrom, readMemTotalFrom.
func TestCollectWithPaths_Fixtures(t *testing.T) {
	capability.InvalidateCache()
	info := capability.CollectWithPaths(context.Background(), capability.FilePaths{
		OSRelease: "testdata/os-release",
		CPUInfo:   "testdata/cpuinfo",
		MemInfo:   "testdata/meminfo",
	})

	if info == nil {
		t.Fatal("expected non-nil HostInfo")
	}
	if info.OS.ID != "debian" {
		t.Errorf("OS.ID = %q, want %q", info.OS.ID, "debian")
	}
	if info.OS.Version != "12" {
		t.Errorf("OS.Version = %q, want %q", info.OS.Version, "12")
	}
	if info.CPU.Cores != 4 {
		t.Errorf("CPU.Cores = %d, want 4", info.CPU.Cores)
	}
	if info.CPU.Vendor != "GenuineIntel" {
		t.Errorf("CPU.Vendor = %q, want GenuineIntel", info.CPU.Vendor)
	}
	want := int64(16384000 * 1024)
	if info.MemoryTotalBytes != want {
		t.Errorf("MemoryTotalBytes = %d, want %d", info.MemoryTotalBytes, want)
	}
}

func TestCollectWithPaths_MissingFiles(t *testing.T) {
	capability.InvalidateCache()
	info := capability.CollectWithPaths(context.Background(), capability.FilePaths{
		OSRelease: "/nonexistent/os-release",
		CPUInfo:   "/nonexistent/cpuinfo",
		MemInfo:   "/nonexistent/meminfo",
	})
	if info == nil {
		t.Fatal("expected non-nil HostInfo even with missing files")
	}
	// On missing files these fields default to zero values.
	if info.OS.ID != "" {
		t.Errorf("OS.ID must be empty for missing file, got %q", info.OS.ID)
	}
	if info.CPU.Cores != 1 {
		t.Errorf("CPU.Cores must default to 1 for missing file, got %d", info.CPU.Cores)
	}
	if info.MemoryTotalBytes != 0 {
		t.Errorf("MemoryTotalBytes must be 0 for missing file, got %d", info.MemoryTotalBytes)
	}
}

func TestFilePaths_DefaultPathsUsed(t *testing.T) {
	// Verify the zero value of FilePaths triggers the defaultPaths via collect().
	// We just ensure it doesn't panic when the real files don't exist (macOS).
	capability.InvalidateCache()
	info := capability.Collect(context.Background())
	if info == nil {
		t.Fatal("Collect with default paths must not return nil")
	}
}
