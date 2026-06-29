package capability_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/core/internal/capability"
)

func TestCollect_ReturnsCachedResult(t *testing.T) {
	capability.InvalidateCache()
	ctx := context.Background()

	info1 := capability.Collect(ctx)
	info2 := capability.Collect(ctx)

	// Pointer equality: second call should return the same cached pointer.
	if info1 != info2 {
		t.Fatal("expected cached result on second call")
	}
}

func TestCollect_FingerprintIsHex(t *testing.T) {
	capability.InvalidateCache()
	info := capability.Collect(context.Background())
	fp := info.HostFingerprint
	if len(fp) != 64 {
		t.Fatalf("fingerprint must be 64 hex chars, got %d: %q", len(fp), fp)
	}
	for _, c := range fp {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("fingerprint contains non-hex char %q", c)
		}
	}
}

func TestCollect_FingerprintIsStable(t *testing.T) {
	capability.InvalidateCache()
	fp1 := capability.Collect(context.Background()).HostFingerprint
	capability.InvalidateCache()
	fp2 := capability.Collect(context.Background()).HostFingerprint
	if fp1 != fp2 {
		t.Fatalf("fingerprint changed between calls: %q vs %q", fp1, fp2)
	}
}

// The canonical host-fingerprint file (written once by the installer) is the
// single source of truth: pmx-storage, the console-broker, and the backend all
// use it to sign/route envelopes. The core agent must report the SAME value, so
// when the file is present it MUST be preferred over a freshly computed hash.
// Recomputing instead produced a mismatch (computed vs file) that broke console
// session dispatch.
func TestCollectWithPaths_PrefersCanonicalFingerprintFile(t *testing.T) {
	capability.InvalidateCache()
	dir := t.TempDir()
	fpFile := filepath.Join(dir, "host-fingerprint")
	const canonical = "08754c8600000000000000000000000000000000000000000000000000000000"
	if err := os.WriteFile(fpFile, []byte(canonical+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	info := capability.CollectWithPaths(context.Background(), capability.FilePaths{
		HostFingerprintFile: fpFile,
	})
	if info.HostFingerprint != canonical {
		t.Fatalf("HostFingerprint = %q, want canonical file value %q", info.HostFingerprint, canonical)
	}
}

func TestCollectWithPaths_FingerprintFallsBackToComputeWhenFileAbsent(t *testing.T) {
	capability.InvalidateCache()
	info := capability.CollectWithPaths(context.Background(), capability.FilePaths{
		HostFingerprintFile: "/nonexistent/host-fingerprint",
	})
	fp := info.HostFingerprint
	if len(fp) != 64 {
		t.Fatalf("fallback fingerprint must be 64 hex chars, got %d: %q", len(fp), fp)
	}
}

func TestCollect_PartialDataOnMissingTools(t *testing.T) {
	capability.InvalidateCache()
	// The test host (macOS dev) won't have lsblk/pveversion; that's fine.
	// The call must succeed and populate Warnings for missing tools.
	info := capability.Collect(context.Background())

	// These must always be present on any host.
	if info.HostFingerprint == "" {
		t.Fatal("host_fingerprint must not be empty")
	}
	// Hostname must be populated.
	if info.Hostname == "" {
		t.Fatal("hostname must not be empty")
	}
	// Warnings may be non-nil but must not panic.
	_ = info.Warnings
}
