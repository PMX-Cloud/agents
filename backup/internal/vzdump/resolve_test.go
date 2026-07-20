package vzdump

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveBinaryPrefersConfiguredWhenExecutable(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "vzdump")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := ResolveBinary(p); got != p {
		t.Fatalf("ResolveBinary(%q) = %q, want %q", p, got, p)
	}
}

func TestResolveBinaryFallsBackToTrustedDirByBasename(t *testing.T) {
	// Simulate a usr-merged Proxmox host: the configured /usr/sbin/vzdump is
	// absent but the real binary lives in another trusted dir (/usr/bin).
	dir := t.TempDir()
	real := filepath.Join(dir, "vzdump")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := trustedBinDirs
	trustedBinDirs = []string{dir}
	defer func() { trustedBinDirs = orig }()

	if got := ResolveBinary("/usr/sbin/vzdump"); got != real {
		t.Fatalf("ResolveBinary fallback = %q, want %q", got, real)
	}
}

func TestResolveBinaryReturnsConfiguredWhenNothingFound(t *testing.T) {
	orig := trustedBinDirs
	trustedBinDirs = []string{t.TempDir()}
	defer func() { trustedBinDirs = orig }()

	in := "/nonexistent/path/vzdump"
	if got := ResolveBinary(in); got != in {
		t.Fatalf("ResolveBinary(%q) = %q, want unchanged", in, got)
	}
}
