package vzdump

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseArchivePath(t *testing.T) {
	t.Parallel()

	line := "INFO: creating vzdump archive '/var/lib/vz/dump/vzdump-qemu-100-2026_05_12-10_00_00.vma.zst'"
	path, ok := parseArchivePath(line)
	if !ok {
		t.Fatal("expected archive path to be parsed")
	}
	if path != "/var/lib/vz/dump/vzdump-qemu-100-2026_05_12-10_00_00.vma.zst" {
		t.Fatalf("parsed path = %q", path)
	}
}

func TestHashFileSHA256(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "backup.bin")
	if err := os.WriteFile(file, []byte("pmx-backup-test"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	hash, size, err := HashFileSHA256(file, nil)
	if err != nil {
		t.Fatalf("HashFileSHA256() error = %v", err)
	}
	if size != int64(len("pmx-backup-test")) {
		t.Fatalf("size = %d", size)
	}
	if hash == "" {
		t.Fatal("hash must not be empty")
	}
}

func TestFindCreatedArchive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a1 := filepath.Join(dir, "vzdump-qemu-101-2026_05_11-10_00_00.vma.zst")
	a2 := filepath.Join(dir, "vzdump-qemu-101-2026_05_12-10_00_00.vma.zst")
	if err := os.WriteFile(a1, []byte("a1"), 0o644); err != nil {
		t.Fatalf("write a1: %v", err)
	}
	if err := os.WriteFile(a2, []byte("a2"), 0o644); err != nil {
		t.Fatalf("write a2: %v", err)
	}

	now := time.Now()
	if err := os.Chtimes(a1, now.Add(-2*time.Hour), now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("chtimes a1: %v", err)
	}
	if err := os.Chtimes(a2, now, now); err != nil {
		t.Fatalf("chtimes a2: %v", err)
	}

	resolved, err := findCreatedArchive(dir, 101, now.Add(-1*time.Minute))
	if err != nil {
		t.Fatalf("findCreatedArchive() error = %v", err)
	}
	if resolved != a2 {
		t.Fatalf("resolved archive = %q, want %q", resolved, a2)
	}
}
