package archive_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pmx-cloud/agents/backup/internal/archive"
)

func TestEnsureInsideAllowedRoots(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	allowed := []string{root}

	inside := filepath.Join(root, "vzdump-qemu-100-2026_05_12-00_00_00.vma.zst")
	if err := os.WriteFile(inside, []byte("archive"), 0o644); err != nil {
		t.Fatalf("write inside archive: %v", err)
	}
	if _, err := archive.EnsureInsideAllowedRoots(inside, allowed); err != nil {
		t.Fatalf("EnsureInsideAllowedRoots(inside) error = %v", err)
	}

	outside := filepath.Join(filepath.Dir(root), "not-allowed", "backup.vma.zst")
	if _, err := archive.EnsureInsideAllowedRoots(outside, allowed); err == nil {
		t.Fatal("expected outside path rejection")
	}
}

func TestEnsureExistingArchiveRejectsSymlinkEscape(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	outsideArchive := filepath.Join(outside, "vzdump-qemu-100-2026_05_12-00_00_00.vma.zst")
	if err := os.WriteFile(outsideArchive, []byte("archive"), 0o644); err != nil {
		t.Fatalf("write outside archive: %v", err)
	}

	linkPath := filepath.Join(root, "linked.vma.zst")
	if err := os.Symlink(outsideArchive, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if _, err := archive.EnsureExistingArchive(linkPath, []string{root}); err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}

func TestEnsurePathForCreateRejectsSymlinkParentEscape(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	linkDir := filepath.Join(root, "linked-dir")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Fatalf("create symlink dir: %v", err)
	}

	destination := filepath.Join(linkDir, "pulled.vma.zst")
	if _, err := archive.EnsurePathForCreate(destination, []string{root}); err == nil {
		t.Fatal("expected create path through symlink parent to be rejected")
	}
}

func TestDeleteArchiveWithSidecars(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	archivePath := filepath.Join(root, "vzdump-qemu-100-2026_05_12-00_00_00.vma.zst")
	notesPath := archivePath + ".notes"

	if err := os.WriteFile(archivePath, []byte("archive"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	if err := os.WriteFile(notesPath, []byte("notes"), 0o644); err != nil {
		t.Fatalf("write notes: %v", err)
	}

	deleted, err := archive.DeleteArchiveWithSidecars(archivePath, []string{root})
	if err != nil {
		t.Fatalf("DeleteArchiveWithSidecars() error = %v", err)
	}
	if len(deleted) < 1 {
		t.Fatalf("expected deleted files, got %v", deleted)
	}
	if _, err := os.Stat(archivePath); !os.IsNotExist(err) {
		t.Fatalf("archive must be deleted, stat err = %v", err)
	}
}
