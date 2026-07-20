package vzdump

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRestoreUsesExplicitGuestCommandAndCloneSafety(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		resourceType string
		wantArgs     string
	}{
		{
			name:         "vm",
			resourceType: "vm",
			wantArgs:     "/backups/vm.vma.zst 201 --storage local-zfs --unique 1",
		},
		{
			name:         "container",
			resourceType: "container",
			wantArgs:     "restore 201 /backups/ct.tar.zst --storage local-zfs --unique 1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			argsFile := filepath.Join(dir, "args")
			status := filepath.Join(dir, "status")
			restore := filepath.Join(dir, "restore")
			if err := os.WriteFile(status, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
				t.Fatalf("write status command: %v", err)
			}
			script := "#!/bin/sh\nprintf '%s' \"$*\" > " + argsFile + "\n"
			if err := os.WriteFile(restore, []byte(script), 0o755); err != nil {
				t.Fatalf("write restore command: %v", err)
			}

			archive := "/backups/vm.vma.zst"
			bins := Binaries{QM: status, QMRestore: restore, PCT: status}
			if tc.resourceType == "container" {
				archive = "/backups/ct.tar.zst"
				bins.PCT = restore
				// The same fake pct binary must report the guest as absent for
				// `pct status` and record the subsequent `pct restore` call.
				pctScript := "#!/bin/sh\nif [ \"$1\" = status ]; then exit 1; fi\nprintf '%s' \"$*\" > " + argsFile + "\n"
				if err := os.WriteFile(restore, []byte(pctScript), 0o755); err != nil {
					t.Fatalf("write pct command: %v", err)
				}
			}

			err := Restore(context.Background(), bins, RestoreParams{
				ArchivePath:  archive,
				VMID:         201,
				Storage:      "local-zfs",
				ResourceType: tc.resourceType,
				Unique:       true,
			}, nil)
			if err != nil {
				t.Fatalf("Restore() error = %v", err)
			}
			got, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatalf("read restore args: %v", err)
			}
			if string(got) != tc.wantArgs {
				t.Fatalf("restore args = %q, want %q", got, tc.wantArgs)
			}
		})
	}
}

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
