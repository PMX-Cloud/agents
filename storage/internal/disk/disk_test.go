package disk_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/storage/internal/disk"
	"github.com/pmx-cloud/agents/storage/internal/storageexec"
)

func TestInventoryParsesDisksPartitionsRemovableAndSMART(t *testing.T) {
	lsblk := `{"blockdevices":[{"name":"sda","size":1073741824,"rota":true,"rm":false,"type":"disk","mountpoint":null,"fstype":null,"serial":"S1","model":"Disk One","vendor":"ATA","wwn":"wwn-1","children":[{"name":"sda1","size":536870912,"rota":true,"rm":false,"type":"part","mountpoint":"/data","fstype":"ext4"}]},{"name":"sdb","size":2048,"rota":false,"rm":true,"type":"disk"}]}`
	m := &storageexec.MockExec{Results: map[string]*storageexec.Result{
		"lsblk":    {Stdout: []byte(lsblk), ExitCode: 0},
		"smartctl": {Stdout: []byte(`{"smart_status":{"passed":true}}`), ExitCode: 0},
	}}
	inv, err := disk.Inventory(context.Background(), m)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if len(inv.Disks) != 2 {
		t.Fatalf("expected 2 disks, got %d", len(inv.Disks))
	}
	if inv.Disks[0].SmartStatus != "passed" || len(inv.Disks[0].Partitions) != 1 {
		t.Fatalf("unexpected first disk: %+v", inv.Disks[0])
	}
	if !inv.Disks[1].Removable {
		t.Fatal("expected removable disk to be flagged")
	}
}

func TestFormatRefusesMountedDiskBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	mounts := filepath.Join(dir, "mounts")
	fstab := filepath.Join(dir, "fstab")
	if err := os.WriteFile(mounts, []byte("/dev/sdb /mnt ext4 rw 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fstab, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m := &storageexec.MockExec{}
	err := disk.Format(context.Background(), m, disk.FormatParams{Device: "/dev/sdb", FSType: "ext4", MountsPath: mounts, FstabPath: fstab})
	if err == nil || !strings.Contains(err.Error(), "mounted") {
		t.Fatalf("expected mounted refusal, got %v", err)
	}
	if len(m.Calls) != 0 {
		t.Fatalf("format must not mutate mounted disk, got calls %v", m.Calls)
	}
}

func TestFormatRunsWipePartitionAndMkfsForSupportedFSType(t *testing.T) {
	dir := t.TempDir()
	mounts := filepath.Join(dir, "mounts")
	fstab := filepath.Join(dir, "fstab")
	_ = os.WriteFile(mounts, nil, 0o600)
	_ = os.WriteFile(fstab, nil, 0o600)
	m := &storageexec.MockExec{Results: map[string]*storageexec.Result{
		"lsblk": {Stdout: []byte(`{"blockdevices":[{"name":"sdb","type":"disk"}]}`), ExitCode: 0},
	}}
	err := disk.Format(context.Background(), m, disk.FormatParams{Device: "/dev/sdb", FSType: "xfs", MountsPath: mounts, FstabPath: fstab})
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	want := []string{"lsblk", "wipefs", "parted", "lsblk", "mkfs.xfs"}
	for i, binary := range want {
		if m.Calls[i].Binary != binary {
			t.Fatalf("call %d expected %s, got %+v", i, binary, m.Calls[i])
		}
	}
	if got := m.Calls[len(m.Calls)-1].Args[len(m.Calls[len(m.Calls)-1].Args)-1]; got != "/dev/sdb1" {
		t.Fatalf("expected mkfs target /dev/sdb1, got %q", got)
	}
}

func TestFormatRefusesMountedDescendantEvenWithForce(t *testing.T) {
	dir := t.TempDir()
	mounts := filepath.Join(dir, "mounts")
	fstab := filepath.Join(dir, "fstab")
	if err := os.WriteFile(mounts, []byte("/dev/sdb1 /data ext4 rw 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fstab, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m := &storageexec.MockExec{Results: map[string]*storageexec.Result{
		"lsblk": {Stdout: []byte(`{"blockdevices":[{"name":"sdb","type":"disk","children":[{"name":"sdb1","type":"part"}]}]}`), ExitCode: 0},
	}}
	err := disk.Format(context.Background(), m, disk.FormatParams{
		Device:     "/dev/sdb",
		FSType:     "ext4",
		Force:      true,
		MountsPath: mounts,
		FstabPath:  fstab,
	})
	if err == nil || !strings.Contains(err.Error(), "mounted") {
		t.Fatalf("expected mounted-descendant refusal, got %v", err)
	}
	if len(m.Calls) != 1 || m.Calls[0].Binary != "lsblk" {
		t.Fatalf("expected only lsblk safety introspection call, got %v", m.Calls)
	}
}

func TestImportImageRejectsUnsafeIDBeforeDownload(t *testing.T) {
	_, err := disk.ImportImage(context.Background(), &storageexec.MockExec{}, disk.ImportImageParams{
		ID:           "../escape",
		SourceURL:    "https://images.example/os.raw",
		AllowedHosts: []string{"images.example"},
		Destination:  "images/os.raw",
		StorageRoot:  t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "id contains unsafe characters") {
		t.Fatalf("expected unsafe id error, got %v", err)
	}
}

func TestImportImageRejectsDestinationOutsideStorageRoot(t *testing.T) {
	root := t.TempDir()
	_, err := disk.ImportImage(context.Background(), &storageexec.MockExec{}, disk.ImportImageParams{
		ID:           "safe-id",
		SourceURL:    "https://images.example/os.raw",
		AllowedHosts: []string{"images.example"},
		Destination:  "/etc/passwd",
		StorageRoot:  root,
	})
	if err == nil || !strings.Contains(err.Error(), "destination escapes storage root") {
		t.Fatalf("expected destination-root escape error, got %v", err)
	}
}
