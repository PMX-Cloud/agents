package storageexec_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/storage/internal/storageexec"
)

func TestMockExecRejectsUnsafeArgumentsBeforeRecording(t *testing.T) {
	m := &storageexec.MockExec{}
	_, err := m.Qm(context.Background(), "set", "100", `; rm -rf /`)
	if err == nil {
		t.Fatal("expected unsafe argument error")
	}
	if len(m.Calls) != 0 {
		t.Fatalf("unsafe call must not be recorded/executed, got %v", m.Calls)
	}
}

func TestExecWhitelistIncludesStorageBinaries(t *testing.T) {
	allowed := storageexec.DefaultAllowedBinaries()
	for _, path := range []string{"/sbin/lsblk", "/sbin/parted", "/sbin/zpool", "/sbin/zfs", "/usr/sbin/smartctl", "/usr/sbin/exportfs", "/usr/bin/net", "/usr/sbin/nvme", "/usr/bin/qemu-img"} {
		if !allowed[path] {
			t.Fatalf("expected %s to be allowed", path)
		}
	}
}
