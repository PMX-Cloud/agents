package zfs_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/storage/internal/storageexec"
	"github.com/pmx-cloud/agents/storage/internal/zfs"
)

func TestPoolCreateRejectsUnknownTopologyBeforeExec(t *testing.T) {
	m := &storageexec.MockExec{}
	err := zfs.PoolCreate(context.Background(), m, zfs.PoolCreateParams{Name: "tank", Topology: "raid10", Devices: []string{"/dev/sdb", "/dev/sdc"}})
	if err == nil || !strings.Contains(err.Error(), "topology") {
		t.Fatalf("expected topology error, got %v", err)
	}
	if len(m.Calls) != 0 {
		t.Fatalf("unexpected exec calls: %v", m.Calls)
	}
}

func TestPoolDestroyRefusesSnapshotsWithoutForce(t *testing.T) {
	m := &storageexec.MockExec{Results: map[string]*storageexec.Result{
		"zfs": {Stdout: []byte("tank/data@s1\n"), ExitCode: 0},
	}}
	err := zfs.PoolDestroy(context.Background(), m, zfs.PoolDestroyParams{Name: "tank"})
	if err == nil || !strings.Contains(err.Error(), "snapshots") {
		t.Fatalf("expected snapshot refusal, got %v", err)
	}
}

func TestSnapshotSendRejectsTamperedDestination(t *testing.T) {
	m := &storageexec.MockExec{}
	err := zfs.SnapshotSend(context.Background(), m, zfs.SnapshotSendParams{Snapshot: "tank/data@s1", Destination: "$(curl attacker)"})
	if err == nil || !strings.Contains(err.Error(), "destination") {
		t.Fatalf("expected destination validation error, got %v", err)
	}
	if len(m.Calls) != 0 {
		t.Fatalf("unexpected exec calls: %v", m.Calls)
	}
}

func TestSnapshotSendWritesLocalStreamDestination(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "snapshot.stream")
	m := &storageexec.MockExec{
		Results: map[string]*storageexec.Result{
			"zfs": {Stdout: []byte("stream-payload"), ExitCode: 0},
		},
	}
	err := zfs.SnapshotSend(context.Background(), m, zfs.SnapshotSendParams{
		Snapshot:    "tank/data@s1",
		Destination: dest,
	})
	if err != nil {
		t.Fatalf("snapshot send: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if string(got) != "stream-payload" {
		t.Fatalf("unexpected stream payload: %q", string(got))
	}
	if len(m.Calls) != 1 || m.Calls[0].Binary != "zfs" {
		t.Fatalf("expected one zfs send call, got %v", m.Calls)
	}
}

func TestDatasetCreateRejectsDedupWithoutGate(t *testing.T) {
	m := &storageexec.MockExec{}
	err := zfs.DatasetCreate(context.Background(), m, zfs.DatasetCreateParams{
		Dataset: "tank/data",
		Options: map[string]any{
			"dedup": "on",
		},
		AllowDedup: false,
	})
	if err == nil || !strings.Contains(err.Error(), "allow_dedup") {
		t.Fatalf("expected dedup gate error, got %v", err)
	}
	if len(m.Calls) != 0 {
		t.Fatalf("unexpected exec calls: %v", m.Calls)
	}
}
