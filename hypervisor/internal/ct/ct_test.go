package ct_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/ct"
	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

func noopStep(_ string) {}

func TestCreate_InvalidCTID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := ct.Create(context.Background(), m, map[string]any{
		"ctid": "1", "ostemplate": "local:vztmpl/debian-12.tar.xz",
	}, noopStep)
	if err == nil {
		t.Fatal("expected error for CTID < 100")
	}
}

func TestUpdate_UnknownOption(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
	err := ct.Update(context.Background(), m, map[string]any{
		"ctid":    "100",
		"options": map[string]any{"badopt": "value"},
	})
	if err == nil {
		t.Fatal("expected error for option not in allowlist")
	}
}

func TestDelete_RequiresStopped(t *testing.T) {
	m := &proxmox.MockExec{
		Result: &proxmox.ExecResult{Stdout: []byte("status: running"), ExitCode: 0},
	}
	err := ct.Delete(context.Background(), m, map[string]any{"ctid": "100"})
	if err == nil {
		t.Fatal("expected error when deleting running CT")
	}
}

func TestMountAdd_TraversalPath(t *testing.T) {
	m := &proxmox.MockExec{}
	err := ct.MountAdd(context.Background(), m, map[string]any{
		"ctid":       "100",
		"volume":     "local-lvm:vm-100-disk-0",
		"mountpoint": "/mnt/../../etc/shadow",
	})
	if err == nil {
		t.Fatal("expected error for traversal mountpoint")
	}
	if len(m.Calls) != 0 {
		t.Fatal("no subprocess must be called for traversal path")
	}
}

func TestStart_Valid(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
	err := ct.Start(context.Background(), m, map[string]any{"ctid": "100"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if m.LastCall().Args[0] != "start" {
		t.Fatalf("expected start command, got %v", m.LastCall().Args)
	}
}
