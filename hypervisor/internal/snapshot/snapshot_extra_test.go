package snapshot_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
	"github.com/pmx-cloud/agents/hypervisor/internal/snapshot"
)

func successExec() *proxmox.MockExec {
	return &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
}

func failExec() *proxmox.MockExec {
	return &proxmox.MockExec{
		Result: &proxmox.ExecResult{ExitCode: 1},
		Err:    fmt.Errorf("exit status 1"),
	}
}

func TestCreate_Valid(t *testing.T) {
	m := successExec()
	err := snapshot.Create(context.Background(), m, map[string]any{
		"vmid": "100", "name": "snap1",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if m.LastCall().Args[0] != "snapshot" {
		t.Fatalf("expected snapshot command, got %v", m.LastCall().Args)
	}
}

func TestCreate_WithDescription(t *testing.T) {
	m := successExec()
	err := snapshot.Create(context.Background(), m, map[string]any{
		"vmid": "100", "name": "snap2", "description": "my-snap",
	})
	if err != nil {
		t.Fatalf("Create with description: %v", err)
	}
}

func TestCreate_QmError(t *testing.T) {
	if snapshot.Create(context.Background(), failExec(), map[string]any{
		"vmid": "100", "name": "snap1",
	}) == nil {
		t.Fatal("expected error from failed qm snapshot")
	}
}

func TestDelete_Valid(t *testing.T) {
	m := successExec()
	err := snapshot.Delete(context.Background(), m, map[string]any{
		"vmid": "100", "name": "snap1",
	})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestDelete_QmError(t *testing.T) {
	if snapshot.Delete(context.Background(), failExec(), map[string]any{
		"vmid": "100", "name": "snap1",
	}) == nil {
		t.Fatal("expected error from failed qm delsnapshot")
	}
}

func TestDelete_MissingName(t *testing.T) {
	m := &proxmox.MockExec{}
	if snapshot.Delete(context.Background(), m, map[string]any{"vmid": "100"}) == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestRollback_QmError(t *testing.T) {
	if snapshot.Rollback(context.Background(), failExec(), map[string]any{
		"vmid": "100", "name": "snap1",
	}) == nil {
		t.Fatal("expected error from failed qm rollback")
	}
}

func TestRollback_MissingVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	if snapshot.Rollback(context.Background(), m, map[string]any{"name": "snap1"}) == nil {
		t.Fatal("expected error for missing vmid")
	}
}
