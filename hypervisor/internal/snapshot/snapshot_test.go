package snapshot_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
	"github.com/pmx-cloud/agents/hypervisor/internal/snapshot"
)

func TestCreate_UnsafeName(t *testing.T) {
	m := &proxmox.MockExec{}
	err := snapshot.Create(context.Background(), m, map[string]any{
		"vmid": "100", "name": `; rm -rf /`,
	})
	if err == nil {
		t.Fatal("expected error for unsafe snapshot name")
	}
	if len(m.Calls) != 0 {
		t.Fatal("no subprocess must be called")
	}
}

func TestCreate_UnsafeDescription(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
	err := snapshot.Create(context.Background(), m, map[string]any{
		"vmid": "100", "name": "snap1", "description": "hello; rm -rf /",
	})
	if err == nil {
		t.Fatal("expected error for unsafe description")
	}
}

func TestDelete_InvalidVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := snapshot.Delete(context.Background(), m, map[string]any{
		"vmid": "1", "name": "snap1",
	})
	if err == nil {
		t.Fatal("expected error for invalid VMID")
	}
}

func TestRollback_Calls(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
	err := snapshot.Rollback(context.Background(), m, map[string]any{
		"vmid": "100", "name": "snap1",
	})
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if m.LastCall().Args[0] != "rollback" {
		t.Fatalf("expected rollback command, got %v", m.LastCall().Args)
	}
}
