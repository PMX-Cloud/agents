package vm_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
	"github.com/pmx-cloud/agents/hypervisor/internal/vm"
)

func noopStep(_ string) {}

func TestCreate_InvalidVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := vm.Create(context.Background(), m, map[string]any{"vmid": "99", "name": "test"}, noopStep)
	if err == nil {
		t.Fatal("expected error for VMID < 100")
	}
	if len(m.Calls) != 0 {
		t.Fatal("no subprocess must be called for invalid VMID")
	}
}

func TestCreate_UnsafeName(t *testing.T) {
	m := &proxmox.MockExec{}
	err := vm.Create(context.Background(), m, map[string]any{
		"vmid": "100",
		"name": `; rm -rf /`,
	}, noopStep)
	if err == nil {
		t.Fatal("expected error for unsafe name")
	}
	if len(m.Calls) != 0 {
		t.Fatal("no subprocess must be called for unsafe name")
	}
}

func TestCreate_Idempotent(t *testing.T) {
	// When qm config returns exit 0, create is a no-op.
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
	var steps []string
	err := vm.Create(context.Background(), m, map[string]any{
		"vmid": "200", "name": "existing-vm",
	}, func(s string) { steps = append(steps, s) })
	if err != nil {
		t.Fatalf("idempotent create: %v", err)
	}
	if len(steps) == 0 || steps[0] != "idempotent: VMID already exists, returning success" {
		t.Fatalf("expected idempotent step, got %v", steps)
	}
	// Only qm config was called.
	if len(m.Calls) != 1 || m.Calls[0].Args[0] != "config" {
		t.Fatalf("expected only qm config call, got %v", m.Calls)
	}
}

func TestUpdate_UnknownOption(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
	err := vm.Update(context.Background(), m, map[string]any{
		"vmid":    "100",
		"options": map[string]any{"unknown_option": "value"},
	})
	if err == nil {
		t.Fatal("expected error for option not in allowlist")
	}
}

func TestUpdate_ValidOption(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
	err := vm.Update(context.Background(), m, map[string]any{
		"vmid":    "100",
		"options": map[string]any{"memory": "4096"},
	})
	if err != nil {
		t.Fatalf("valid option rejected: %v", err)
	}
}

func TestDelete_RequiresStoppedVM(t *testing.T) {
	// Simulate running VM (qm status returns "running").
	m := &proxmox.MockExec{
		Result: &proxmox.ExecResult{
			Stdout:   []byte("status: running"),
			ExitCode: 0,
		},
	}
	err := vm.Delete(context.Background(), m, map[string]any{"vmid": "100"})
	if err == nil {
		t.Fatal("expected error when deleting running VM")
	}
}

func TestStart_InvalidVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := vm.Start(context.Background(), m, map[string]any{"vmid": "0"})
	if err == nil {
		t.Fatal("expected error for invalid VMID")
	}
	if len(m.Calls) != 0 {
		t.Fatal("no call must be made for invalid VMID")
	}
}

func TestDiskResize_ZeroSize(t *testing.T) {
	m := &proxmox.MockExec{}
	err := vm.DiskResize(context.Background(), m, map[string]any{
		"vmid": "100", "disk_id": "scsi0", "size_gb": 0,
	})
	if err == nil {
		t.Fatal("expected error for size_gb=0")
	}
}

func TestDiskResize_NegativeSize(t *testing.T) {
	m := &proxmox.MockExec{}
	err := vm.DiskResize(context.Background(), m, map[string]any{
		"vmid": "100", "disk_id": "scsi0", "size_gb": -10,
	})
	if err == nil {
		t.Fatal("expected error for negative size_gb")
	}
}

func TestMigrate_InvalidTargetNode(t *testing.T) {
	m := &proxmox.MockExec{}
	err := vm.Migrate(context.Background(), m, map[string]any{
		"vmid": "100", "target_node": `; rm -rf /`,
	}, noopStep)
	if err == nil {
		t.Fatal("expected error for unsafe target_node")
	}
	if len(m.Calls) != 0 {
		t.Fatal("no subprocess must be called for unsafe target")
	}
}

func TestSynologyDSMParams(t *testing.T) {
	envelope := map[string]any{"vmid": "200", "name": "synology"}
	p := vm.SynologyDSMParams(envelope)
	if p["ostype"] != "other" {
		t.Fatalf("wrong ostype: %v", p["ostype"])
	}
}

func TestZimaOSParams(t *testing.T) {
	envelope := map[string]any{"vmid": "201", "name": "zimaos"}
	p := vm.ZimaOSParams(envelope)
	if p["ostype"] != "l26" {
		t.Fatalf("wrong ostype: %v", p["ostype"])
	}
}
