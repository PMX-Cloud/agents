package vm_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
	"github.com/pmx-cloud/agents/hypervisor/internal/vm"
)

// notFoundExec simulates a VM that does not exist.
// ExitCode=1 bypasses the "VMID already exists" idempotency check (which tests
// ExitCode==0), but Err=nil so subsequent qm calls succeed.
func notFoundExec() *proxmox.MockExec {
	return &proxmox.MockExec{
		Result: &proxmox.ExecResult{ExitCode: 1, Stderr: []byte("does not exist")},
	}
}

// failExec returns a mock that fails with an error (for testing error paths).
func failExec() *proxmox.MockExec {
	return &proxmox.MockExec{
		Result: &proxmox.ExecResult{ExitCode: 1, Stderr: []byte("failed")},
		Err:    fmt.Errorf("exit status 1"),
	}
}

func successExec() *proxmox.MockExec {
	return &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
}

// ── vm.create full path ───────────────────────────────────────────────────────

func TestCreate_FullPath_ValidParams(t *testing.T) {
	m := notFoundExec()
	var steps []string
	err := vm.Create(context.Background(), m, map[string]any{
		"vmid":      "101",
		"name":      "test-vm",
		"memory_mb": 1024,
		"cores":     2,
	}, func(s string) { steps = append(steps, s) })
	if err != nil {
		t.Fatalf("Create full path: %v", err)
	}
	// At least one step should have been emitted.
	if len(steps) == 0 {
		t.Fatal("expected at least one step")
	}
}

func TestCreate_MissingName(t *testing.T) {
	m := notFoundExec()
	err := vm.Create(context.Background(), m, map[string]any{
		"vmid": "101",
		// no name
	}, noopStep)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

// ── vm.stop ───────────────────────────────────────────────────────────────────

func TestStop_GracefulTimeout(t *testing.T) {
	// Simulate a running VM that succeeds stop.
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte("status: running"), ExitCode: 0}}
	err := vm.Stop(context.Background(), m, map[string]any{"vmid": "100", "timeout_seconds": 1})
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestStop_InvalidVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := vm.Stop(context.Background(), m, map[string]any{"vmid": "0"})
	if err == nil {
		t.Fatal("expected error for invalid VMID")
	}
}

// ── vm.reboot / reset / suspend / resume ─────────────────────────────────────

func TestReboot_Valid(t *testing.T) {
	m := successExec()
	err := vm.Reboot(context.Background(), m, map[string]any{"vmid": "100"})
	if err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	if m.LastCall().Args[0] != "reboot" {
		t.Fatalf("expected reboot, got %v", m.LastCall().Args)
	}
}

func TestReboot_InvalidVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := vm.Reboot(context.Background(), m, map[string]any{"vmid": "1"})
	if err == nil {
		t.Fatal("expected error for invalid VMID")
	}
}

func TestReset_Valid(t *testing.T) {
	m := successExec()
	err := vm.Reset(context.Background(), m, map[string]any{"vmid": "100"})
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
}

func TestSuspend_Valid(t *testing.T) {
	m := successExec()
	err := vm.Suspend(context.Background(), m, map[string]any{"vmid": "100"})
	if err != nil {
		t.Fatalf("Suspend: %v", err)
	}
}

func TestResume_Valid(t *testing.T) {
	m := successExec()
	err := vm.Resume(context.Background(), m, map[string]any{"vmid": "100"})
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
}

// ── vm.delete ─────────────────────────────────────────────────────────────────

func TestDelete_StoppedVM(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte("status: stopped"), ExitCode: 0}}
	err := vm.Delete(context.Background(), m, map[string]any{"vmid": "100"})
	if err != nil {
		t.Fatalf("Delete of stopped VM: %v", err)
	}
}

func TestDelete_InvalidVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := vm.Delete(context.Background(), m, map[string]any{"vmid": "99"})
	if err == nil {
		t.Fatal("expected error for invalid VMID")
	}
}

// ── vm.migrate ────────────────────────────────────────────────────────────────

func TestMigrate_ValidParams(t *testing.T) {
	m := successExec()
	var steps []string
	err := vm.Migrate(context.Background(), m, map[string]any{
		"vmid":        "100",
		"target_node": "pve2",
		"online":      true,
	}, func(s string) { steps = append(steps, s) })
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
}

func TestMigrate_MissingTargetNode(t *testing.T) {
	m := &proxmox.MockExec{}
	err := vm.Migrate(context.Background(), m, map[string]any{"vmid": "100"}, noopStep)
	if err == nil {
		t.Fatal("expected error for missing target_node")
	}
}

// ── vm.disk.attach / detach ───────────────────────────────────────────────────

func TestDiskAttach_Valid(t *testing.T) {
	m := successExec()
	err := vm.DiskAttach(context.Background(), m, map[string]any{
		"vmid":    "100",
		"bus":     "scsi",
		"disk_id": "0",
		"volume":  "local-lvm:vm-100-disk-0",
	})
	if err != nil {
		t.Fatalf("DiskAttach: %v", err)
	}
}

func TestDiskAttach_InvalidVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := vm.DiskAttach(context.Background(), m, map[string]any{"vmid": "1", "bus": "scsi", "disk_id": "0", "volume": "local-lvm:v"})
	if err == nil {
		t.Fatal("expected error for invalid VMID")
	}
}

func TestDiskDetach_Valid(t *testing.T) {
	m := successExec()
	err := vm.DiskDetach(context.Background(), m, map[string]any{
		"vmid":    "100",
		"disk_id": "scsi0",
	})
	if err != nil {
		t.Fatalf("DiskDetach: %v", err)
	}
}

func TestDiskResize_ValidPositive(t *testing.T) {
	m := successExec()
	err := vm.DiskResize(context.Background(), m, map[string]any{
		"vmid": "100", "disk_id": "scsi0", "size_gb": 10,
	})
	if err != nil {
		t.Fatalf("DiskResize: %v", err)
	}
}

// ── VMStatus and ensureVMExists ───────────────────────────────────────────────

func TestVMStatus_Running(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte("status: running"), ExitCode: 0}}
	status, err := vm.VMStatus(context.Background(), m, "100")
	if err != nil {
		t.Fatalf("VMStatus: %v", err)
	}
	if status != "running" {
		t.Fatalf("expected running, got %q", status)
	}
}

func TestVMStatus_QmError(t *testing.T) {
	_, err := vm.VMStatus(context.Background(), failExec(), "100")
	if err == nil {
		t.Fatal("expected error when qm status fails")
	}
}
