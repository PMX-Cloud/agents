package vm_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
	"github.com/pmx-cloud/agents/hypervisor/internal/vm"
)

// ── vm.start ──────────────────────────────────────────────────────────────────

func TestStart_Valid(t *testing.T) {
	m := successExec()
	err := vm.Start(context.Background(), m, map[string]any{"vmid": "100"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if m.LastCall().Args[0] != "start" {
		t.Fatalf("expected start, got %v", m.LastCall().Args)
	}
}

func TestStart_QmError(t *testing.T) {
	err := vm.Start(context.Background(), failExec(), map[string]any{"vmid": "100"})
	if err == nil {
		t.Fatal("expected error from Start")
	}
}

// ── vm.reset / suspend / resume — error paths ─────────────────────────────────

func TestReset_QmError(t *testing.T) {
	if err := vm.Reset(context.Background(), failExec(), map[string]any{"vmid": "100"}); err == nil {
		t.Fatal("expected error from Reset")
	}
}

func TestSuspend_QmError(t *testing.T) {
	if err := vm.Suspend(context.Background(), failExec(), map[string]any{"vmid": "100"}); err == nil {
		t.Fatal("expected error from Suspend")
	}
}

func TestResume_QmError(t *testing.T) {
	if err := vm.Resume(context.Background(), failExec(), map[string]any{"vmid": "100"}); err == nil {
		t.Fatal("expected error from Resume")
	}
}

// ── vm.create with disk and cloud-init params ─────────────────────────────────

func TestCreate_WithDisk(t *testing.T) {
	m := notFoundExec()
	var steps []string
	err := vm.Create(context.Background(), m, map[string]any{
		"vmid": "102", "name": "vm-with-disk",
		"disk": "vm-102-disk-0", "storage": "local-lvm",
	}, func(s string) { steps = append(steps, s) })
	if err != nil {
		t.Fatalf("Create with disk: %v", err)
	}
	if !containsStep(steps, "attach-disk") {
		t.Fatalf("expected attach-disk step, got %v", steps)
	}
}

func TestCreate_WithCloudInit(t *testing.T) {
	m := notFoundExec()
	var steps []string
	err := vm.Create(context.Background(), m, map[string]any{
		"vmid": "103", "name": "vm-cloud-init", "cloud_init": true,
	}, func(s string) { steps = append(steps, s) })
	if err != nil {
		t.Fatalf("Create with cloud-init: %v", err)
	}
	if !containsStep(steps, "configure-cloud-init") {
		t.Fatalf("expected configure-cloud-init step, got %v", steps)
	}
}

func TestCreate_UnsafeDisk(t *testing.T) {
	m := notFoundExec()
	err := vm.Create(context.Background(), m, map[string]any{
		"vmid": "104", "name": "test", "disk": "; rm -rf /",
	}, noopStep)
	if err == nil {
		t.Fatal("expected error for unsafe disk param")
	}
}

// ── vm.update — missing vmid / ensureVMExists error ──────────────────────────

func TestUpdate_MissingVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := vm.Update(context.Background(), m, map[string]any{
		"options": map[string]any{"memory": "2048"},
	})
	if err == nil {
		t.Fatal("expected error for missing vmid")
	}
}

func TestUpdate_VMNotFound(t *testing.T) {
	err := vm.Update(context.Background(), failExec(), map[string]any{
		"vmid":    "100",
		"options": map[string]any{"memory": "2048"},
	})
	if err == nil {
		t.Fatal("expected error when VM not found")
	}
}

// ── vm.disk.detach / resize — error paths ─────────────────────────────────────

func TestDiskDetach_QmError(t *testing.T) {
	if err := vm.DiskDetach(context.Background(), failExec(), map[string]any{
		"vmid": "100", "disk_id": "scsi0",
	}); err == nil {
		t.Fatal("expected error")
	}
}

func TestDiskResize_QmError(t *testing.T) {
	if err := vm.DiskResize(context.Background(), failExec(), map[string]any{
		"vmid": "100", "disk_id": "scsi0", "size_gb": 5,
	}); err == nil {
		t.Fatal("expected error")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func containsStep(steps []string, want string) bool {
	for _, s := range steps {
		if s == want {
			return true
		}
	}
	return false
}
