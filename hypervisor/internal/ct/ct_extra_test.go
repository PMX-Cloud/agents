package ct_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/ct"
	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

// notFoundCT simulates a CT that does not exist — ExitCode=1 but Err=nil
// so subsequent pct calls succeed.
func notFoundCT() *proxmox.MockExec {
	return &proxmox.MockExec{
		Result: &proxmox.ExecResult{ExitCode: 1, Stderr: []byte("not found")},
	}
}

func failCT() *proxmox.MockExec {
	return &proxmox.MockExec{
		Result: &proxmox.ExecResult{ExitCode: 1},
		Err:    fmt.Errorf("exit status 1"),
	}
}

func successCT() *proxmox.MockExec {
	return &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
}

// ── ct.create full path ───────────────────────────────────────────────────────

func TestCreate_FullPath(t *testing.T) {
	m := notFoundCT()
	var steps []string
	err := ct.Create(context.Background(), m, map[string]any{
		"ctid":       "101",
		"ostemplate": "local:vztmpl/debian-12.tar.xz",
		"hostname":   "test-ct",
	}, func(s string) { steps = append(steps, s) })
	if err != nil {
		t.Fatalf("Create full path: %v", err)
	}
}

func TestCreate_MissingOSTemplate(t *testing.T) {
	m := &proxmox.MockExec{}
	err := ct.Create(context.Background(), m, map[string]any{
		"ctid": "101",
	}, noopStep)
	if err == nil {
		t.Fatal("expected error for missing ostemplate")
	}
}

func TestCreate_UnsafeHostname(t *testing.T) {
	m := notFoundCT()
	err := ct.Create(context.Background(), m, map[string]any{
		"ctid":       "101",
		"ostemplate": "local:vztmpl/debian-12.tar.xz",
		"hostname":   "; rm -rf /",
	}, noopStep)
	if err == nil {
		t.Fatal("expected error for unsafe hostname")
	}
}

// ── ct.update valid path ──────────────────────────────────────────────────────

func TestUpdate_ValidOption(t *testing.T) {
	m := successCT()
	err := ct.Update(context.Background(), m, map[string]any{
		"ctid":    "100",
		"options": map[string]any{"memory": "512"},
	})
	if err != nil {
		t.Fatalf("Update valid option: %v", err)
	}
}

// ── ct.delete ─────────────────────────────────────────────────────────────────

func TestDelete_InvalidCTID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := ct.Delete(context.Background(), m, map[string]any{"ctid": "1"})
	if err == nil {
		t.Fatal("expected error for invalid CTID")
	}
}

func TestDelete_Stopped(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte("status: stopped"), ExitCode: 0}}
	err := ct.Delete(context.Background(), m, map[string]any{"ctid": "100"})
	if err != nil {
		t.Fatalf("Delete stopped CT: %v", err)
	}
}

// ── ct.start / stop / reboot ─────────────────────────────────────────────────

func TestStop_Valid(t *testing.T) {
	m := successCT()
	err := ct.Stop(context.Background(), m, map[string]any{"ctid": "100"})
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestStop_InvalidCTID(t *testing.T) {
	if ct.Stop(context.Background(), &proxmox.MockExec{}, map[string]any{"ctid": "1"}) == nil {
		t.Fatal("expected error for invalid CTID")
	}
}

func TestStop_Error(t *testing.T) {
	if ct.Stop(context.Background(), failCT(), map[string]any{"ctid": "100"}) == nil {
		t.Fatal("expected error")
	}
}

func TestReboot_Valid(t *testing.T) {
	m := successCT()
	err := ct.Reboot(context.Background(), m, map[string]any{"ctid": "100"})
	if err != nil {
		t.Fatalf("Reboot: %v", err)
	}
}

func TestReboot_InvalidCTID(t *testing.T) {
	if ct.Reboot(context.Background(), &proxmox.MockExec{}, map[string]any{"ctid": "99"}) == nil {
		t.Fatal("expected error for invalid CTID")
	}
}

// ── ct.mount ──────────────────────────────────────────────────────────────────

func TestMountAdd_Valid(t *testing.T) {
	m := successCT()
	err := ct.MountAdd(context.Background(), m, map[string]any{
		"ctid":       "100",
		"volume":     "local-lvm:vm-100-disk-0",
		"mountpoint": "/mnt/data",
	})
	if err != nil {
		t.Fatalf("MountAdd: %v", err)
	}
}

func TestMountAdd_InvalidCTID(t *testing.T) {
	if ct.MountAdd(context.Background(), &proxmox.MockExec{}, map[string]any{
		"ctid": "1", "volume": "local:v", "mountpoint": "/mnt/data",
	}) == nil {
		t.Fatal("expected error for invalid CTID")
	}
}

func TestMountRemove_Valid(t *testing.T) {
	m := successCT()
	err := ct.MountRemove(context.Background(), m, map[string]any{
		"ctid":     "100",
		"mount_id": "mp0",
	})
	if err != nil {
		t.Fatalf("MountRemove: %v", err)
	}
}

func TestMountRemove_InvalidCTID(t *testing.T) {
	if ct.MountRemove(context.Background(), &proxmox.MockExec{}, map[string]any{
		"ctid": "1", "mount_id": "mp0",
	}) == nil {
		t.Fatal("expected error for invalid CTID")
	}
}
