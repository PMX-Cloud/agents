package proxmox_test

import (
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

// ── Safe token tests ──────────────────────────────────────────────────────────

func TestIsSafeToken_Valid(t *testing.T) {
	cases := []string{"100", "vm-name", "local-lvm", "sata0", "scsi1", "net0"}
	for _, c := range cases {
		if !proxmox.IsSafeToken(c) {
			t.Errorf("expected %q to be safe", c)
		}
	}
}

func TestIsSafeToken_Injection_Rejected(t *testing.T) {
	cases := []string{
		`; rm -rf /`,
		`$(rm -rf /)`,
		"net0\nrm -rf /",
		"",
		"has space",
		"has\ttab",
	}
	for _, c := range cases {
		if proxmox.IsSafeToken(c) {
			t.Errorf("expected %q to be rejected as unsafe", c)
		}
	}
}

func TestRequiredSafeToken_Valid(t *testing.T) {
	params := map[string]any{"vmid": "100"}
	val, err := proxmox.RequiredSafeToken(params, "vmid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "100" {
		t.Fatalf("wrong value: %q", val)
	}
}

func TestRequiredSafeToken_Missing(t *testing.T) {
	_, err := proxmox.RequiredSafeToken(map[string]any{}, "vmid")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestRequiredSafeToken_Unsafe(t *testing.T) {
	params := map[string]any{"net0": `"; rm -rf /"`}
	_, err := proxmox.RequiredSafeToken(params, "net0")
	if err == nil {
		t.Fatal("expected error for unsafe value")
	}
}

func TestRequiredVMID_Valid(t *testing.T) {
	for _, id := range []string{"100", "999", "99999999"} {
		params := map[string]any{"vmid": id}
		val, err := proxmox.RequiredVMID(params, "vmid")
		if err != nil {
			t.Fatalf("VMID %q rejected: %v", id, err)
		}
		if val != id {
			t.Fatalf("wrong value for %q: %q", id, val)
		}
	}
}

func TestRequiredVMID_BelowMin(t *testing.T) {
	params := map[string]any{"vmid": "99"}
	_, err := proxmox.RequiredVMID(params, "vmid")
	if err == nil {
		t.Fatal("expected error for VMID < 100")
	}
}

func TestRequiredVMID_Alpha(t *testing.T) {
	params := map[string]any{"vmid": "abc"}
	_, err := proxmox.RequiredVMID(params, "vmid")
	if err == nil {
		t.Fatal("expected error for non-numeric VMID")
	}
}

func TestRequiredPCIID_Valid(t *testing.T) {
	params := map[string]any{"pciId": "0000:01:00.0"}
	_, err := proxmox.RequiredPCIID(params, "pciId")
	if err != nil {
		t.Fatalf("valid PCI ID rejected: %v", err)
	}
}

func TestRequiredPCIID_Injection(t *testing.T) {
	params := map[string]any{"pciId": "0000:01:00.0; rm -rf /"}
	_, err := proxmox.RequiredPCIID(params, "pciId")
	if err == nil {
		t.Fatal("expected rejection for injected PCI ID")
	}
}

func TestRequiredDevicePath_Valid(t *testing.T) {
	params := map[string]any{"device": "/dev/sda"}
	_, err := proxmox.RequiredDevicePath(params, "device")
	if err != nil {
		t.Fatalf("valid device path rejected: %v", err)
	}
}

func TestRequiredDevicePath_Traversal(t *testing.T) {
	params := map[string]any{"device": "/dev/../etc/shadow"}
	_, err := proxmox.RequiredDevicePath(params, "device")
	if err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestValidateAbsolutePath_NoTraversal(t *testing.T) {
	_, err := proxmox.ValidateAbsolutePath("/var/lib/vz/../../../etc/shadow", "p")
	if err == nil {
		t.Fatal("expected traversal rejection")
	}
}

// ── MockExec tests ────────────────────────────────────────────────────────────

func TestMockExec_RecordsCalls(t *testing.T) {
	m := &proxmox.MockExec{}
	m.Qm(nil, "start", "100")
	m.Qm(nil, "stop", "100")
	if len(m.Calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(m.Calls))
	}
	if m.Calls[0].Args[0] != "start" {
		t.Fatalf("wrong first arg: %q", m.Calls[0].Args[0])
	}
}

func TestMockExec_LastCall(t *testing.T) {
	m := &proxmox.MockExec{}
	if m.LastCall() != nil {
		t.Fatal("LastCall should be nil when no calls")
	}
	m.Pvesh(nil, "get", "/nodes")
	lc := m.LastCall()
	if lc.Binary != "pvesh" {
		t.Fatalf("wrong binary: %q", lc.Binary)
	}
}
