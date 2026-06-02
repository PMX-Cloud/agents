package template_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
	"github.com/pmx-cloud/agents/hypervisor/internal/template"
)

func TestConvert_Valid(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
	err := template.Convert(context.Background(), m, map[string]any{"vmid": "100"})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if m.LastCall().Args[0] != "template" {
		t.Fatalf("expected qm template call, got %v", m.LastCall().Args)
	}
}

func TestConvert_InvalidVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := template.Convert(context.Background(), m, map[string]any{"vmid": "1"})
	if err == nil {
		t.Fatal("expected error for invalid VMID")
	}
	if len(m.Calls) != 0 {
		t.Fatal("no call should be made for invalid VMID")
	}
}

func TestConvert_MissingVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := template.Convert(context.Background(), m, map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing vmid")
	}
}

func TestConvert_QmError(t *testing.T) {
	m := &proxmox.MockExec{
		Result: &proxmox.ExecResult{ExitCode: 1, Stderr: []byte("already a template")},
		Err:    fmt.Errorf("exit status 1"),
	}
	err := template.Convert(context.Background(), m, map[string]any{"vmid": "100"})
	if err == nil {
		t.Fatal("expected error when qm template fails")
	}
}

func TestClone_Valid(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
	err := template.Clone(context.Background(), m, map[string]any{
		"template_vmid": "100",
		"new_vmid":      "200",
		"name":          "my-clone",
	})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	call := m.LastCall()
	if call.Args[0] != "clone" {
		t.Fatalf("expected clone command, got %v", call.Args)
	}
}

func TestClone_WithoutName(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
	err := template.Clone(context.Background(), m, map[string]any{
		"template_vmid": "100",
		"new_vmid":      "200",
	})
	if err != nil {
		t.Fatalf("Clone without name: %v", err)
	}
}

func TestClone_InvalidTemplateVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := template.Clone(context.Background(), m, map[string]any{
		"template_vmid": "99",
		"new_vmid":      "200",
	})
	if err == nil {
		t.Fatal("expected error for invalid template_vmid")
	}
}

func TestClone_InvalidNewVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := template.Clone(context.Background(), m, map[string]any{
		"template_vmid": "100",
		"new_vmid":      "0",
	})
	if err == nil {
		t.Fatal("expected error for invalid new_vmid")
	}
}

func TestClone_UnsafeName(t *testing.T) {
	m := &proxmox.MockExec{}
	err := template.Clone(context.Background(), m, map[string]any{
		"template_vmid": "100",
		"new_vmid":      "200",
		"name":          "; rm -rf /",
	})
	if err == nil {
		t.Fatal("expected error for unsafe name")
	}
	if len(m.Calls) != 0 {
		t.Fatal("no call should be made for unsafe name")
	}
}

func TestClone_QmError(t *testing.T) {
	m := &proxmox.MockExec{
		Result: &proxmox.ExecResult{ExitCode: 1, Stderr: []byte("not found")},
		Err:    fmt.Errorf("exit status 1"),
	}
	err := template.Clone(context.Background(), m, map[string]any{
		"template_vmid": "100",
		"new_vmid":      "200",
	})
	if err == nil {
		t.Fatal("expected error when qm clone fails")
	}
}
