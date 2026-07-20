package provisioning_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/provisioning"
	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

func TestApply_BadYAML(t *testing.T) {
	m := &proxmox.MockExec{}
	err := provisioning.Apply(context.Background(), m, map[string]any{
		"vmid":     "100",
		"job_id":   "job-001",
		"userdata": "not: valid: yaml: : :",
	})
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if len(m.Calls) != 0 {
		t.Fatal("qm must not be called for invalid YAML")
	}
}

func TestApply_MissingVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := provisioning.Apply(context.Background(), m, map[string]any{
		"job_id":   "job-001",
		"userdata": "#cloud-config\nhostname: test\n",
	})
	if err == nil {
		t.Fatal("expected error for missing vmid")
	}
}

func TestApply_UnsafeJobID(t *testing.T) {
	m := &proxmox.MockExec{}
	err := provisioning.Apply(context.Background(), m, map[string]any{
		"vmid":     "100",
		"job_id":   "../../../etc/shadow",
		"userdata": "#cloud-config\nhostname: test\n",
	})
	if err == nil {
		t.Fatal("expected error for unsafe job_id")
	}
}

func TestCleanup_InvalidVMID(t *testing.T) {
	err := provisioning.Cleanup(map[string]any{"vmid": "1", "job_id": "job-001"})
	if err == nil {
		t.Fatal("expected error for VMID < 100")
	}
}

func TestCleanup_UnsafeJobID(t *testing.T) {
	err := provisioning.Cleanup(map[string]any{"vmid": "100", "job_id": `../../etc/shadow`})
	if err == nil {
		t.Fatal("expected error for unsafe job_id")
	}
}
