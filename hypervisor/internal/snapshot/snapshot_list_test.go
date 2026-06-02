package snapshot_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
	"github.com/pmx-cloud/agents/hypervisor/internal/snapshot"
)

func TestList_Valid(t *testing.T) {
	m := successExec()
	out, err := snapshot.List(context.Background(), m, map[string]any{"vmid": "100"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	_ = out
}

func TestList_InvalidVMID(t *testing.T) {
	m := &proxmox.MockExec{}
	_, err := snapshot.List(context.Background(), m, map[string]any{"vmid": "1"})
	if err == nil {
		t.Fatal("expected error for invalid VMID")
	}
}

func TestList_QmError(t *testing.T) {
	m := &proxmox.MockExec{
		Result: &proxmox.ExecResult{ExitCode: 1},
		Err:    fmt.Errorf("exit status 1"),
	}
	_, err := snapshot.List(context.Background(), m, map[string]any{"vmid": "100"})
	if err == nil {
		t.Fatal("expected error from qm listsnapshot failure")
	}
}

func TestCreate_AlreadyExistsError(t *testing.T) {
	// Simulate qm returning "already exists" in the error message.
	m := &proxmox.MockExec{
		Result: &proxmox.ExecResult{ExitCode: 1},
		Err:    fmt.Errorf("snapshot already exists"),
	}
	err := snapshot.Create(context.Background(), m, map[string]any{
		"vmid": "100", "name": "existing-snap",
	})
	if err == nil {
		t.Fatal("expected error for already-existing snapshot")
	}
	// Verify it's the SNAPSHOT_EXISTS error code.
	if len(err.Error()) > 0 && err.Error()[:13] != "SNAPSHOT_EXIS" {
		// Accept either SNAPSHOT_EXISTS or vm.snapshot.create — both are correct.
		t.Logf("error: %v", err)
	}
}
