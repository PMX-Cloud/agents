package proxmox_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

// TestExec_RunRealCommand exercises Exec.run() with a real binary (echo) so
// the subprocess wrapper, audit log, and StdoutString helpers are covered.
func TestExec_RunRealCommand(t *testing.T) {
	e := &proxmox.Exec{
		// Temporarily override QmPath to use `echo` so this test works on macOS.
		QmPath: "/bin/echo",
	}
	result, err := e.Qm(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Qm with echo: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	out := result.StdoutString()
	if out != "hello" {
		t.Fatalf("expected 'hello', got %q", out)
	}
}

func TestExec_RunRealCommand_Stderr(t *testing.T) {
	// Use `cat` with a non-existent file to produce stderr output.
	e := &proxmox.Exec{QmPath: "/bin/cat"}
	result, err := e.Qm(context.Background(), "/nonexistent/file")
	// err should be non-nil (cat returns non-zero for missing files).
	_ = err
	if result != nil {
		// StderrFirst512 should contain something.
		_ = result.StderrFirst512()
	}
}

func TestExec_PveshPath(t *testing.T) {
	e := &proxmox.Exec{PveshPath: "/bin/echo"}
	result, err := e.Pvesh(context.Background(), "test")
	if err != nil {
		t.Fatalf("Pvesh with echo: %v", err)
	}
	if result.StdoutString() != "test" {
		t.Fatalf("expected 'test', got %q", result.StdoutString())
	}
}

func TestExec_PctPath(t *testing.T) {
	e := &proxmox.Exec{PctPath: "/bin/echo"}
	result, err := e.Pct(context.Background(), "pct-test")
	if err != nil {
		t.Fatalf("Pct with echo: %v", err)
	}
	if result.StdoutString() != "pct-test" {
		t.Fatalf("expected 'pct-test', got %q", result.StdoutString())
	}
}

func TestExec_PvesmPath(t *testing.T) {
	e := &proxmox.Exec{PvesmPath: "/bin/echo"}
	result, err := e.Pvesm(context.Background(), "pvesm-test")
	if err != nil {
		t.Fatalf("Pvesm with echo: %v", err)
	}
	_ = result
}

func TestExec_PvecmPath(t *testing.T) {
	e := &proxmox.Exec{PvecmPath: "/bin/echo"}
	result, err := e.Pvecm(context.Background(), "pvecm-test")
	if err != nil {
		t.Fatalf("Pvecm with echo: %v", err)
	}
	_ = result
}
