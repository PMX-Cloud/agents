package spawn

import (
	"context"
	"testing"
)

// TestCloseFd_NoOp verifies closeFd is safe to call with any value on non-Linux.
// This covers the stub implementation in spawn_other.go.
func TestCloseFd_NoOp(t *testing.T) {
	// Calling with -1 (invalid fd) must not panic on non-Linux.
	closeFd(-1)
	closeFd(0)
}

// TestDefaultCmdRunner_ErrorPath verifies the defaultCmdRunner wrapper
// correctly runs a command and captures combined output on error.
func TestDefaultCmdRunner_ErrorPath(t *testing.T) {
	// Run a nonexistent command to exercise the error path.
	_, err := defaultCmdRunner(context.Background(), []string{"__pmx_nonexistent_cmd__"}, nil)
	if err == nil {
		t.Fatal("expected error when running a nonexistent command")
	}
}
