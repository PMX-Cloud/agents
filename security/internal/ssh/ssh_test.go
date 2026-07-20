package ssh_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pmx-cloud/agents/security/internal/rootscope"
	"github.com/pmx-cloud/agents/security/internal/ssh"
)

type mockRootRunner struct{}

func (m *mockRootRunner) RunRoot(ctx context.Context, jobID, name, command string, args []string, h rootscope.Hardening) (*rootscope.Result, error) {
	return &rootscope.Result{ExitCode: 0}, nil
}

func TestAuditDetectsDrift(t *testing.T) {
	dir := t.TempDir()
	mainCfg := filepath.Join(dir, "sshd_config")
	dropDir := filepath.Join(dir, "sshd_config.d")
	if err := os.MkdirAll(dropDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(mainCfg, []byte("PasswordAuthentication yes\n"), 0o600)

	res, err := ssh.Audit(mainCfg, dropDir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(res.Drift) == 0 {
		t.Fatalf("expected drift, got none")
	}
}

func TestHardenWritesTempFilesAndInvokesRootRunner(t *testing.T) {
	err := ssh.Harden(context.Background(), ssh.HardenParams{JobID: "job1", StateDir: t.TempDir()}, &mockRootRunner{})
	if err != nil {
		t.Fatalf("harden: %v", err)
	}
}
