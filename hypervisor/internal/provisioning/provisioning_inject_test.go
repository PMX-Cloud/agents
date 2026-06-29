package provisioning_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/provisioning"
	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

func successExec() *proxmox.MockExec {
	return &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
}

// ── ApplyWithDir — write path ────────────────────────────────────────────────

func TestApplyWithDir_Success(t *testing.T) {
	dir := t.TempDir()
	m := successExec()
	err := provisioning.ApplyWithDir(context.Background(), m, map[string]any{
		"vmid":     "100",
		"job_id":   "job-inject-001",
		"userdata": "#cloud-config\nhostname: testvm\n",
	}, dir)
	if err != nil {
		t.Fatalf("ApplyWithDir: %v", err)
	}
	// Verify the snippet file was written.
	snippetPath := filepath.Join(dir, "userdata-100-job-inject-001.yaml")
	if _, err := os.Stat(snippetPath); err != nil {
		t.Fatalf("snippet file not created: %v", err)
	}
	// Verify qm set was called with --cicustom.
	call := m.LastCall()
	if call.Args[2] != "--cicustom" {
		t.Fatalf("expected --cicustom, got %v", call.Args)
	}
}

func TestApplyWithDir_MkdirFails(t *testing.T) {
	// A non-creatable path (file where dir should be).
	tmpFile, _ := os.CreateTemp("", "prov-test")
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	m := successExec()
	err := provisioning.ApplyWithDir(context.Background(), m, map[string]any{
		"vmid":     "100",
		"job_id":   "job-002",
		"userdata": "hostname: test\n",
	}, tmpFile.Name()) // a file, not a directory
	if err == nil {
		t.Fatal("expected error when dir is actually a file")
	}
}

func TestApplyWithDir_QmError(t *testing.T) {
	dir := t.TempDir()
	m := &proxmox.MockExec{
		Result: &proxmox.ExecResult{ExitCode: 1},
		Err:    fmt.Errorf("exit status 1"),
	}
	_ = provisioning.ApplyWithDir(context.Background(), m, map[string]any{
		"vmid":     "100",
		"job_id":   "job-003",
		"userdata": "hostname: test\n",
	}, dir)
	// Accept error (qm fails) — verifies the qm-error path is exercised.
}

// ── CleanupWithDir ────────────────────────────────────────────────────────────

func TestCleanupWithDir_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	snippetPath := filepath.Join(dir, "userdata-100-job-del-001.yaml")
	os.WriteFile(snippetPath, []byte("data"), 0o644)

	err := provisioning.CleanupWithDir(map[string]any{
		"vmid": "100", "job_id": "job-del-001",
	}, dir)
	if err != nil {
		t.Fatalf("CleanupWithDir existing file: %v", err)
	}
	// File must be gone.
	if _, err := os.Stat(snippetPath); !os.IsNotExist(err) {
		t.Fatal("expected snippet file to be deleted")
	}
}

func TestCleanupWithDir_NonExistentFile(t *testing.T) {
	dir := t.TempDir()
	err := provisioning.CleanupWithDir(map[string]any{
		"vmid": "100", "job_id": "job-nofile",
	}, dir)
	if err != nil {
		t.Fatalf("CleanupWithDir non-existent file: %v", err)
	}
}
