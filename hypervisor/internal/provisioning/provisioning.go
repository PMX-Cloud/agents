/*
Package provisioning implements provisioning.apply — applies cloud-init userdata to a VM.

Security:
  - Userdata is YAML-parsed at receive time; any parse failure rejects the envelope.
  - Snippet file is written as root:root 0640 — never world-readable.
  - File path is constructed from validated VMID + JobID; no free-form user input in path.
  - After VM consumes the snippet, provisioning.cleanup deletes it.
*/
package provisioning

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

// DefaultSnippetDir is the Proxmox snippet directory used in production.
const DefaultSnippetDir = "/var/lib/vz/snippets"

// Apply writes userdata to a snippet file and configures the VM to use it.
func Apply(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	return ApplyWithDir(ctx, px, params, DefaultSnippetDir)
}

// ApplyWithDir is the injectable variant used in tests.
func ApplyWithDir(ctx context.Context, px proxmox.ExecIface, params map[string]any, dir string) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	jobID := proxmox.StringParam(params, "job_id", "")
	if jobID == "" {
		return fmt.Errorf("provisioning.apply: job_id is required")
	}
	if !proxmox.IsJobID(jobID) {
		return fmt.Errorf("provisioning.apply: job_id contains unsafe characters")
	}
	userdata, ok := params["userdata"].(string)
	if !ok || userdata == "" {
		return fmt.Errorf("provisioning.apply: userdata is required")
	}

	// Validate YAML at envelope-receive time.
	var userdataObj any
	if err := yaml.Unmarshal([]byte(userdata), &userdataObj); err != nil {
		return fmt.Errorf("provisioning.apply: userdata is not valid YAML: %w", err)
	}

	// Build snippet path — no user input in path components beyond validated vmid/jobID.
	snippetName := fmt.Sprintf("userdata-%s-%s.yaml", vmid, jobID)
	snippetPath := filepath.Join(dir, snippetName)

	// Write snippet: root:root, 0640 (never world-readable).
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("provisioning.apply: mkdir %s: %w", dir, err)
	}
	f, err := os.OpenFile(snippetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return fmt.Errorf("provisioning.apply: create snippet: %w", err)
	}
	if _, err := f.WriteString(userdata); err != nil {
		f.Close()
		os.Remove(snippetPath)
		return fmt.Errorf("provisioning.apply: write snippet: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("provisioning.apply: close snippet: %w", err)
	}

	// Configure VM to use the snippet.
	cicustomVal := fmt.Sprintf("user=local:snippets/%s", snippetName)
	if _, err := px.Qm(ctx, "set", vmid, "--cicustom", cicustomVal); err != nil {
		return fmt.Errorf("provisioning.apply: qm set cicustom: %w", err)
	}
	return nil
}

// Cleanup removes the snippet file after the VM has consumed it.
func Cleanup(params map[string]any) error {
	return CleanupWithDir(params, DefaultSnippetDir)
}

// CleanupWithDir is the injectable variant used in tests.
func CleanupWithDir(params map[string]any, dir string) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	jobID := proxmox.StringParam(params, "job_id", "")
	if jobID == "" {
		return fmt.Errorf("provisioning.cleanup: job_id is required")
	}
	if !proxmox.IsJobID(jobID) {
		return fmt.Errorf("provisioning.cleanup: job_id contains unsafe characters")
	}
	snippetName := fmt.Sprintf("userdata-%s-%s.yaml", vmid, jobID)
	snippetPath := filepath.Join(dir, snippetName)
	if err := os.Remove(snippetPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("provisioning.cleanup: %w", err)
	}
	return nil
}
