// Package snapshot implements vm.snapshot.* commands (create, delete, rollback, list).
package snapshot

import (
	"context"
	"fmt"
	"strings"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

// Create creates a snapshot for a VM.
func Create(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	name, err := proxmox.RequiredSafeToken(params, "name")
	if err != nil {
		return err
	}
	description := proxmox.StringParam(params, "description", "")

	args := []string{"snapshot", vmid, name}
	if description != "" {
		// Validate description contains no shell metacharacters.
		if strings.ContainsAny(description, ";\n\r`$\\") {
			return fmt.Errorf("snapshot.create: description contains unsafe characters")
		}
		args = append(args, "--description", description)
	}

	if _, err := px.Qm(ctx, args...); err != nil {
		// Detect duplicate snapshot name.
		if strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("SNAPSHOT_EXISTS: snapshot %q already exists for VMID %s", name, vmid)
		}
		return fmt.Errorf("vm.snapshot.create: %w", err)
	}
	return nil
}

// Delete removes a snapshot.
func Delete(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	name, err := proxmox.RequiredSafeToken(params, "name")
	if err != nil {
		return err
	}
	if _, err := px.Qm(ctx, "delsnapshot", vmid, name); err != nil {
		return fmt.Errorf("vm.snapshot.delete: %w", err)
	}
	return nil
}

// Rollback rolls back a VM to a snapshot.
func Rollback(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	name, err := proxmox.RequiredSafeToken(params, "name")
	if err != nil {
		return err
	}
	if _, err := px.Qm(ctx, "rollback", vmid, name); err != nil {
		return fmt.Errorf("vm.snapshot.rollback: %w", err)
	}
	return nil
}

// List returns the snapshot list for a VM (raw qm listsnapshot output).
func List(ctx context.Context, px proxmox.ExecIface, params map[string]any) (string, error) {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return "", err
	}
	result, err := px.Qm(ctx, "listsnapshot", vmid)
	if err != nil {
		return "", fmt.Errorf("vm.snapshot.list: %w", err)
	}
	return result.StdoutString(), nil
}
