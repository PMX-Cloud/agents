// Package template implements vm.template.* commands (convert + clone).
package template

import (
	"context"
	"fmt"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

// Convert converts a VM to a template (qm template <vmid>).
func Convert(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	if _, err := px.Qm(ctx, "template", vmid); err != nil {
		return fmt.Errorf("vm.template.convert: %w", err)
	}
	return nil
}

// Clone instantiates a full clone from a template (qm clone <template-vmid> <new-vmid> --full).
func Clone(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	templateVMID, err := proxmox.RequiredVMID(params, "template_vmid")
	if err != nil {
		return err
	}
	newVMID, err := proxmox.RequiredVMID(params, "new_vmid")
	if err != nil {
		return err
	}
	name := proxmox.StringParam(params, "name", "")

	args := []string{"clone", templateVMID, newVMID, "--full"}
	if name != "" {
		if !proxmox.IsSafeToken(name) {
			return fmt.Errorf("vm.template.clone: name contains unsafe characters: %q", name)
		}
		args = append(args, "--name", name)
	}

	if _, err := px.Qm(ctx, args...); err != nil {
		return fmt.Errorf("vm.template.clone: %w", err)
	}
	return nil
}
