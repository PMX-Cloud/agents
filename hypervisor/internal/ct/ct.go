// Package ct implements container lifecycle commands using pct.
package ct

import (
	"context"
	"fmt"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

// ctUpdateAllowlist defines all pct options that ct.update may set.
var ctUpdateAllowlist = map[string]bool{
	"hostname": true, "memory": true, "swap": true, "cores": true,
	"onboot": true, "description": true, "tags": true, "net0": true,
	"net1": true, "net2": true, "protection": true, "unprivileged": true,
	"features": true, "startup": true,
}

func Create(ctx context.Context, px proxmox.ExecIface, params map[string]any, stepFn func(string)) error {
	ctid, err := proxmox.RequiredVMID(params, "ctid")
	if err != nil {
		return err
	}
	ostemplate, err := proxmox.RequiredSafeVolume(params, "ostemplate")
	if err != nil {
		return err
	}
	hostname := proxmox.StringParam(params, "hostname", "")
	if hostname != "" && !proxmox.IsSafeToken(hostname) {
		return fmt.Errorf("ct.create: hostname contains unsafe characters")
	}
	memory := proxmox.IntParam(params, "memory", 512)
	cores := proxmox.IntParam(params, "cores", 0)
	storage := proxmox.StringParam(params, "storage", "local-lvm")
	if !proxmox.IsSafeToken(storage) {
		return fmt.Errorf("ct.create: storage contains unsafe characters")
	}
	disk := proxmox.IntParam(params, "disk_gb", 8)

	// Idempotency check.
	if result, _ := px.Pct(ctx, "config", ctid); result != nil && result.ExitCode == 0 {
		stepFn("idempotent: CTID already exists")
		return nil
	}

	// Substitute an active rootdir-capable storage when the requested one
	// (often a backend default like "local-lvm") does not exist on this host.
	if resolved := proxmox.ResolveStorage(ctx, px, storage, "rootdir"); resolved != storage {
		stepFn(fmt.Sprintf("storage %q unavailable, using %q", storage, resolved))
		storage = resolved
	}

	stepFn("allocate")
	args := []string{"create", ctid, ostemplate,
		"--memory", fmt.Sprintf("%d", memory),
		"--rootfs", fmt.Sprintf("%s:%d", storage, disk),
	}
	if cores > 0 {
		args = append(args, "--cores", fmt.Sprintf("%d", cores))
	}
	if hostname != "" {
		args = append(args, "--hostname", hostname)
	}
	if _, err := px.Pct(ctx, args...); err != nil {
		return fmt.Errorf("ct.create: %w", err)
	}
	stepFn("done")
	return nil
}

func Update(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	ctid, err := proxmox.RequiredVMID(params, "ctid")
	if err != nil {
		return err
	}
	options, ok := params["options"].(map[string]any)
	if !ok || len(options) == 0 {
		return fmt.Errorf("ct.update: options map is required")
	}
	args := []string{"set", ctid}
	for key, val := range options {
		if !ctUpdateAllowlist[key] {
			return fmt.Errorf("ct.update: option %q is not in the allowlist", key)
		}
		sval := fmt.Sprintf("%v", val)
		if !proxmox.IsSafeToken(sval) {
			return fmt.Errorf("ct.update: value for %q contains unsafe characters", key)
		}
		args = append(args, "--"+key, sval)
	}
	if _, err := px.Pct(ctx, args...); err != nil {
		return fmt.Errorf("ct.update: %w", err)
	}
	return nil
}

func Delete(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	ctid, err := proxmox.RequiredVMID(params, "ctid")
	if err != nil {
		return err
	}
	// Idempotency: if the CT no longer exists on this host, deletion is a no-op.
	// Mirrors the ct.create existence probe. This lets the backend reconcile ghost
	// records whose host CT is already gone (e.g. after a failed create) instead of
	// leaving them wedged in "deleting" forever.
	if result, _ := px.Pct(ctx, "config", ctid); result == nil || result.ExitCode != 0 {
		return nil
	}
	// Refuse if running.
	status, err := ctStatus(ctx, px, ctid)
	if err != nil {
		return err
	}
	if status == "running" {
		return fmt.Errorf("ct.delete: CTID %s is running — stop it first", ctid)
	}
	if _, err := px.Pct(ctx, "destroy", ctid); err != nil {
		return fmt.Errorf("ct.delete: %w", err)
	}
	return nil
}

func Start(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	ctid, err := proxmox.RequiredVMID(params, "ctid")
	if err != nil {
		return err
	}
	if _, err := px.Pct(ctx, "start", ctid); err != nil {
		return fmt.Errorf("ct.start: %w", err)
	}
	return nil
}

func Stop(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	ctid, err := proxmox.RequiredVMID(params, "ctid")
	if err != nil {
		return err
	}
	if _, err := px.Pct(ctx, "stop", ctid); err != nil {
		return fmt.Errorf("ct.stop: %w", err)
	}
	return nil
}

func Reboot(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	ctid, err := proxmox.RequiredVMID(params, "ctid")
	if err != nil {
		return err
	}
	if _, err := px.Pct(ctx, "reboot", ctid); err != nil {
		return fmt.Errorf("ct.reboot: %w", err)
	}
	return nil
}

func MountAdd(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	ctid, err := proxmox.RequiredVMID(params, "ctid")
	if err != nil {
		return err
	}
	volume, err := proxmox.RequiredSafeVolume(params, "volume")
	if err != nil {
		return err
	}
	mountpoint, err := proxmox.RequiredAbsolutePath(params, "mountpoint")
	if err != nil {
		return err
	}
	slot := proxmox.IntParam(params, "slot", 0)
	mpArg := fmt.Sprintf("--mp%d", slot)
	mpVal := fmt.Sprintf("%s,mp=%s", volume, mountpoint)
	if _, err := px.Pct(ctx, "set", ctid, mpArg, mpVal); err != nil {
		return fmt.Errorf("ct.mount.add: %w", err)
	}
	return nil
}

func MountRemove(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	ctid, err := proxmox.RequiredVMID(params, "ctid")
	if err != nil {
		return err
	}
	slot := proxmox.IntParam(params, "slot", 0)
	mpArg := fmt.Sprintf("mp%d", slot)
	if _, err := px.Pct(ctx, "set", ctid, "--delete", mpArg); err != nil {
		return fmt.Errorf("ct.mount.remove: %w", err)
	}
	return nil
}

func ctStatus(ctx context.Context, px proxmox.ExecIface, ctid string) (string, error) {
	result, err := px.Pct(ctx, "status", ctid)
	if err != nil {
		return "", fmt.Errorf("ct.status %s: %w", ctid, err)
	}
	for _, line := range []string{result.StdoutString()} {
		if len(line) > 8 {
			return line[8:], nil // "status: running" → "running"
		}
	}
	return "unknown", nil
}
