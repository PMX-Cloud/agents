/*
Package vm implements VM lifecycle commands for pmx-hypervisor.

All commands invoke qm/pvesm via proxmox.ExecIface — never bash -c, never
string-interpolated shell.

Commands: vm.create, vm.update, vm.start, vm.stop, vm.reboot, vm.reset,

	vm.suspend, vm.resume, vm.delete, vm.migrate
*/
package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

// ── Common helpers ────────────────────────────────────────────────────────────

// VMStatus returns the current status of a VMID via qm status.
func VMStatus(ctx context.Context, px proxmox.ExecIface, vmid string) (string, error) {
	result, err := px.Qm(ctx, "status", vmid, "--verbose", "0")
	if err != nil {
		return "", fmt.Errorf("vm.status %s: %w", vmid, err)
	}
	for _, line := range strings.Split(result.StdoutString(), "\n") {
		if strings.HasPrefix(line, "status:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "status:")), nil
		}
	}
	return "unknown", nil
}

// ensureVMExists returns nil if the VMID exists, error otherwise.
func ensureVMExists(ctx context.Context, px proxmox.ExecIface, vmid string) error {
	_, err := px.Qm(ctx, "config", vmid)
	if err != nil {
		return fmt.Errorf("VMID %s does not exist: %w", vmid, err)
	}
	return nil
}

// ── vm.create ────────────────────────────────────────────────────────────────

// CreateParams holds validated parameters for vm.create.
type CreateParams struct {
	VMID      string
	Name      string
	MemoryMB  int
	Cores     int
	Net0      string // e.g. "virtio,bridge=vmbr0"
	Disk      string // pre-prepared disk from pmx-storage
	Storage   string
	CloudInit bool
	OSType    string
}

// vmUpdateAllowlist defines all qm options that vm.update is permitted to set.
var vmUpdateAllowlist = map[string]bool{
	"name": true, "memory": true, "cores": true, "sockets": true,
	"cpu": true, "net0": true, "net1": true, "net2": true, "net3": true,
	"onboot": true, "description": true, "tags": true, "kvm": true,
	"balloon": true, "numa": true, "agent": true, "ostype": true,
	"boot": true, "bootdisk": true, "startup": true, "watchdog": true,
	"hotplug": true, "vcpus": true, "shares": true,
}

// Create runs vm.create — idempotent (same VMID + config → success without re-work).
// Emits step frames via the stepFn callback.
func Create(ctx context.Context, px proxmox.ExecIface, params map[string]any, stepFn func(string)) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	name, err := proxmox.RequiredSafeToken(params, "name")
	if err != nil {
		return err
	}
	memory := proxmox.IntParam(params, "memory", 1024)
	cores := proxmox.IntParam(params, "cores", 1)
	net0 := proxmox.StringParam(params, "net0", "virtio,bridge=vmbr0")
	storage := proxmox.StringParam(params, "storage", "local-lvm")
	disk := proxmox.StringParam(params, "disk", "")

	// Idempotency: check if VMID already exists.
	if result, _ := px.Qm(ctx, "config", vmid); result != nil && result.ExitCode == 0 {
		stepFn("idempotent: VMID already exists, returning success")
		return nil
	}

	// Step: allocate.
	stepFn("allocate")
	if _, err := px.Qm(ctx, "create", vmid,
		"--name", name,
		"--memory", fmt.Sprintf("%d", memory),
		"--cores", fmt.Sprintf("%d", cores),
		"--net0", net0,
		"--ostype", proxmox.StringParam(params, "ostype", "l26"),
	); err != nil {
		return fmt.Errorf("vm.create allocate: %w", err)
	}

	// Step: attach-disk (disk was prepared by pmx-storage).
	if disk != "" {
		stepFn("attach-disk")
		if !proxmox.IsSafeToken(disk) {
			return fmt.Errorf("disk param contains unsafe characters: %q", disk)
		}
		if !proxmox.IsSafeToken(storage) {
			return fmt.Errorf("storage param contains unsafe characters: %q", storage)
		}
		if _, err := px.Qm(ctx, "set", vmid,
			"--scsi0", fmt.Sprintf("%s:%s", storage, disk),
		); err != nil {
			return fmt.Errorf("vm.create attach-disk: %w", err)
		}
	}

	// Step: configure-cloud-init (optional).
	if proxmox.BoolParam(params, "cloud_init") {
		stepFn("configure-cloud-init")
		if _, err := px.Qm(ctx, "set", vmid,
			"--ide2", fmt.Sprintf("%s:cloudinit", storage),
			"--serial0", "socket",
			"--vga", "serial0",
		); err != nil {
			return fmt.Errorf("vm.create cloud-init: %w", err)
		}
	}

	stepFn("done")
	return nil
}

// ── vm.update ────────────────────────────────────────────────────────────────

// Update runs vm.update — validates every option key against the allowlist.
func Update(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	if err := ensureVMExists(ctx, px, vmid); err != nil {
		return err
	}

	options, ok := params["options"].(map[string]any)
	if !ok || len(options) == 0 {
		return fmt.Errorf("vm.update: options map is required")
	}

	args := []string{"set", vmid}
	for key, val := range options {
		if !vmUpdateAllowlist[key] {
			return fmt.Errorf("vm.update: option %q is not in the allowlist", key)
		}
		sval := fmt.Sprintf("%v", val)
		if !proxmox.IsSafeToken(sval) {
			return fmt.Errorf("vm.update: value for %q contains unsafe characters", key)
		}
		args = append(args, "--"+key, sval)
	}

	if _, err := px.Qm(ctx, args...); err != nil {
		return fmt.Errorf("vm.update: %w", err)
	}
	return nil
}

// ── Lifecycle: start/stop/reboot/reset/suspend/resume ────────────────────────

func Start(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	if _, err := px.Qm(ctx, "start", vmid); err != nil {
		return fmt.Errorf("vm.start: %w", err)
	}
	return nil
}

// Stop gracefully shuts down with timeout, escalating to hard stop.
func Stop(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	timeoutSec := proxmox.IntParam(params, "timeout_seconds", 60)
	force := proxmox.BoolParam(params, "force")

	if !force {
		// Graceful shutdown first.
		_, _ = px.Qm(ctx, "shutdown", vmid, "--timeout", fmt.Sprintf("%d", timeoutSec))
		// Check if it stopped.
		status, _ := VMStatus(ctx, px, vmid)
		if status == "stopped" {
			return nil
		}
	}

	// Hard stop.
	if _, err := px.Qm(ctx, "stop", vmid); err != nil {
		return fmt.Errorf("vm.stop: %w", err)
	}
	return nil
}

func Reboot(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	if _, err := px.Qm(ctx, "reboot", vmid); err != nil {
		return fmt.Errorf("vm.reboot: %w", err)
	}
	return nil
}

func Reset(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	if _, err := px.Qm(ctx, "reset", vmid); err != nil {
		return fmt.Errorf("vm.reset: %w", err)
	}
	return nil
}

func Suspend(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	if _, err := px.Qm(ctx, "suspend", vmid); err != nil {
		return fmt.Errorf("vm.suspend: %w", err)
	}
	return nil
}

func Resume(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	if _, err := px.Qm(ctx, "resume", vmid); err != nil {
		return fmt.Errorf("vm.resume: %w", err)
	}
	return nil
}

// ── vm.delete ─────────────────────────────────────────────────────────────────

// Delete destroys a VM. Refuses if VM is running.
func Delete(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	status, err := VMStatus(ctx, px, vmid)
	if err != nil {
		return err
	}
	if status == "running" {
		return fmt.Errorf("vm.delete: VMID %s is running — stop it first", vmid)
	}
	if _, err := px.Qm(ctx, "destroy", vmid, "--purge"); err != nil {
		return fmt.Errorf("vm.delete: %w", err)
	}
	return nil
}

// ── vm.migrate ────────────────────────────────────────────────────────────────

// Migrate runs qm migrate. stepFn receives progress updates.
func Migrate(ctx context.Context, px proxmox.ExecIface, params map[string]any, stepFn func(string)) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	targetNode, err := proxmox.RequiredSafeToken(params, "target_node")
	if err != nil {
		return err
	}
	online := "0"
	if proxmox.BoolParam(params, "online") {
		online = "1"
	}

	stepFn("migrate: starting")
	if _, err := px.Qm(ctx, "migrate", vmid, targetNode, "--online", online); err != nil {
		return fmt.Errorf("vm.migrate: %w", err)
	}
	stepFn("migrate: complete")
	return nil
}

// ── vm.disk.attach/detach/resize ─────────────────────────────────────────────

func DiskAttach(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	volume, err := proxmox.RequiredSafeVolume(params, "volume")
	if err != nil {
		return err
	}
	bus := proxmox.StringParam(params, "bus", "scsi")
	slot := proxmox.IntParam(params, "slot", 1)
	if !proxmox.IsSafeToken(bus) {
		return fmt.Errorf("vm.disk.attach: bus contains unsafe characters")
	}
	busArg := fmt.Sprintf("--%s%d", bus, slot)
	if _, err := px.Qm(ctx, "set", vmid, busArg, volume); err != nil {
		return fmt.Errorf("vm.disk.attach: %w", err)
	}
	return nil
}

func DiskDetach(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	diskID, err := proxmox.RequiredSafeToken(params, "disk_id")
	if err != nil {
		return err
	}
	force := "0"
	if proxmox.BoolParam(params, "force") {
		force = "1"
	}
	if _, err := px.Qm(ctx, "unlink", vmid, "--idlist", diskID, "--force", force); err != nil {
		return fmt.Errorf("vm.disk.detach: %w", err)
	}
	return nil
}

func DiskResize(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	vmid, err := proxmox.RequiredVMID(params, "vmid")
	if err != nil {
		return err
	}
	diskID, err := proxmox.RequiredSafeToken(params, "disk_id")
	if err != nil {
		return err
	}
	sizeGB := proxmox.IntParam(params, "size_gb", 0)
	if sizeGB <= 0 {
		return fmt.Errorf("vm.disk.resize: size_gb must be > 0 (shrink not supported)")
	}
	if _, err := px.Qm(ctx, "resize", vmid, diskID, fmt.Sprintf("+%dG", sizeGB)); err != nil {
		return fmt.Errorf("vm.disk.resize: %w", err)
	}
	return nil
}

// ── vm.create.synology-dsm / vm.create.zimaos ────────────────────────────────

// SynologyDSMParams returns the vm.create params for a Synology DSM VM.
func SynologyDSMParams(envelope map[string]any) map[string]any {
	p := cloneParams(envelope)
	p["ostype"] = "other"
	p["memory"] = proxmox.IntParam(envelope, "memory", 4096)
	p["cores"] = proxmox.IntParam(envelope, "cores", 2)
	p["net0"] = proxmox.StringParam(envelope, "net0", "e1000,bridge=vmbr0")
	return p
}

// ZimaOSParams returns the vm.create params for a ZimaOS VM.
func ZimaOSParams(envelope map[string]any) map[string]any {
	p := cloneParams(envelope)
	p["ostype"] = "l26"
	p["memory"] = proxmox.IntParam(envelope, "memory", 2048)
	p["cores"] = proxmox.IntParam(envelope, "cores", 2)
	p["net0"] = proxmox.StringParam(envelope, "net0", "virtio,bridge=vmbr0")
	return p
}

func cloneParams(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// ── Unused at compile-time on macOS (JSON import) ────────────────────────────

var _ = json.Marshal
var _ = time.Now
