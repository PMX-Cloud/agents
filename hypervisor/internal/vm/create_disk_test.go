package vm_test

import (
	"context"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
	"github.com/pmx-cloud/agents/hypervisor/internal/vm"
)

// scriptedExec routes each subprocess call through a handler so multi-step
// flows (idempotency probe → storage resolve → create → set) can be scripted.
type scriptedExec struct {
	calls   []proxmox.MockCall
	handler func(binary string, args []string) *proxmox.ExecResult
}

func (s *scriptedExec) run(binary string, args ...string) (*proxmox.ExecResult, error) {
	s.calls = append(s.calls, proxmox.MockCall{Binary: binary, Args: args})
	return s.handler(binary, args), nil
}

func (s *scriptedExec) Pvesh(_ context.Context, args ...string) (*proxmox.ExecResult, error) {
	return s.run("pvesh", args...)
}
func (s *scriptedExec) Qm(_ context.Context, args ...string) (*proxmox.ExecResult, error) {
	return s.run("qm", args...)
}
func (s *scriptedExec) Pct(_ context.Context, args ...string) (*proxmox.ExecResult, error) {
	return s.run("pct", args...)
}
func (s *scriptedExec) Pvesm(_ context.Context, args ...string) (*proxmox.ExecResult, error) {
	return s.run("pvesm", args...)
}
func (s *scriptedExec) Pvecm(_ context.Context, args ...string) (*proxmox.ExecResult, error) {
	return s.run("pvecm", args...)
}

const testStorageList = `[
  {"storage":"GB-250","content":"rootdir,images","active":1,"enabled":1,"avail":221731853312}
]`

func newCreateScript() *scriptedExec {
	return &scriptedExec{handler: func(binary string, args []string) *proxmox.ExecResult {
		if binary == "qm" && args[0] == "config" {
			return &proxmox.ExecResult{ExitCode: 2} // VM does not exist yet
		}
		if binary == "pvesh" {
			return &proxmox.ExecResult{ExitCode: 0, Stdout: []byte(testStorageList)}
		}
		return &proxmox.ExecResult{ExitCode: 0}
	}}
}

func TestCreate_AllocatesBootDisk(t *testing.T) {
	s := newCreateScript()
	err := vm.Create(context.Background(), s, map[string]any{
		"vmid": "990", "name": "disk-test", "memory": 1024, "cores": 1,
		"storage": "local-lvm", "disk_gb": 16,
	}, noopStep)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	var setCall []string
	for _, call := range s.calls {
		if call.Binary == "qm" && call.Args[0] == "set" {
			setCall = call.Args
		}
	}
	if setCall == nil {
		t.Fatalf("expected qm set for boot disk, calls: %+v", s.calls)
	}
	joined := strings.Join(setCall, " ")
	// local-lvm is absent from the host → resolved to GB-250.
	if !strings.Contains(joined, "--scsi0 GB-250:16") {
		t.Errorf("expected --scsi0 GB-250:16, got %q", joined)
	}
	if !strings.Contains(joined, "--boot order=scsi0;net0") {
		t.Errorf("expected boot order, got %q", joined)
	}
}

func TestCreate_NoDiskParamsStaysDiskless(t *testing.T) {
	s := newCreateScript()
	err := vm.Create(context.Background(), s, map[string]any{
		"vmid": "991", "name": "diskless", "memory": 512,
	}, noopStep)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, call := range s.calls {
		if call.Binary == "pvesh" {
			t.Errorf("storage resolution must be skipped without disk params")
		}
		if call.Binary == "qm" && call.Args[0] == "set" {
			t.Errorf("no qm set expected without disk params, got %v", call.Args)
		}
	}
}

func TestCreate_AppliesAdvancedQEMUOptions(t *testing.T) {
	s := newCreateScript()
	err := vm.Create(context.Background(), s, map[string]any{
		"vmid": "992", "name": "advanced-vm", "memory": 4096, "cores": 4, "sockets": 2,
		"disk_gb": 32, "net0": "virtio,bridge=vmbr1,firewall=1",
		"cpu_model": "host", "machine": "q35", "bios": "ovmf",
		"agent_enabled": true, "start_on_boot": true, "nested_virtualization": true,
		"boot_order": "net0;scsi0;ide2",
	}, noopStep)
	if err != nil {
		t.Fatalf("create advanced VM: %v", err)
	}

	var createCall, bootCall []string
	for _, call := range s.calls {
		if call.Binary != "qm" {
			continue
		}
		if call.Args[0] == "create" {
			createCall = call.Args
		}
		if call.Args[0] == "set" && strings.Contains(strings.Join(call.Args, " "), "order=net0;scsi0;ide2") {
			bootCall = call.Args
		}
	}
	joined := strings.Join(createCall, " ")
	for _, expected := range []string{
		"--sockets 2", "--ide2 none,media=cdrom", "--net0 virtio,bridge=vmbr1,firewall=1", "--cpu host",
		"--machine q35", "--bios ovmf", "--agent enabled=1", "--onboot 1",
		"--tags pmx-nested-cloud",
	} {
		if !strings.Contains(joined, expected) {
			t.Errorf("expected %q in qm create args, got %q", expected, joined)
		}
	}
	if bootCall == nil {
		t.Fatalf("expected explicit boot-order update, calls: %+v", s.calls)
	}
}

func TestCreate_RejectsUnsafeNetworkAndBootOrder(t *testing.T) {
	for name, params := range map[string]map[string]any{
		"network": {
			"vmid": "993", "name": "bad-net", "net0": "virtio,bridge=vmbr0,rate=0",
		},
		"boot": {
			"vmid": "994", "name": "bad-boot", "boot_order": "scsi0;scsi0",
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newCreateScript()
			if err := vm.Create(context.Background(), s, params, noopStep); err == nil {
				t.Fatal("expected unsafe create parameters to be rejected")
			}
			if len(s.calls) != 0 {
				t.Fatalf("no subprocess expected for unsafe parameters, got %+v", s.calls)
			}
		})
	}
}
