// Package libvirt is the libvirt/KVM hypervisor provider for pmx-hypervisor.
//
// VMStart / VMStop / VMDelete are wired to `virsh` so the backend can drive
// power-state operations on Debian/Ubuntu hosts that run libvirt. VM creation
// and storage listing still go through the legacy adapter for now — they
// need richer plumbing (qemu-img, virsh define from XML) that the agent
// doesn't gain by routing through this surface.
package libvirt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/pmx-cloud/agents/hypervisor/internal/provider"
)

// Test seam: writeFile/removeFile are package-level so tests can override
// them without touching the filesystem.
var (
	writeFile  = func(path string, data []byte) error { return os.WriteFile(path, data, 0o600) }
	removeFile = func(path string) error { return os.Remove(path) }
)

// Provider satisfies provider.Provider for libvirt/KVM hosts.
type Provider struct {
	// virshPath overrides the default `virsh` lookup; tests inject here.
	virshPath string
	// runner is the subprocess executor; tests inject a fake.
	runner func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// New returns the libvirt provider stub.
func New() *Provider {
	return &Provider{
		virshPath: "virsh",
		runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		},
	}
}

func (p *Provider) Kind() provider.Kind { return provider.KindLibvirt }

func (p *Provider) Discover(_ context.Context) (provider.Capabilities, error) {
	return provider.Capabilities{
		Hypervisor: string(provider.KindLibvirt),
		Storage:    []string{"dir"},
		Network:    []string{"bridge"},
		Console:    []string{"vnc", "spice"},
	}, nil
}

// vmIDPattern matches libvirt domain names: alphanumeric, dash, underscore,
// dot. Anything outside this set is rejected as a precaution against shell
// injection even though we don't go through a shell.
var vmIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func (p *Provider) validateVMID(vmID string) error {
	if !vmIDPattern.MatchString(vmID) {
		return fmt.Errorf("libvirt: invalid VM identifier %q", vmID)
	}
	return nil
}

// VMCreate provisions a minimal libvirt domain from a default qcow2 disk
// stored at /var/lib/libvirt/images/<name>.qcow2.
//
// The implementation is deliberately conservative — it generates a small XML
// document with the standard ide/virtio devices, a default 'virbr0' bridge,
// and a single qcow2 disk file, then defines it via `virsh define`. Users
// who need richer setups (cloud-init disk, NUMA, GPU passthrough, multiple
// disks) should keep using the dispatcher's legacy job path which has full
// VMSpec support — this surface exists so the HypervisorRegistry has a
// working entry point for the common case.
//
// The disk image must already exist; the provider does NOT create it from
// scratch. Use `qemu-img create -f qcow2 ...` ahead of calling this method
// (or wire VMSpec.Template to point at a base image).
func (p *Provider) VMCreate(ctx context.Context, spec provider.VMSpec) (provider.JobHandle, error) {
	if err := p.validateVMID(spec.Name); err != nil {
		return provider.JobHandle{}, err
	}
	if spec.CPUCores <= 0 || spec.MemoryMiB <= 0 {
		return provider.JobHandle{}, fmt.Errorf("libvirt: VMCreate requires CPUCores and MemoryMiB")
	}
	diskPath := spec.Template
	if diskPath == "" {
		diskPath = fmt.Sprintf("/var/lib/libvirt/images/%s.qcow2", spec.Name)
	}
	xml := fmt.Sprintf(libvirtDomainTemplate, spec.Name, spec.MemoryMiB*1024, spec.CPUCores, diskPath)

	// virsh define accepts XML on stdin via --file -, but our runner is a
	// flat exec wrapper; write to a temp file instead.
	defPath := fmt.Sprintf("/tmp/pmx-libvirt-%s.xml", spec.Name)
	if err := writeFile(defPath, []byte(xml)); err != nil {
		return provider.JobHandle{}, fmt.Errorf("libvirt: write %s: %w", defPath, err)
	}
	defer removeFile(defPath)

	out, err := p.runner(ctx, p.virshPath, "define", defPath)
	if err != nil {
		return provider.JobHandle{}, fmt.Errorf("virsh define %s: %w (%s)", spec.Name, err, strings.TrimSpace(string(out)))
	}
	return provider.JobHandle{JobID: newJobID(), Provider: provider.KindLibvirt}, nil
}

const libvirtDomainTemplate = `<domain type='kvm'>
  <name>%s</name>
  <memory unit='KiB'>%d</memory>
  <vcpu placement='static'>%d</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-7.2'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features><acpi/><apic/></features>
  <cpu mode='host-passthrough' check='none' migratable='on'/>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='%s'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='bridge'>
      <source bridge='virbr0'/>
      <model type='virtio'/>
    </interface>
    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>
    <video><model type='virtio' heads='1'/></video>
  </devices>
</domain>
`

func (p *Provider) VMStart(ctx context.Context, vmID string) (provider.JobHandle, error) {
	if err := p.validateVMID(vmID); err != nil {
		return provider.JobHandle{}, err
	}
	out, err := p.runner(ctx, p.virshPath, "start", vmID)
	if err != nil {
		return provider.JobHandle{}, fmt.Errorf("virsh start %s: %w (%s)", vmID, err, strings.TrimSpace(string(out)))
	}
	return provider.JobHandle{JobID: newJobID(), Provider: provider.KindLibvirt}, nil
}

func (p *Provider) VMStop(ctx context.Context, vmID string) (provider.JobHandle, error) {
	if err := p.validateVMID(vmID); err != nil {
		return provider.JobHandle{}, err
	}
	out, err := p.runner(ctx, p.virshPath, "destroy", vmID)
	if err != nil {
		return provider.JobHandle{}, fmt.Errorf("virsh destroy %s: %w (%s)", vmID, err, strings.TrimSpace(string(out)))
	}
	return provider.JobHandle{JobID: newJobID(), Provider: provider.KindLibvirt}, nil
}

func (p *Provider) VMDelete(ctx context.Context, vmID string) (provider.JobHandle, error) {
	if err := p.validateVMID(vmID); err != nil {
		return provider.JobHandle{}, err
	}
	// Best-effort stop first; ignore failure (might already be stopped).
	_, _ = p.runner(ctx, p.virshPath, "destroy", vmID)
	out, err := p.runner(ctx, p.virshPath, "undefine", vmID, "--remove-all-storage")
	if err != nil {
		return provider.JobHandle{}, fmt.Errorf("virsh undefine %s: %w (%s)", vmID, err, strings.TrimSpace(string(out)))
	}
	return provider.JobHandle{JobID: newJobID(), Provider: provider.KindLibvirt}, nil
}

func (p *Provider) CTCreate(_ context.Context, _ provider.VMSpec) (provider.JobHandle, error) {
	return provider.JobHandle{}, provider.ErrNotSupported
}

func (p *Provider) StorageList(_ context.Context) ([]provider.StorageSummary, error) {
	return nil, provider.ErrNotSupported
}

func newJobID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return "job_" + hex.EncodeToString(buf)
}
