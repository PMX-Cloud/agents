// Package proxmox implements provider.Provider for Proxmox VE hosts by
// delegating to the existing internal/proxmox.ExecIface (pvesh / qm / pct /
// pvesm / pvecm wrappers). This is a thin adapter layer: the actual subprocess
// audit + injection-resistant exec logic still lives in internal/proxmox.
package proxmox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/pmx-cloud/agents/hypervisor/internal/ct"
	"github.com/pmx-cloud/agents/hypervisor/internal/provider"
	pveexec "github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
	"github.com/pmx-cloud/agents/hypervisor/internal/vm"
)

// Provider satisfies provider.Provider for Proxmox VE hosts.
type Provider struct {
	exec pveexec.ExecIface
}

// New returns a Proxmox provider backed by the given ExecIface.
func New(exec pveexec.ExecIface) *Provider {
	return &Provider{exec: exec}
}

func (p *Provider) Kind() provider.Kind { return provider.KindProxmox }

func (p *Provider) Discover(_ context.Context) (provider.Capabilities, error) {
	// Proxmox is detected at startup (presence of pveversion); the agent's
	// core layer fills in the storage/network/backup/console specifics from
	// its own probes. The provider just declares the headline kind so the
	// backend knows the VM/CT/cluster surface is live.
	return provider.Capabilities{
		Hypervisor: string(provider.KindProxmox),
		Storage:    []string{"zfs", "lvm", "dir"},
		Network:    []string{"bridge", "vlan", "ovs"},
		Backup:     []string{"vzdump", "s3"},
		Console:    []string{"vnc", "spice"},
	}, nil
}

// VMCreate provisions a Proxmox VM via the existing internal/vm.Create
// path. The legacy job-dispatch router still owns the full envelope-level
// flow (audit, streaming step events); this provider call exists so the
// backend's HypervisorRegistry can ask the agent for a VM without going
// through that router — e.g. for in-process tests.
func (p *Provider) VMCreate(ctx context.Context, spec provider.VMSpec) (provider.JobHandle, error) {
	if p.exec == nil {
		return provider.JobHandle{}, provider.ErrNotSupported
	}
	params := map[string]any{
		"name":    spec.Name,
		"cores":   spec.CPUCores,
		"memory":  spec.MemoryMiB,
		"storage": "local-lvm",
		"ostype":  "l26",
	}
	if spec.Template != "" {
		params["template"] = spec.Template
	}
	if err := vm.Create(ctx, p.exec, params, nil); err != nil {
		return provider.JobHandle{}, err
	}
	return provider.JobHandle{JobID: newJobID(), Provider: provider.KindProxmox}, nil
}

func (p *Provider) VMStart(ctx context.Context, vmID string) (provider.JobHandle, error) {
	if p.exec == nil {
		return provider.JobHandle{}, provider.ErrNotSupported
	}
	if err := vm.Start(ctx, p.exec, map[string]any{"vmid": vmID}); err != nil {
		return provider.JobHandle{}, err
	}
	return provider.JobHandle{JobID: newJobID(), Provider: provider.KindProxmox}, nil
}

func (p *Provider) VMStop(ctx context.Context, vmID string) (provider.JobHandle, error) {
	if p.exec == nil {
		return provider.JobHandle{}, provider.ErrNotSupported
	}
	if err := vm.Stop(ctx, p.exec, map[string]any{"vmid": vmID}); err != nil {
		return provider.JobHandle{}, err
	}
	return provider.JobHandle{JobID: newJobID(), Provider: provider.KindProxmox}, nil
}

func (p *Provider) VMDelete(ctx context.Context, vmID string) (provider.JobHandle, error) {
	if p.exec == nil {
		return provider.JobHandle{}, provider.ErrNotSupported
	}
	if err := vm.Delete(ctx, p.exec, map[string]any{"vmid": vmID, "purge": true}); err != nil {
		return provider.JobHandle{}, err
	}
	return provider.JobHandle{JobID: newJobID(), Provider: provider.KindProxmox}, nil
}

func (p *Provider) CTCreate(ctx context.Context, spec provider.VMSpec) (provider.JobHandle, error) {
	if p.exec == nil {
		return provider.JobHandle{}, provider.ErrNotSupported
	}
	params := map[string]any{
		"hostname": spec.Name,
		"cores":    spec.CPUCores,
		"memory":   spec.MemoryMiB,
		"storage":  "local-lvm",
	}
	if spec.Template != "" {
		params["template"] = spec.Template
	}
	if err := ct.Create(ctx, p.exec, params, nil); err != nil {
		return provider.JobHandle{}, err
	}
	return provider.JobHandle{JobID: newJobID(), Provider: provider.KindProxmox}, nil
}

func (p *Provider) StorageList(ctx context.Context) ([]provider.StorageSummary, error) {
	if p.exec == nil {
		return nil, provider.ErrNotSupported
	}
	// Use the existing pvesm wrapper to list storage. The output parser lives
	// in internal/proxmox; storage listing was already in the legacy job
	// router under storage.* commands.
	result, err := p.exec.Pvesm(ctx, "status", "--output-format", "json")
	if err != nil {
		return nil, fmt.Errorf("pvesm status: %w", err)
	}
	_ = result
	// Parsing pvesm JSON is non-trivial and varies by Proxmox version; for now
	// return an empty list so the surface compiles and runs. Real parsing is
	// owned by the agent's storage handlers — backend storage UI still gets
	// its data from the storage agent (pmx-storage), not from this method.
	return nil, nil
}

func newJobID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return "job_" + hex.EncodeToString(buf)
}
