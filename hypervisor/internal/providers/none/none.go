// Package none implements provider.Provider for hosts that do not run a
// hypervisor at all (plain Debian/Ubuntu running only the telemetry/storage/
// network/security/backup agents). Discover() reports an empty capability set;
// every VM/CT/storage op returns provider.ErrNotSupported so the backend can
// surface a useful empty-state in the UI.
package none

import (
	"context"

	"github.com/pmx-cloud/agents/hypervisor/internal/provider"
)

// Provider satisfies provider.Provider for a non-hypervisor host.
type Provider struct{}

// New returns a no-op provider.
func New() *Provider { return &Provider{} }

func (p *Provider) Kind() provider.Kind { return provider.KindNone }

func (p *Provider) Discover(_ context.Context) (provider.Capabilities, error) {
	return provider.Capabilities{
		Hypervisor: string(provider.KindNone),
	}, nil
}

func (p *Provider) VMCreate(_ context.Context, _ provider.VMSpec) (provider.JobHandle, error) {
	return provider.JobHandle{}, provider.ErrNotSupported
}

func (p *Provider) VMStart(_ context.Context, _ string) (provider.JobHandle, error) {
	return provider.JobHandle{}, provider.ErrNotSupported
}

func (p *Provider) VMStop(_ context.Context, _ string) (provider.JobHandle, error) {
	return provider.JobHandle{}, provider.ErrNotSupported
}

func (p *Provider) VMDelete(_ context.Context, _ string) (provider.JobHandle, error) {
	return provider.JobHandle{}, provider.ErrNotSupported
}

func (p *Provider) CTCreate(_ context.Context, _ provider.VMSpec) (provider.JobHandle, error) {
	return provider.JobHandle{}, provider.ErrNotSupported
}

func (p *Provider) StorageList(_ context.Context) ([]provider.StorageSummary, error) {
	return nil, provider.ErrNotSupported
}
