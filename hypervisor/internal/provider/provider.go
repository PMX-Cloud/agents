// Package provider defines the hypervisor-agnostic interface that
// pmx-hypervisor uses to dispatch VM/CT/storage/network operations to a
// specific backend. Concrete providers live under internal/providers/<kind>/.
//
// Provider selection happens at agent startup based on the --provider flag
// (auto | proxmox | libvirt | none). The "auto" mode probes the host for
// pveversion (-> proxmox), then virsh (-> libvirt), and falls back to "none"
// for plain Debian/Ubuntu hosts that run only telemetry/storage/network/
// security/backup agents.
package provider

import (
	"context"
	"errors"
)

// Kind identifies the hypervisor backend a Provider speaks to.
type Kind string

const (
	KindProxmox Kind = "proxmox"
	KindLibvirt Kind = "libvirt"
	KindNone    Kind = "none"
)

// ErrNotSupported is returned by providers for operations they do not implement
// (for example, VM creation on a "none" provider). The backend's
// HypervisorRegistry surfaces this as HypervisorNotSupportedError to the UI.
var ErrNotSupported = errors.New("hypervisor operation not supported by this provider")

// Capabilities is the structured discovery payload a Provider reports back to
// the backend at registration time. Persisted onto nodes.capabilities so the
// UI knows which tabs to light up for the node.
//
// Schema mirrors the JSON shape the agent core sends in agent.register:
//
//	{
//	  "hypervisor.provider": "proxmox",
//	  "storage":             ["zfs", "lvm"],
//	  "network":             ["bridge", "vlan"],
//	  "backup":              ["vzdump", "s3"],
//	  "console":             ["vnc"]
//	}
type Capabilities struct {
	Hypervisor string   `json:"hypervisor.provider"`
	Storage    []string `json:"storage,omitempty"`
	Network    []string `json:"network,omitempty"`
	Backup     []string `json:"backup,omitempty"`
	Console    []string `json:"console,omitempty"`
}

// VMSpec is the minimal cross-provider VM specification. Provider-specific
// extras (cloud-init disk, NUMA pinning, …) belong on the request envelope,
// not in this surface.
type VMSpec struct {
	Name      string
	CPUCores  int
	MemoryMiB int
	DiskGiB   int
	Template  string
}

// JobHandle identifies an in-flight asynchronous operation against the host.
// The backend tracks completion via the job event stream, not by polling here.
type JobHandle struct {
	JobID    string
	Provider Kind
}

// Provider is the hypervisor abstraction. Implementations live under
// internal/providers/<kind>/ and are wired up by main.go based on the
// --provider flag.
type Provider interface {
	// Kind returns the backend this provider speaks to.
	Kind() Kind

	// Discover returns the structured capability set the agent should report
	// to the backend at registration time. Implementations should be fast
	// (~hundreds of milliseconds) and safe to call from a `--preflight` run.
	Discover(ctx context.Context) (Capabilities, error)

	// VMCreate provisions a VM matching spec on the host. Returns a JobHandle
	// once the job has been accepted; the caller polls the job event stream
	// for completion.
	VMCreate(ctx context.Context, spec VMSpec) (JobHandle, error)
	// VMStart powers on a VM by its provider-native identifier.
	VMStart(ctx context.Context, vmID string) (JobHandle, error)
	// VMStop powers off a VM by its provider-native identifier.
	VMStop(ctx context.Context, vmID string) (JobHandle, error)
	// VMDelete destroys a VM by its provider-native identifier.
	VMDelete(ctx context.Context, vmID string) (JobHandle, error)

	// CTCreate provisions a container matching spec on the host.
	CTCreate(ctx context.Context, spec VMSpec) (JobHandle, error)

	// StorageList enumerates storage pools/backings visible on the host.
	StorageList(ctx context.Context) ([]StorageSummary, error)
}

// StorageSummary is the cross-provider storage view returned by StorageList.
type StorageSummary struct {
	ID       string
	Name     string
	Type     string
	TotalGiB int64
	UsedGiB  int64
}
