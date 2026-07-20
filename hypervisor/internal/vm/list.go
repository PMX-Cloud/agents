/*
list.go — vm.list / ct.list inventory commands.

Enumerates existing guests on the host via a single
`pvesh get /cluster/resources --type vm` call (returns both QEMU VMs and LXC
containers with status/maxcpu/maxmem/maxdisk/template/tags) and maps them to a
compact payload. The backend's inventory sync upserts the result into the
platform DB so pre-existing guests become visible without being re-created.

Payload is intentionally compact: the agent→backend frame cap is 64 KiB.
*/
package vm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

// clusterResource mirrors the fields we consume from pvesh /cluster/resources.
type clusterResource struct {
	Type     string  `json:"type"` // "qemu" | "lxc"
	VMID     int     `json:"vmid"`
	Name     string  `json:"name"`
	Node     string  `json:"node"`
	Status   string  `json:"status"`
	MaxCPU   float64 `json:"maxcpu"`
	MaxMem   int64   `json:"maxmem"`
	MaxDisk  int64   `json:"maxdisk"`
	Template int     `json:"template"`
	Tags     string  `json:"tags"`
	Uptime   int64   `json:"uptime"`
	CPU      float64 `json:"cpu"`
	Mem      int64   `json:"mem"`
}

// InventoryItem is one guest in the vm.list / ct.list response.
type InventoryItem struct {
	VMID      int     `json:"vmid"`
	Name      string  `json:"name"`
	Node      string  `json:"node"`
	Status    string  `json:"status"`
	Cores     int     `json:"cores"`
	MemoryMB  int64   `json:"memoryMb"`
	DiskGB    int64   `json:"diskGb"`
	Template  bool    `json:"template"`
	Tags      string  `json:"tags,omitempty"`
	UptimeSec int64   `json:"uptimeSec,omitempty"`
	CPUUsage  float64 `json:"cpuUsage,omitempty"`
	MemBytes  int64   `json:"memBytes,omitempty"`
}

// ListInventory returns the JSON body for vm.list (kind "qemu") or ct.list
// (kind "lxc"). The response key is "vms" or "containers" respectively.
func ListInventory(ctx context.Context, px proxmox.ExecIface, kind string) ([]byte, error) {
	if kind != "qemu" && kind != "lxc" {
		return nil, fmt.Errorf("inventory: unsupported kind %q", kind)
	}

	result, err := px.Pvesh(ctx, "get", "/cluster/resources", "--type", "vm", "--output-format", "json")
	if err != nil {
		return nil, fmt.Errorf("inventory: pvesh cluster/resources: %w", err)
	}

	var resources []clusterResource
	if err := json.Unmarshal(result.Stdout, &resources); err != nil {
		return nil, fmt.Errorf("inventory: parse pvesh output: %w", err)
	}

	items := make([]InventoryItem, 0, len(resources))
	for _, r := range resources {
		if r.Type != kind || r.VMID <= 0 {
			continue
		}
		items = append(items, InventoryItem{
			VMID:      r.VMID,
			Name:      r.Name,
			Node:      r.Node,
			Status:    r.Status,
			Cores:     int(r.MaxCPU),
			MemoryMB:  r.MaxMem / (1024 * 1024),
			DiskGB:    (r.MaxDisk + (1 << 30) - 1) / (1 << 30),
			Template:  r.Template == 1,
			Tags:      r.Tags,
			UptimeSec: r.Uptime,
			CPUUsage:  r.CPU,
			MemBytes:  r.Mem,
		})
	}

	key := "vms"
	if kind == "lxc" {
		key = "containers"
	}
	return json.Marshal(map[string][]InventoryItem{key: items})
}
