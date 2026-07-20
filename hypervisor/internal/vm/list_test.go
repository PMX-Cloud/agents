package vm_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
	"github.com/pmx-cloud/agents/hypervisor/internal/vm"
)

const pveshFixture = `[
  {"type":"qemu","vmid":100,"name":"net-openwrt-gateway","node":"dell","status":"running",
   "maxcpu":12,"maxmem":1073741824,"maxdisk":3221225472,"template":0,
   "tags":"community-script","uptime":1913746,"cpu":0.0036,"mem":104398848},
  {"type":"qemu","vmid":101,"name":"media-iptv","node":"dell","status":"stopped",
   "maxcpu":12,"maxmem":65548582912,"maxdisk":236223201280,"template":0},
  {"type":"qemu","vmid":900,"name":"tmpl-debian","node":"dell","status":"stopped",
   "maxcpu":2,"maxmem":2147483648,"maxdisk":10737418240,"template":1},
  {"type":"lxc","vmid":200,"name":"ct-web","node":"dell","status":"running",
   "maxcpu":2,"maxmem":536870912,"maxdisk":8589934592,"template":0,"uptime":42}
]`

type inventoryResponse struct {
	VMs        []vm.InventoryItem `json:"vms"`
	Containers []vm.InventoryItem `json:"containers"`
}

func TestListInventory_VMs(t *testing.T) {
	mock := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte(pveshFixture)}}

	raw, err := vm.ListInventory(context.Background(), mock, "qemu")
	if err != nil {
		t.Fatalf("ListInventory: %v", err)
	}

	var resp inventoryResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.VMs) != 3 {
		t.Fatalf("expected 3 VMs, got %d", len(resp.VMs))
	}

	first := resp.VMs[0]
	if first.VMID != 100 || first.Name != "net-openwrt-gateway" || first.Status != "running" {
		t.Errorf("unexpected first VM: %+v", first)
	}
	if first.Cores != 12 || first.MemoryMB != 1024 || first.DiskGB != 3 {
		t.Errorf("unexpected sizing: cores=%d memMb=%d diskGb=%d", first.Cores, first.MemoryMB, first.DiskGB)
	}
	if first.Tags != "community-script" || first.UptimeSec != 1913746 {
		t.Errorf("unexpected tags/uptime: %+v", first)
	}
	if !resp.VMs[2].Template {
		t.Errorf("vmid 900 should be flagged template")
	}

	call := mock.LastCall()
	if call == nil || call.Binary != "pvesh" {
		t.Fatalf("expected pvesh call, got %+v", call)
	}
}

func TestListInventory_Containers(t *testing.T) {
	mock := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte(pveshFixture)}}

	raw, err := vm.ListInventory(context.Background(), mock, "lxc")
	if err != nil {
		t.Fatalf("ListInventory: %v", err)
	}

	var resp inventoryResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(resp.Containers))
	}
	if resp.Containers[0].VMID != 200 || resp.Containers[0].Status != "running" {
		t.Errorf("unexpected container: %+v", resp.Containers[0])
	}
}

func TestListInventory_RejectsUnknownKind(t *testing.T) {
	mock := &proxmox.MockExec{}
	if _, err := vm.ListInventory(context.Background(), mock, "bogus"); err == nil {
		t.Fatal("expected error for unknown kind")
	}
}

func TestListInventory_BadJSON(t *testing.T) {
	mock := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte("not-json")}}
	if _, err := vm.ListInventory(context.Background(), mock, "qemu"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestListInventory_EmptyHost(t *testing.T) {
	mock := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte("[]")}}
	raw, err := vm.ListInventory(context.Background(), mock, "qemu")
	if err != nil {
		t.Fatalf("ListInventory: %v", err)
	}
	var resp inventoryResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.VMs == nil || len(resp.VMs) != 0 {
		t.Fatalf("expected empty (non-null) vms array, got %+v", resp.VMs)
	}
}
