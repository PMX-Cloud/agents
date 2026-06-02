package libvirt

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/provider"
)

type call struct {
	name string
	args []string
}

func newFakeProvider(t *testing.T, runner func(ctx context.Context, name string, args ...string) ([]byte, error)) *Provider {
	t.Helper()
	p := New()
	p.runner = runner
	return p
}

func TestVMStart_InvokesVirshStart(t *testing.T) {
	var got []call
	p := newFakeProvider(t, func(_ context.Context, name string, args ...string) ([]byte, error) {
		got = append(got, call{name, args})
		return []byte(""), nil
	})
	handle, err := p.VMStart(context.Background(), "node1-vm-7")
	if err != nil {
		t.Fatalf("VMStart: %v", err)
	}
	if len(got) != 1 || got[0].name != "virsh" || got[0].args[0] != "start" || got[0].args[1] != "node1-vm-7" {
		t.Errorf("unexpected calls: %#v", got)
	}
	if handle.Provider != provider.KindLibvirt {
		t.Errorf("want libvirt provider in handle, got %s", handle.Provider)
	}
}

func TestVMStart_RejectsInvalidVMID(t *testing.T) {
	p := newFakeProvider(t, func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		t.Errorf("runner should not be called")
		return nil, nil
	})
	_, err := p.VMStart(context.Background(), "node1; rm -rf /")
	if err == nil {
		t.Fatal("expected error for invalid VMID")
	}
	if !strings.Contains(err.Error(), "invalid VM identifier") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVMStop_PropagatesVirshFailure(t *testing.T) {
	p := newFakeProvider(t, func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("domain not running"), errors.New("exit status 1")
	})
	_, err := p.VMStop(context.Background(), "vm1")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "domain not running") {
		t.Errorf("missing stderr in error: %v", err)
	}
}

func TestVMDelete_DestroysThenUndefines(t *testing.T) {
	var got []call
	p := newFakeProvider(t, func(_ context.Context, name string, args ...string) ([]byte, error) {
		got = append(got, call{name, args})
		return []byte(""), nil
	})
	if _, err := p.VMDelete(context.Background(), "vm1"); err != nil {
		t.Fatalf("VMDelete: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 calls, got %d: %#v", len(got), got)
	}
	if got[0].args[0] != "destroy" || got[1].args[0] != "undefine" {
		t.Errorf("unexpected call sequence: %#v", got)
	}
}

func TestVMCreate_RejectsBadInput(t *testing.T) {
	p := newFakeProvider(t, func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		t.Errorf("runner should not be called")
		return nil, nil
	})
	if _, err := p.VMCreate(context.Background(), provider.VMSpec{Name: "good name"}); err == nil {
		t.Fatal("expected error for spaces in name")
	}
	if _, err := p.VMCreate(context.Background(), provider.VMSpec{Name: "good-name", CPUCores: 0, MemoryMiB: 2048}); err == nil {
		t.Fatal("expected error for CPU=0")
	}
}

func TestVMCreate_GeneratesAndDefinesXML(t *testing.T) {
	var got []call
	var writtenXML string
	origWrite := writeFile
	origRemove := removeFile
	writeFile = func(_ string, data []byte) error {
		writtenXML = string(data)
		return nil
	}
	removeFile = func(_ string) error { return nil }
	t.Cleanup(func() {
		writeFile = origWrite
		removeFile = origRemove
	})

	p := newFakeProvider(t, func(_ context.Context, name string, args ...string) ([]byte, error) {
		got = append(got, call{name, args})
		return []byte("Domain 'vm1' defined"), nil
	})
	if _, err := p.VMCreate(context.Background(), provider.VMSpec{
		Name:      "vm1",
		CPUCores:  2,
		MemoryMiB: 2048,
		Template:  "/var/lib/libvirt/images/base.qcow2",
	}); err != nil {
		t.Fatalf("VMCreate: %v", err)
	}
	if !strings.Contains(writtenXML, "<name>vm1</name>") {
		t.Errorf("XML missing name: %s", writtenXML)
	}
	if !strings.Contains(writtenXML, "<memory unit='KiB'>2097152</memory>") {
		t.Errorf("XML missing memory: %s", writtenXML)
	}
	if !strings.Contains(writtenXML, "/var/lib/libvirt/images/base.qcow2") {
		t.Errorf("XML missing disk path: %s", writtenXML)
	}
	if len(got) != 1 || got[0].args[0] != "define" {
		t.Errorf("expected virsh define call, got: %#v", got)
	}
}

func TestDiscover_ReportsLibvirtCaps(t *testing.T) {
	p := New()
	caps, err := p.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if caps.Hypervisor != string(provider.KindLibvirt) {
		t.Errorf("want libvirt, got %s", caps.Hypervisor)
	}
	if len(caps.Console) == 0 {
		t.Errorf("expected console capabilities for libvirt")
	}
}
