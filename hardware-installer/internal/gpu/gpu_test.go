package gpu

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAttachRejectsInvalidPCIID(t *testing.T) {
	t.Parallel()

	_, err := Attach(context.Background(), Params{QM: "/usr/sbin/qm"}, AttachRequest{
		VMID:  101,
		PCIID: "not-a-pci",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid pci_id") {
		t.Fatalf("expected invalid pci error, got %v", err)
	}
}

func TestAttachLXCIdempotent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	config := filepath.Join(dir, "101.conf")
	if err := os.WriteFile(config, []byte("arch: amd64\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	res1, err := AttachLXC(context.Background(), Params{LXCConfigDir: dir}, AttachLXCRequest{VMID: 101, Type: "nvidia"}, nil)
	if err != nil {
		t.Fatalf("AttachLXC first call error = %v", err)
	}
	if !res1.Changed {
		t.Fatal("expected first call to change file")
	}

	res2, err := AttachLXC(context.Background(), Params{LXCConfigDir: dir}, AttachLXCRequest{VMID: 101, Type: "nvidia"}, nil)
	if err != nil {
		t.Fatalf("AttachLXC second call error = %v", err)
	}
	if res2.Changed {
		t.Fatal("expected second call to be idempotent")
	}
}

func TestLxcLinesForType(t *testing.T) {
	t.Parallel()

	if got := lxcLinesForType("intel"); len(got) != 2 {
		t.Fatalf("intel lines len = %d, want 2", len(got))
	}
	if got := lxcLinesForType("nvidia"); len(got) < 3 {
		t.Fatalf("nvidia lines len = %d, want >=3", len(got))
	}
}
