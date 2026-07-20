package capability_test

import (
	"os"
	"testing"

	"github.com/pmx-cloud/agents/core/internal/capability"
)

// ── ParseLsblkOutput ──────────────────────────────────────────────────────────

func TestParseLsblkOutput_Fixture(t *testing.T) {
	data, err := os.ReadFile("testdata/lsblk.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	disks, err := capability.ParseLsblkOutput(data)
	if err != nil {
		t.Fatalf("ParseLsblkOutput: %v", err)
	}
	if len(disks) != 2 {
		t.Fatalf("expected 2 disks (sda + nvme0n1, loop0 excluded), got %d", len(disks))
	}
	// sda must be rotational
	var found bool
	for _, d := range disks {
		if d.Name == "sda" {
			found = true
			if !d.Rotational {
				t.Error("sda must be rotational")
			}
			if d.SizeBytes != 500107862016 {
				t.Errorf("sda size = %d, want 500107862016", d.SizeBytes)
			}
		}
		if d.Name == "nvme0n1" && d.Rotational {
			t.Error("nvme0n1 must not be rotational")
		}
	}
	if !found {
		t.Error("sda not found in results")
	}
}

func TestParseLsblkOutput_ExcludesLoops(t *testing.T) {
	data := []byte(`{"blockdevices":[{"name":"loop0","size":"1024","rota":"0","type":"loop"}]}`)
	disks, err := capability.ParseLsblkOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(disks) != 0 {
		t.Fatalf("loop device must be excluded, got %d disks", len(disks))
	}
}

func TestParseLsblkOutput_Empty(t *testing.T) {
	disks, err := capability.ParseLsblkOutput([]byte(`{"blockdevices":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(disks) != 0 {
		t.Fatal("empty blockdevices must return 0 disks")
	}
}

func TestParseLsblkOutput_BadJSON(t *testing.T) {
	_, err := capability.ParseLsblkOutput([]byte(`not-json`))
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

// ── ParseIPLink ───────────────────────────────────────────────────────────────

func TestParseIPLink_Fixture(t *testing.T) {
	data, err := os.ReadFile("testdata/ip-link.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	nics := capability.ParseIPLink(data)
	// lo must be excluded; eth0 + eth1 must be present
	if len(nics) != 2 {
		t.Fatalf("expected 2 NICs (lo excluded), got %d", len(nics))
	}
	for _, n := range nics {
		if n.Name == "lo" {
			t.Fatal("loopback must be excluded")
		}
		if n.MAC == "" {
			t.Fatalf("NIC %q has empty MAC", n.Name)
		}
	}
}

func TestParseIPLink_ExcludesLoopback(t *testing.T) {
	data := []byte(`[{"ifname":"lo","address":"00:00:00:00:00:00","link_type":"loopback"}]`)
	nics := capability.ParseIPLink(data)
	if len(nics) != 0 {
		t.Fatal("loopback must be excluded")
	}
}

func TestParseIPLink_ExcludesNoMAC(t *testing.T) {
	data := []byte(`[{"ifname":"tun0","address":"","link_type":"none"}]`)
	nics := capability.ParseIPLink(data)
	if len(nics) != 0 {
		t.Fatal("NIC with empty address must be excluded")
	}
}

func TestParseIPLink_BadJSON(t *testing.T) {
	nics := capability.ParseIPLink([]byte(`not-json`))
	if nics == nil {
		t.Fatal("should return empty slice (not nil) for bad JSON")
	}
	if len(nics) != 0 {
		t.Fatal("bad JSON should return 0 NICs")
	}
}

func TestParseIPLink_Empty(t *testing.T) {
	nics := capability.ParseIPLink([]byte(`[]`))
	if nics == nil {
		t.Fatal("nil slice from empty array")
	}
	if len(nics) != 0 {
		t.Fatal("empty array should return 0 NICs")
	}
}
