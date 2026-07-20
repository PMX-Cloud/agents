package capability_test

import (
	"os"
	"testing"

	"github.com/pmx-cloud/agents/core/internal/capability"
)

// ── ParseOSRelease ────────────────────────────────────────────────────────────

func TestParseOSRelease_Debian12(t *testing.T) {
	data, err := os.ReadFile("testdata/os-release")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	info := capability.ParseOSRelease(data)
	if info.ID != "debian" {
		t.Errorf("ID = %q, want %q", info.ID, "debian")
	}
	if info.Version != "12" {
		t.Errorf("Version = %q, want %q", info.Version, "12")
	}
}

func TestParseOSRelease_QuotedValues(t *testing.T) {
	data := []byte(`ID="ubuntu"` + "\n" + `VERSION_ID="22.04"` + "\n")
	info := capability.ParseOSRelease(data)
	if info.ID != "ubuntu" {
		t.Errorf("ID = %q, want %q", info.ID, "ubuntu")
	}
	if info.Version != "22.04" {
		t.Errorf("Version = %q, want %q", info.Version, "22.04")
	}
}

func TestParseOSRelease_Empty(t *testing.T) {
	info := capability.ParseOSRelease([]byte{})
	if info.ID != "" || info.Version != "" {
		t.Errorf("empty input should give empty result, got %+v", info)
	}
}

func TestParseOSRelease_MalformedLines(t *testing.T) {
	data := []byte("not-a-kv-line\nID=debian\n=empty-key\n")
	info := capability.ParseOSRelease(data)
	if info.ID != "debian" {
		t.Errorf("ID = %q, want %q", info.ID, "debian")
	}
}

// ── ParseCPUInfo ──────────────────────────────────────────────────────────────

func TestParseCPUInfo_Fixture(t *testing.T) {
	data, err := os.ReadFile("testdata/cpuinfo")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	info := capability.ParseCPUInfo(data)
	if info.Vendor != "GenuineIntel" {
		t.Errorf("Vendor = %q, want GenuineIntel", info.Vendor)
	}
	if info.Model == "" {
		t.Error("Model must not be empty")
	}
	if info.Cores != 4 {
		t.Errorf("Cores = %d, want 4 (distinct core ids 0,1,2,3)", info.Cores)
	}
	if len(info.Flags) == 0 {
		t.Error("Flags must not be empty")
	}
}

func TestParseCPUInfo_Empty(t *testing.T) {
	info := capability.ParseCPUInfo([]byte{})
	// Cores defaults to 1 when none found.
	if info.Cores != 1 {
		t.Errorf("empty cpuinfo should default to 1 core, got %d", info.Cores)
	}
}

func TestParseCPUInfo_NoCoreID(t *testing.T) {
	// If no core id lines, cores defaults to 1.
	data := []byte("vendor_id\t: AuthenticAMD\nmodel name\t: AMD EPYC\n")
	info := capability.ParseCPUInfo(data)
	if info.Cores != 1 {
		t.Errorf("expected 1 core, got %d", info.Cores)
	}
	if info.Vendor != "AuthenticAMD" {
		t.Errorf("Vendor = %q, want AuthenticAMD", info.Vendor)
	}
}

// ── ParseMemTotal ─────────────────────────────────────────────────────────────

func TestParseMemTotal_Fixture(t *testing.T) {
	data, err := os.ReadFile("testdata/meminfo")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	got := capability.ParseMemTotal(data)
	want := int64(16384000 * 1024)
	if got != want {
		t.Errorf("ParseMemTotal = %d, want %d", got, want)
	}
}

func TestParseMemTotal_Empty(t *testing.T) {
	if capability.ParseMemTotal([]byte{}) != 0 {
		t.Error("empty input should return 0")
	}
}

func TestParseMemTotal_NoMemTotal(t *testing.T) {
	data := []byte("MemFree: 1000 kB\nSwapTotal: 2000 kB\n")
	if capability.ParseMemTotal(data) != 0 {
		t.Error("missing MemTotal line should return 0")
	}
}

func TestParseMemTotal_MalformedLine(t *testing.T) {
	data := []byte("MemTotal: abc kB\n")
	// Malformed value should return 0, not panic.
	if capability.ParseMemTotal(data) != 0 {
		t.Error("malformed MemTotal should return 0")
	}
}
