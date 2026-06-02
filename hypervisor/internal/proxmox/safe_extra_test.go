package proxmox_test

import (
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

// ── IsSafeVolume ──────────────────────────────────────────────────────────────

func TestIsSafeVolume_Valid(t *testing.T) {
	cases := []string{
		"local-lvm:vm-100-disk-0",
		"local:vztmpl/debian-12.tar.xz",
		"ceph:vm-200-disk-1",
		"nfs-data:backup/file.vma.zst",
	}
	for _, c := range cases {
		if !proxmox.IsSafeVolume(c) {
			t.Errorf("expected %q to be a safe volume", c)
		}
	}
}

func TestIsSafeVolume_Unsafe(t *testing.T) {
	cases := []string{
		"",
		"vol; rm -rf /",
		"vol\nrm",
		"vol$(cmd)",
	}
	for _, c := range cases {
		if proxmox.IsSafeVolume(c) {
			t.Errorf("expected %q to be rejected as unsafe", c)
		}
	}
}

func TestRequiredSafeVolume_Valid(t *testing.T) {
	val, err := proxmox.RequiredSafeVolume(map[string]any{"vol": "local-lvm:disk-0"}, "vol")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "local-lvm:disk-0" {
		t.Fatalf("wrong value: %q", val)
	}
}

func TestRequiredSafeVolume_Missing(t *testing.T) {
	_, err := proxmox.RequiredSafeVolume(map[string]any{}, "vol")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestRequiredSafeVolume_Unsafe(t *testing.T) {
	_, err := proxmox.RequiredSafeVolume(map[string]any{"vol": "bad; rm"}, "vol")
	if err == nil {
		t.Fatal("expected error for unsafe value")
	}
}

// ── IsJobID ───────────────────────────────────────────────────────────────────

func TestIsJobID_Valid(t *testing.T) {
	for _, c := range []string{"job-001", "abc123", "test_job", "UUID-v7-abc123"} {
		if !proxmox.IsJobID(c) {
			t.Errorf("expected %q to be a valid job ID", c)
		}
	}
}

func TestIsJobID_Unsafe(t *testing.T) {
	for _, c := range []string{"", "../../etc/shadow", "job.with.dots", "job/path"} {
		if proxmox.IsJobID(c) {
			t.Errorf("expected %q to be rejected as job ID", c)
		}
	}
}

// ── RequiredSafeTokenAny ──────────────────────────────────────────────────────

func TestRequiredSafeTokenAny_FirstKeyFound(t *testing.T) {
	val, err := proxmox.RequiredSafeTokenAny(map[string]any{"a": "first"}, "a", "b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "first" {
		t.Fatalf("wrong value: %q", val)
	}
}

func TestRequiredSafeTokenAny_SecondKeyFallback(t *testing.T) {
	val, err := proxmox.RequiredSafeTokenAny(map[string]any{"b": "second"}, "a", "b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "second" {
		t.Fatalf("wrong value: %q", val)
	}
}

func TestRequiredSafeTokenAny_NoneFound(t *testing.T) {
	_, err := proxmox.RequiredSafeTokenAny(map[string]any{}, "a", "b")
	if err == nil {
		t.Fatal("expected error when neither key found")
	}
}

// ── RequiredAbsolutePath ──────────────────────────────────────────────────────

func TestRequiredAbsolutePath_Valid(t *testing.T) {
	val, err := proxmox.RequiredAbsolutePath(map[string]any{"path": "/var/lib/foo"}, "path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "/var/lib/foo" {
		t.Fatalf("wrong value: %q", val)
	}
}

func TestRequiredAbsolutePath_Traversal(t *testing.T) {
	_, err := proxmox.RequiredAbsolutePath(map[string]any{"path": "/var/../etc/shadow"}, "path")
	if err == nil {
		t.Fatal("expected error for traversal path")
	}
}

func TestRequiredAbsolutePath_Relative(t *testing.T) {
	_, err := proxmox.RequiredAbsolutePath(map[string]any{"path": "relative/path"}, "path")
	if err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestRequiredAbsolutePath_Missing(t *testing.T) {
	_, err := proxmox.RequiredAbsolutePath(map[string]any{}, "path")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

// ── BoolParam ─────────────────────────────────────────────────────────────────

func TestBoolParam_True(t *testing.T) {
	for _, v := range []any{true, "true", "1", "yes"} {
		if !proxmox.BoolParam(map[string]any{"k": v}, "k") {
			t.Errorf("expected true for %v", v)
		}
	}
}

func TestBoolParam_False(t *testing.T) {
	if proxmox.BoolParam(map[string]any{"k": false}, "k") {
		t.Fatal("expected false for false")
	}
	if proxmox.BoolParam(map[string]any{}, "missing") {
		t.Fatal("expected false for missing key")
	}
}

// ── IntParam ──────────────────────────────────────────────────────────────────

func TestIntParam_Float64(t *testing.T) {
	val := proxmox.IntParam(map[string]any{"n": float64(42)}, "n", 0)
	if val != 42 {
		t.Fatalf("expected 42, got %d", val)
	}
}

func TestIntParam_Int(t *testing.T) {
	val := proxmox.IntParam(map[string]any{"n": 7}, "n", 0)
	if val != 7 {
		t.Fatalf("expected 7, got %d", val)
	}
}

func TestIntParam_Missing(t *testing.T) {
	val := proxmox.IntParam(map[string]any{}, "n", 99)
	if val != 99 {
		t.Fatalf("expected fallback 99, got %d", val)
	}
}

// ── OneOf ─────────────────────────────────────────────────────────────────────

func TestOneOf_Match(t *testing.T) {
	if !proxmox.OneOf("b", "a", "b", "c") {
		t.Fatal("expected true for 'b' in ['a','b','c']")
	}
}

func TestOneOf_NoMatch(t *testing.T) {
	if proxmox.OneOf("z", "a", "b", "c") {
		t.Fatal("expected false for 'z' not in ['a','b','c']")
	}
}

// ── ExecResult helpers ────────────────────────────────────────────────────────

func TestExecResult_StdoutString(t *testing.T) {
	r := &proxmox.ExecResult{Stdout: []byte("  hello  ")}
	if r.StdoutString() != "hello" {
		t.Fatalf("expected 'hello', got %q", r.StdoutString())
	}
}

func TestExecResult_StderrFirst512_Short(t *testing.T) {
	r := &proxmox.ExecResult{Stderr: []byte("short error")}
	if r.StderrFirst512() != "short error" {
		t.Fatalf("expected 'short error', got %q", r.StderrFirst512())
	}
}

func TestExecResult_StderrFirst512_Long(t *testing.T) {
	long := make([]byte, 1024)
	for i := range long {
		long[i] = 'x'
	}
	r := &proxmox.ExecResult{Stderr: long}
	got := r.StderrFirst512()
	if len(got) != 512 {
		t.Fatalf("expected 512 bytes, got %d", len(got))
	}
}

// ── MockExec — additional paths ───────────────────────────────────────────────

func TestMockExec_Pct(t *testing.T) {
	m := &proxmox.MockExec{}
	result, err := m.Pct(nil, "status", "100")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestMockExec_Pvesm(t *testing.T) {
	m := &proxmox.MockExec{}
	result, _ := m.Pvesm(nil, "list")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestMockExec_Pvecm(t *testing.T) {
	m := &proxmox.MockExec{}
	result, _ := m.Pvecm(nil, "status")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}
