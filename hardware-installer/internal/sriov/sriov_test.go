package sriov

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMergeKernelCmdline(t *testing.T) {
	t.Parallel()

	line := `GRUB_CMDLINE_LINUX_DEFAULT="quiet"`
	updated, changed, err := mergeKernelCmdline(line, []string{"intel_iommu=on", "iommu=pt"})
	if err != nil {
		t.Fatalf("mergeKernelCmdline() error = %v", err)
	}
	if !changed || updated == line {
		t.Fatalf("expected line to change, got changed=%v line=%q", changed, updated)
	}
}

func TestEnablePFIdempotent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	grubPath := filepath.Join(dir, "grub")
	modprobePath := filepath.Join(dir, "sriov.conf")
	cpuInfoPath := filepath.Join(dir, "cpuinfo")
	if err := os.WriteFile(grubPath, []byte("GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n"), 0o644); err != nil {
		t.Fatalf("write grub: %v", err)
	}
	if err := os.WriteFile(cpuInfoPath, []byte("vendor_id\t: GenuineIntel\n"), 0o644); err != nil {
		t.Fatalf("write cpuinfo: %v", err)
	}

	res1, err := EnablePF(context.Background(), Params{
		CPUInfoPath:        cpuInfoPath,
		GrubPath:           grubPath,
		ModprobeConfigPath: modprobePath,
		UpdateGrubPath:     "/usr/bin/true",
	}, EnableRequest{Driver: "ixgbe", MaxVFs: 8}, nil)
	if err != nil {
		t.Fatalf("EnablePF first call error = %v", err)
	}
	if !res1.Changed {
		t.Fatal("expected first call changed=true")
	}

	res2, err := EnablePF(context.Background(), Params{
		CPUInfoPath:        cpuInfoPath,
		GrubPath:           grubPath,
		ModprobeConfigPath: modprobePath,
		UpdateGrubPath:     "/usr/bin/true",
	}, EnableRequest{Driver: "ixgbe", MaxVFs: 8}, nil)
	if err != nil {
		t.Fatalf("EnablePF second call error = %v", err)
	}
	if res2.Changed {
		t.Fatal("expected second call changed=false")
	}
}

func TestDetectIOMMUTokensAMD(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cpuInfoPath := filepath.Join(dir, "cpuinfo")
	if err := os.WriteFile(cpuInfoPath, []byte("vendor_id\t: AuthenticAMD\n"), 0o644); err != nil {
		t.Fatalf("write cpuinfo: %v", err)
	}

	tokens, err := detectIOMMUTokens(cpuInfoPath)
	if err != nil {
		t.Fatalf("detectIOMMUTokens() error = %v", err)
	}
	if len(tokens) != 2 || tokens[0] != "amd_iommu=on" || tokens[1] != "iommu=pt" {
		t.Fatalf("detectIOMMUTokens() = %v, want amd tokens", tokens)
	}
}
