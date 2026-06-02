package iommu

import "testing"

func TestMergeKernelCmdlineAddsTokens(t *testing.T) {
	t.Parallel()

	line := `GRUB_CMDLINE_LINUX_DEFAULT="quiet"`
	updated, changed, err := mergeKernelCmdline(line, []string{"intel_iommu=on", "iommu=pt"})
	if err != nil {
		t.Fatalf("mergeKernelCmdline() error = %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	if updated == line {
		t.Fatal("expected updated line")
	}
}

func TestMergeKernelCmdlineNoop(t *testing.T) {
	t.Parallel()

	line := `GRUB_CMDLINE_LINUX_DEFAULT="quiet intel_iommu=on iommu=pt"`
	updated, changed, err := mergeKernelCmdline(line, []string{"intel_iommu=on", "iommu=pt"})
	if err != nil {
		t.Fatalf("mergeKernelCmdline() error = %v", err)
	}
	if changed || updated != line {
		t.Fatalf("expected noop, got changed=%v updated=%q", changed, updated)
	}
}
