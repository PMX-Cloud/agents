// Package sriov configures persistent PF SR-IOV enablement on boot.
package sriov

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pmx-cloud/agents/hardware-installer/internal/runner"
)

type Params struct {
	CPUInfoPath        string
	GrubPath           string
	ModprobeConfigPath string
	UpdateGrubPath     string
	OutputLimit        int64
}

type EnableRequest struct {
	Driver string `json:"driver"`
	MaxVFs int    `json:"max_vfs"`
	Count  int    `json:"count"`
}

type Result struct {
	RebootRequired bool `json:"reboot_required"`
	Changed        bool `json:"changed"`
	GrubChanged    bool `json:"grub_changed"`
	DriverChanged  bool `json:"driver_changed"`
}

var safeDriver = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func EnablePF(ctx context.Context, p Params, req EnableRequest, stepFn func(string)) (*Result, error) {
	driver := strings.TrimSpace(req.Driver)
	if !safeDriver.MatchString(driver) {
		return nil, fmt.Errorf("sriov: invalid driver %q", req.Driver)
	}
	maxVFs := req.MaxVFs
	if maxVFs <= 0 {
		maxVFs = req.Count
	}
	if maxVFs <= 0 || maxVFs > 256 {
		return nil, fmt.Errorf("sriov: max_vfs must be between 1 and 256")
	}
	requiredTokens, err := detectIOMMUTokens(p.CPUInfoPath)
	if err != nil {
		return nil, err
	}

	grubChanged, err := ensureGrubTokens(p.GrubPath, requiredTokens)
	if err != nil {
		return nil, err
	}
	if grubChanged {
		if _, err := runner.Run(ctx, runner.Command{
			Path:        p.UpdateGrubPath,
			OutputLimit: p.OutputLimit,
		}, stepFn); err != nil {
			return nil, fmt.Errorf("sriov: update-grub failed: %w", err)
		}
	}

	content := []byte(fmt.Sprintf("options %s max_vfs=%d\n", driver, maxVFs))
	driverChanged, err := writeIfChanged(p.ModprobeConfigPath, content)
	if err != nil {
		return nil, err
	}
	return &Result{
		RebootRequired: true,
		Changed:        grubChanged || driverChanged,
		GrubChanged:    grubChanged,
		DriverChanged:  driverChanged,
	}, nil
}

func detectIOMMUTokens(cpuInfoPath string) ([]string, error) {
	raw, err := os.ReadFile(cpuInfoPath)
	if err != nil {
		return nil, fmt.Errorf("sriov: read cpuinfo %q: %w", cpuInfoPath, err)
	}
	text := strings.ToLower(string(raw))
	switch {
	case strings.Contains(text, "genuineintel"):
		return []string{"intel_iommu=on", "iommu=pt"}, nil
	case strings.Contains(text, "authenticamd"):
		return []string{"amd_iommu=on", "iommu=pt"}, nil
	default:
		return nil, fmt.Errorf("sriov: unable to detect CPU vendor from %s", cpuInfoPath)
	}
}

func ensureGrubTokens(grubPath string, required []string) (bool, error) {
	f, err := os.Open(grubPath)
	if err != nil {
		return false, fmt.Errorf("sriov: open grub %q: %w", grubPath, err)
	}
	defer f.Close()

	lines := make([]string, 0, 64)
	updated := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "GRUB_CMDLINE_LINUX_DEFAULT=") {
			next, changed, err := mergeKernelCmdline(line, required)
			if err != nil {
				return false, err
			}
			if changed {
				line = next
				updated = true
			}
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("sriov: read grub: %w", err)
	}
	if !updated {
		return false, nil
	}
	return true, writeIfChangedRaw(grubPath, []byte(strings.Join(lines, "\n")+"\n"))
}

func mergeKernelCmdline(line string, required []string) (string, bool, error) {
	const prefix = "GRUB_CMDLINE_LINUX_DEFAULT="
	if !strings.HasPrefix(line, prefix) {
		return line, false, nil
	}
	raw := strings.TrimPrefix(line, prefix)
	if len(raw) < 2 {
		return "", false, fmt.Errorf("sriov: invalid grub cmdline format")
	}
	quote := raw[:1]
	if quote != `"` && quote != "'" {
		return "", false, fmt.Errorf("sriov: unsupported grub cmdline quote")
	}
	if raw[len(raw)-1:] != quote {
		return "", false, fmt.Errorf("sriov: unbalanced grub cmdline quote")
	}
	items := strings.Fields(raw[1 : len(raw)-1])
	set := map[string]struct{}{}
	for _, item := range items {
		set[item] = struct{}{}
	}
	changed := false
	for _, item := range required {
		if _, ok := set[item]; ok {
			continue
		}
		items = append(items, item)
		set[item] = struct{}{}
		changed = true
	}
	if !changed {
		return line, false, nil
	}
	return prefix + quote + strings.Join(items, " ") + quote, true, nil
}

func writeIfChanged(path string, content []byte) (bool, error) {
	current, err := os.ReadFile(path)
	if err == nil && bytes.Equal(current, content) {
		return false, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("sriov: read %q: %w", path, err)
	}
	if err := writeIfChangedRaw(path, content); err != nil {
		return false, err
	}
	return true, nil
}

func writeIfChangedRaw(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("sriov: mkdir %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-sriov-*")
	if err != nil {
		return fmt.Errorf("sriov: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sriov: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sriov: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sriov: replace %q: %w", path, err)
	}
	return nil
}
