// Package iommu enables host IOMMU by editing grub defaults and updating boot config.
package iommu

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pmx-cloud/agents/hardware-installer/internal/runner"
)

type Params struct {
	CPUInfoPath string
	GrubPath    string
	UpdateGrub  string
	OutputLimit int64
}

type Result struct {
	RebootRequired bool   `json:"reboot_required"`
	Vendor         string `json:"vendor"`
	Changed        bool   `json:"changed"`
}

func Enable(ctx context.Context, p Params, stepFn func(string)) (*Result, error) {
	vendor, tokens := detectVendorAndTokens(p.CPUInfoPath)
	if vendor == "" {
		return nil, fmt.Errorf("iommu: unable to detect CPU vendor from %s", p.CPUInfoPath)
	}
	changed, err := ensureGrubTokens(p.GrubPath, tokens)
	if err != nil {
		return nil, err
	}
	if stepFn != nil {
		stepFn(fmt.Sprintf("iommu: cpu vendor=%s", vendor))
	}
	if changed {
		if stepFn != nil {
			stepFn("iommu: grub config updated")
		}
		if _, err := runner.Run(ctx, runner.Command{
			Path:        p.UpdateGrub,
			Args:        []string{},
			OutputLimit: p.OutputLimit,
		}, stepFn); err != nil {
			return nil, fmt.Errorf("iommu: update-grub failed: %w", err)
		}
	}
	return &Result{RebootRequired: true, Vendor: vendor, Changed: changed}, nil
}

func detectVendorAndTokens(cpuInfoPath string) (string, []string) {
	raw, err := os.ReadFile(cpuInfoPath)
	if err != nil {
		return "", nil
	}
	text := strings.ToLower(string(raw))
	if strings.Contains(text, "genuineintel") {
		return "intel", []string{"intel_iommu=on", "iommu=pt"}
	}
	if strings.Contains(text, "authenticamd") {
		return "amd", []string{"amd_iommu=on", "iommu=pt"}
	}
	return "", nil
}

func ensureGrubTokens(grubPath string, tokens []string) (bool, error) {
	file, err := os.Open(grubPath)
	if err != nil {
		return false, fmt.Errorf("iommu: open grub config %q: %w", grubPath, err)
	}
	defer file.Close()

	lines := make([]string, 0, 32)
	scanner := bufio.NewScanner(file)
	updated := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "GRUB_CMDLINE_LINUX_DEFAULT=") {
			nextLine, changed, err := mergeKernelCmdline(line, tokens)
			if err != nil {
				return false, err
			}
			if changed {
				line = nextLine
				updated = true
			}
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("iommu: read grub config: %w", err)
	}
	if !updated {
		return false, nil
	}

	tmp, err := os.CreateTemp(filepath.Dir(grubPath), ".grub-*.tmp")
	if err != nil {
		return false, fmt.Errorf("iommu: create temp grub file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("iommu: write temp grub file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("iommu: close temp grub file: %w", err)
	}
	if err := os.Rename(tmpPath, grubPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("iommu: atomic replace grub file: %w", err)
	}
	return true, nil
}

func mergeKernelCmdline(line string, required []string) (string, bool, error) {
	prefix := "GRUB_CMDLINE_LINUX_DEFAULT="
	if !strings.HasPrefix(line, prefix) {
		return line, false, nil
	}
	value := strings.TrimPrefix(line, prefix)
	quote := `"`
	if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
		quote = "'"
	}
	if !(strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) && !(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
		return "", false, fmt.Errorf("iommu: unsupported grub cmdline format: %q", line)
	}
	raw := value[1 : len(value)-1]
	tokens := strings.Fields(raw)
	set := map[string]struct{}{}
	for _, token := range tokens {
		set[token] = struct{}{}
	}
	changed := false
	for _, token := range required {
		if _, ok := set[token]; ok {
			continue
		}
		tokens = append(tokens, token)
		set[token] = struct{}{}
		changed = true
	}
	if !changed {
		return line, false, nil
	}
	return prefix + quote + strings.Join(tokens, " ") + quote, true, nil
}
