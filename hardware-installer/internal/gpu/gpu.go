// Package gpu performs host-side GPU helper operations.
package gpu

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/pmx-cloud/agents/hardware-installer/internal/runner"
)

type Params struct {
	QM           string
	NvidiaSMI    string
	LXCConfigDir string
	OutputLimit  int64
}

type AttachRequest struct {
	VMID    int    `json:"vmid"`
	PCIID   string `json:"pci_id"`
	Slot    string `json:"slot"`
	Primary bool   `json:"primary"`
}

type DetachRequest struct {
	VMID int    `json:"vmid"`
	Slot string `json:"slot"`
}

type ModeRequest struct {
	Mode     string `json:"mode"`
	GPUIndex *int   `json:"gpu_index,omitempty"`
}

type AttachLXCRequest struct {
	VMID int    `json:"vmid"`
	Type string `json:"type"`
}

type Result struct {
	Changed bool `json:"changed"`
}

var (
	safeToken = regexp.MustCompile(`^[a-zA-Z0-9._:-]+$`)
	pciIDRe   = regexp.MustCompile(`^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$`)
)

func Attach(ctx context.Context, p Params, req AttachRequest, stepFn func(string)) (*Result, error) {
	if req.VMID <= 0 {
		return nil, fmt.Errorf("gpu.attach: vmid must be positive")
	}
	if !pciIDRe.MatchString(strings.TrimSpace(req.PCIID)) {
		return nil, fmt.Errorf("gpu.attach: invalid pci_id %q", req.PCIID)
	}
	slot := strings.TrimSpace(req.Slot)
	if slot == "" {
		slot = "hostpci0"
	}
	if !safeToken.MatchString(slot) {
		return nil, fmt.Errorf("gpu.attach: invalid slot %q", req.Slot)
	}
	xvga := "0"
	if req.Primary {
		xvga = "1"
	}
	if _, err := runner.Run(ctx, runner.Command{
		Path: p.QM,
		Args: []string{
			"set",
			strconv.Itoa(req.VMID),
			"-" + slot,
			fmt.Sprintf("%s,pcie=1,x-vga=%s", strings.ToLower(req.PCIID), xvga),
		},
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("gpu.attach: qm set failed: %w", err)
	}
	return &Result{Changed: true}, nil
}

func Detach(ctx context.Context, p Params, req DetachRequest, stepFn func(string)) (*Result, error) {
	if req.VMID <= 0 {
		return nil, fmt.Errorf("gpu.detach: vmid must be positive")
	}
	slot := strings.TrimSpace(req.Slot)
	if slot == "" {
		slot = "hostpci0"
	}
	if !safeToken.MatchString(slot) {
		return nil, fmt.Errorf("gpu.detach: invalid slot %q", req.Slot)
	}
	if _, err := runner.Run(ctx, runner.Command{
		Path:        p.QM,
		Args:        []string{"set", strconv.Itoa(req.VMID), "-delete", slot},
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("gpu.detach: qm set delete failed: %w", err)
	}
	return &Result{Changed: true}, nil
}

func Mode(ctx context.Context, p Params, req ModeRequest, stepFn func(string)) (*Result, error) {
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "compute"
	}
	if mode != "compute" && mode != "default" {
		return nil, fmt.Errorf("gpu.mode: mode must be compute or default")
	}

	indexArgs := []string{}
	if req.GPUIndex != nil {
		if *req.GPUIndex < 0 {
			return nil, fmt.Errorf("gpu.mode: gpu_index must be >= 0")
		}
		indexArgs = append(indexArgs, "-i", strconv.Itoa(*req.GPUIndex))
	}

	persistence := "1"
	computeMode := "EXCLUSIVE_PROCESS"
	if mode == "default" {
		persistence = "0"
		computeMode = "DEFAULT"
	}

	pmArgs := append(append([]string{}, indexArgs...), "-pm", persistence)
	if _, err := runner.Run(ctx, runner.Command{
		Path:        p.NvidiaSMI,
		Args:        pmArgs,
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("gpu.mode: set persistence mode failed: %w", err)
	}

	cmArgs := append(append([]string{}, indexArgs...), "-c", computeMode)
	if _, err := runner.Run(ctx, runner.Command{
		Path:        p.NvidiaSMI,
		Args:        cmArgs,
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("gpu.mode: set compute mode failed: %w", err)
	}

	return &Result{Changed: true}, nil
}

func AttachLXC(_ context.Context, p Params, req AttachLXCRequest, _ func(string)) (*Result, error) {
	if req.VMID <= 0 {
		return nil, fmt.Errorf("gpu.attach.lxc: vmid must be positive")
	}
	gpuType := strings.ToLower(strings.TrimSpace(req.Type))
	if gpuType == "" {
		gpuType = "nvidia"
	}
	if gpuType != "nvidia" && gpuType != "intel" && gpuType != "amd" {
		return nil, fmt.Errorf("gpu.attach.lxc: type must be nvidia, intel, or amd")
	}

	configPath := filepath.Join(p.LXCConfigDir, fmt.Sprintf("%d.conf", req.VMID))
	lines, err := readLines(configPath)
	if err != nil {
		return nil, fmt.Errorf("gpu.attach.lxc: read %q: %w", configPath, err)
	}

	additions := lxcLinesForType(gpuType)
	changed := false
	for _, line := range additions {
		if slices.Contains(lines, line) {
			continue
		}
		lines = append(lines, line)
		changed = true
	}
	if !changed {
		return &Result{Changed: false}, nil
	}
	if err := writeLinesAtomic(configPath, lines); err != nil {
		return nil, fmt.Errorf("gpu.attach.lxc: write %q: %w", configPath, err)
	}
	return &Result{Changed: true}, nil
}

func lxcLinesForType(gpuType string) []string {
	switch gpuType {
	case "nvidia":
		return []string{
			"lxc.cgroup2.devices.allow: c 195:* rwm",
			"lxc.cgroup2.devices.allow: c 511:* rwm",
			"lxc.mount.entry: /dev/nvidia0 dev/nvidia0 none bind,optional,create=file 0 0",
			"lxc.mount.entry: /dev/nvidiactl dev/nvidiactl none bind,optional,create=file 0 0",
			"lxc.mount.entry: /dev/nvidia-uvm dev/nvidia-uvm none bind,optional,create=file 0 0",
		}
	default:
		return []string{
			"lxc.cgroup2.devices.allow: c 226:* rwm",
			"lxc.mount.entry: /dev/dri dev/dri none bind,optional,create=dir 0 0",
		}
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lines := make([]string, 0, 64)
	s := bufio.NewScanner(f)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func writeLinesAtomic(path string, lines []string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-lxc-*.conf")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	payload := strings.Join(lines, "\n")
	if !strings.HasSuffix(payload, "\n") {
		payload += "\n"
	}
	if _, err := tmp.WriteString(payload); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
