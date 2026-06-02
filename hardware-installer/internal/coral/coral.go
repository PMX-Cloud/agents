// Package coral installs and discovers Coral TPU hardware on the host.
package coral

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/pmx-cloud/agents/hardware-installer/internal/runner"
)

type Params struct {
	AptGet      string
	LSPCI       string
	DKMS        string
	OutputLimit int64
}

type InstallRequest struct {
	Interface string `json:"interface"`
}

type InstallResult struct {
	RebootRequired bool     `json:"reboot_required"`
	Packages       []string `json:"packages"`
}

type AttachResult struct {
	Detected bool     `json:"detected"`
	PCIIDs   []string `json:"pci_ids,omitempty"`
}

var pciLine = regexp.MustCompile(`(?i)^([0-9a-f]{2}:[0-9a-f]{2}\.[0-7]).*`)

func Install(ctx context.Context, p Params, req InstallRequest, stepFn func(string)) (*InstallResult, error) {
	typeName := strings.ToLower(strings.TrimSpace(req.Interface))
	if typeName == "" {
		typeName = "usb"
	}
	if typeName != "usb" && typeName != "m2" {
		return nil, fmt.Errorf("coral: interface must be usb or m2")
	}

	packages := []string{"gasket-dkms", "libedgetpu1-std"}
	if typeName == "m2" {
		packages[1] = "libedgetpu1-max"
	}
	env := map[string]string{"DEBIAN_FRONTEND": "noninteractive"}

	if _, err := runner.Run(ctx, runner.Command{
		Path:        p.AptGet,
		Args:        []string{"update"},
		Env:         env,
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("coral: apt update failed: %w", err)
	}
	args := []string{"install", "-y", "--option=Dpkg::Options::=--force-confnew"}
	args = append(args, packages...)
	if _, err := runner.Run(ctx, runner.Command{
		Path:        p.AptGet,
		Args:        args,
		Env:         env,
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("coral: apt install failed: %w", err)
	}
	status, err := runner.Run(ctx, runner.Command{
		Path:        p.DKMS,
		Args:        []string{"status", "gasket"},
		OutputLimit: p.OutputLimit,
	}, stepFn)
	if err != nil {
		return nil, fmt.Errorf("coral: dkms status failed: %w", err)
	}
	if !strings.Contains(strings.ToLower(status.Combined), "installed") {
		return nil, fmt.Errorf("coral: dkms status does not show installed modules")
	}
	return &InstallResult{RebootRequired: true, Packages: packages}, nil
}

func Attach(ctx context.Context, p Params, stepFn func(string)) (*AttachResult, error) {
	out, err := runner.Run(ctx, runner.Command{
		Path:        p.LSPCI,
		Args:        []string{"-nn"},
		OutputLimit: p.OutputLimit,
	}, stepFn)
	if err != nil {
		return nil, fmt.Errorf("coral: lspci failed: %w", err)
	}
	ids := parseCoralPCIIDs(out.Combined)
	return &AttachResult{Detected: len(ids) > 0, PCIIDs: ids}, nil
}

func parseCoralPCIIDs(raw string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 2)
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if !(strings.Contains(lower, "google") || strings.Contains(lower, "1ac1:")) {
			continue
		}
		match := pciLine.FindStringSubmatch(trimmed)
		if len(match) != 2 {
			continue
		}
		id := strings.ToLower(match[1])
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
