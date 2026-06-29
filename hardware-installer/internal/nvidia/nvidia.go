// Package nvidia installs NVIDIA driver dependencies for Proxmox hosts.
package nvidia

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/pmx-cloud/agents/hardware-installer/internal/runner"
)

type Params struct {
	AptGet      string
	AptCache    string
	LSPCI       string
	DKMS        string
	OutputLimit int64
}

type Result struct {
	RebootRequired bool `json:"reboot_required"`
	Detected       bool `json:"detected"`
}

func Install(ctx context.Context, p Params, stepFn func(string)) (*Result, error) {
	detected, err := detectNvidiaGPU(ctx, p.LSPCI, p.OutputLimit, stepFn)
	if err != nil {
		return nil, err
	}
	if !detected {
		return nil, fmt.Errorf("nvidia: no NVIDIA GPU detected")
	}
	if err := verifyPackageAvailable(ctx, p.AptCache, p.OutputLimit, stepFn); err != nil {
		return nil, err
	}

	env := map[string]string{
		"DEBIAN_FRONTEND": "noninteractive",
	}
	if _, err := runner.Run(ctx, runner.Command{
		Path:        p.AptGet,
		Args:        []string{"update"},
		Env:         env,
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("nvidia: apt update failed: %w", err)
	}

	headersPkg := detectHeadersPackage()
	depsArgs := []string{"install", "-y", "--option=Dpkg::Options::=--force-confnew", headersPkg, "build-essential", "dkms"}
	if _, err := runner.Run(ctx, runner.Command{
		Path:        p.AptGet,
		Args:        depsArgs,
		Env:         env,
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("nvidia: install deps failed: %w", err)
	}

	driverArgs := []string{"install", "-y", "--option=Dpkg::Options::=--force-confnew", "nvidia-driver", "firmware-misc-nonfree"}
	if _, err := runner.Run(ctx, runner.Command{
		Path:        p.AptGet,
		Args:        driverArgs,
		Env:         env,
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("nvidia: install driver failed: %w", err)
	}

	dkmsResult, dkmsErr := runner.Run(ctx, runner.Command{
		Path:        p.DKMS,
		Args:        []string{"status", "nvidia"},
		OutputLimit: p.OutputLimit,
	}, stepFn)
	if dkmsErr != nil {
		return nil, fmt.Errorf("nvidia: dkms status failed: %w", dkmsErr)
	}
	if !strings.Contains(strings.ToLower(dkmsResult.Combined), "installed") {
		return nil, fmt.Errorf("nvidia: dkms status does not show installed modules")
	}

	return &Result{RebootRequired: true, Detected: true}, nil
}

func detectNvidiaGPU(ctx context.Context, lspciPath string, outputLimit int64, stepFn func(string)) (bool, error) {
	res, err := runner.Run(ctx, runner.Command{
		Path:        lspciPath,
		Args:        []string{"-nn"},
		OutputLimit: outputLimit,
	}, stepFn)
	if err != nil {
		return false, fmt.Errorf("nvidia: lspci failed: %w", err)
	}
	return strings.Contains(strings.ToLower(res.Combined), "nvidia"), nil
}

func verifyPackageAvailable(ctx context.Context, aptCachePath string, outputLimit int64, stepFn func(string)) error {
	res, err := runner.Run(ctx, runner.Command{
		Path:        aptCachePath,
		Args:        []string{"search", "nvidia-driver"},
		OutputLimit: outputLimit,
	}, stepFn)
	if err != nil {
		return fmt.Errorf("nvidia: apt-cache search failed: %w", err)
	}
	if !strings.Contains(strings.ToLower(res.Combined), "nvidia-driver") {
		return fmt.Errorf("nvidia: nvidia-driver package not available in apt cache")
	}
	return nil
}

func detectHeadersPackage() string {
	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "pve-headers"
	}
	release := strings.TrimSpace(string(kernel))
	if release == "" {
		return "pve-headers"
	}
	return "pve-headers-" + release
}
