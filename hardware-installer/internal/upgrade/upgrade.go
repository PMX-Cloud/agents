// Package upgrade runs one-shot Proxmox upgrade routines.
package upgrade

import (
	"context"
	"fmt"
	"strings"

	"github.com/pmx-cloud/agents/hardware-installer/internal/runner"
)

type Params struct {
	AptGet      string
	PVEUpgrade  string
	OutputLimit int64
}

type RunRequest struct {
	Mode string `json:"mode"`
}

type Result struct {
	RebootRequired bool   `json:"reboot_required"`
	Mode           string `json:"mode"`
}

func Run(ctx context.Context, p Params, req RunRequest, stepFn func(string)) (*Result, error) {
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "automatic"
	}
	if mode != "automatic" && mode != "check-only" && mode != "interactive" {
		return nil, fmt.Errorf("upgrade: mode must be automatic, check-only, or interactive")
	}

	if mode == "automatic" {
		env := map[string]string{"DEBIAN_FRONTEND": "noninteractive"}
		if _, err := runner.Run(ctx, runner.Command{
			Path:        p.AptGet,
			Args:        []string{"update"},
			Env:         env,
			OutputLimit: p.OutputLimit,
		}, stepFn); err != nil {
			return nil, fmt.Errorf("upgrade: apt update failed: %w", err)
		}
		if _, err := runner.Run(ctx, runner.Command{
			Path:        p.AptGet,
			Args:        []string{"dist-upgrade", "-y"},
			Env:         env,
			OutputLimit: p.OutputLimit,
		}, stepFn); err != nil {
			return nil, fmt.Errorf("upgrade: apt dist-upgrade failed: %w", err)
		}
	}

	if _, err := runner.Run(ctx, runner.Command{
		Path:        p.PVEUpgrade,
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("upgrade: pveupgrade failed: %w", err)
	}

	return &Result{RebootRequired: mode != "check-only", Mode: mode}, nil
}
