// Package kernel supports allowlisted kernel module loading.
package kernel

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/pmx-cloud/agents/hardware-installer/internal/runner"
)

type Params struct {
	ModprobePath   string
	AllowedModules []string
	OutputLimit    int64
}

type LoadRequest struct {
	Module  string   `json:"module"`
	Options []string `json:"options"`
}

type Result struct {
	Module string `json:"module"`
	Loaded bool   `json:"loaded"`
}

var safeArg = regexp.MustCompile(`^[a-zA-Z0-9._=:-]+$`)

func LoadModule(ctx context.Context, p Params, req LoadRequest, stepFn func(string)) (*Result, error) {
	module := strings.TrimSpace(req.Module)
	if !safeArg.MatchString(module) {
		return nil, fmt.Errorf("kernel.module.load: invalid module %q", req.Module)
	}
	if !slices.Contains(p.AllowedModules, module) {
		return nil, fmt.Errorf("kernel.module.load: module %q is not allowlisted", module)
	}
	args := []string{module}
	for _, raw := range req.Options {
		option := strings.TrimSpace(raw)
		if !safeArg.MatchString(option) {
			return nil, fmt.Errorf("kernel.module.load: invalid option %q", raw)
		}
		args = append(args, option)
	}
	if _, err := runner.Run(ctx, runner.Command{
		Path:        p.ModprobePath,
		Args:        args,
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("kernel.module.load: modprobe failed: %w", err)
	}
	return &Result{Module: module, Loaded: true}, nil
}
