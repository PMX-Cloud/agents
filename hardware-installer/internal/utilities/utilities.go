// Package utilities installs a strict allowlisted package set.
package utilities

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/pmx-cloud/agents/hardware-installer/internal/runner"
)

type Params struct {
	AptGet          string
	AllowedPackages []string
	OutputLimit     int64
}

type InstallRequest struct {
	Packages []string `json:"packages"`
}

type Result struct {
	Installed []string `json:"installed"`
}

var safePackage = regexp.MustCompile(`^[a-zA-Z0-9+._:-]+$`)

func Install(ctx context.Context, p Params, req InstallRequest, stepFn func(string)) (*Result, error) {
	packages, err := resolvePackages(req.Packages, p.AllowedPackages)
	if err != nil {
		return nil, err
	}
	env := map[string]string{"DEBIAN_FRONTEND": "noninteractive"}
	if _, err := runner.Run(ctx, runner.Command{
		Path:        p.AptGet,
		Args:        []string{"update"},
		Env:         env,
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("utilities: apt update failed: %w", err)
	}
	args := append([]string{"install", "-y"}, packages...)
	if _, err := runner.Run(ctx, runner.Command{
		Path:        p.AptGet,
		Args:        args,
		Env:         env,
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("utilities: apt install failed: %w", err)
	}
	return &Result{Installed: packages}, nil
}

func resolvePackages(requested []string, allowed []string) ([]string, error) {
	if len(requested) == 0 {
		return nil, fmt.Errorf("utilities: packages must be non-empty")
	}
	allowSet := map[string]struct{}{}
	for _, pkg := range allowed {
		allowSet[pkg] = struct{}{}
	}
	result := make([]string, 0, len(requested))
	seen := map[string]struct{}{}
	for _, raw := range requested {
		pkg := strings.TrimSpace(raw)
		if pkg == "" || !safePackage.MatchString(pkg) {
			return nil, fmt.Errorf("utilities: invalid package %q", raw)
		}
		if _, ok := allowSet[pkg]; !ok {
			return nil, fmt.Errorf("utilities: package %q is not allowlisted", pkg)
		}
		if _, ok := seen[pkg]; ok {
			continue
		}
		seen[pkg] = struct{}{}
		result = append(result, pkg)
	}
	slices.Sort(result)
	return result, nil
}
