// Package lynis implements lynis.run.
package lynis

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Finding struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type RunResult struct {
	ReportPath  string            `json:"report_path"`
	Findings    map[string]string `json:"findings"`
	Warnings    []string          `json:"warnings"`
	Suggestions []string          `json:"suggestions"`
}

type Runner interface {
	Run(ctx context.Context, binary string, args ...string) ([]byte, []byte, error)
}

type ExecRunner struct{}

func (r *ExecRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	var out, err bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &err
	e := cmd.Run()
	return out.Bytes(), err.Bytes(), e
}

func Run(ctx context.Context, binary string, profile string, reportPath string, step func(string), runner Runner) (*RunResult, error) {
	if runner == nil {
		runner = &ExecRunner{}
	}
	if step == nil {
		step = func(string) {}
	}
	if reportPath == "" {
		reportPath = "/var/log/lynis-report.dat"
	}

	step("starting lynis audit")
	args := []string{"audit", "system", "--quick", "--no-colors", "--quiet"}
	if strings.TrimSpace(profile) != "" {
		args = append(args, "--profile", profile)
	}
	stdout, stderr, err := runner.Run(ctx, binary, args...)
	if err != nil {
		return nil, fmt.Errorf("lynis.run failed: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	_ = stdout // lynis --quiet gives little stdout; report file is canonical output.

	step("parsing lynis report")
	findings, warnings, suggestions, err := parseReport(reportPath)
	if err != nil {
		return nil, err
	}

	return &RunResult{
		ReportPath:  reportPath,
		Findings:    findings,
		Warnings:    warnings,
		Suggestions: suggestions,
	}, nil
}

func parseReport(path string) (map[string]string, []string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("lynis.report open %s: %w", path, err)
	}
	defer f.Close()

	findings := map[string]string{}
	warnings := []string{}
	suggestions := []string{}

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		findings[k] = v
		switch {
		case strings.HasPrefix(k, "warning"):
			warnings = append(warnings, v)
		case strings.HasPrefix(k, "suggestion"):
			suggestions = append(suggestions, v)
		}
	}
	if err := s.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("lynis.report scan: %w", err)
	}
	return findings, warnings, suggestions, nil
}
