// Package rootscope runs short-lived root operations via systemd-run --scope.
package rootscope

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const DefaultSystemdRunPath = "/usr/bin/systemd-run"

type Hardening struct {
	ReadWritePaths  []string
	AppArmorProfile string
}

type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

type Runner interface {
	Run(ctx context.Context, binary string, args ...string) (*Result, error)
}

type ExecRunner struct{}

func (r *ExecRunner) Run(ctx context.Context, binary string, args ...string) (*Result, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exit := 0
	if err != nil {
		exit = -1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
	}
	res := &Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: exit, Duration: time.Since(start)}
	if err != nil {
		return res, fmt.Errorf("rootscope exec failed: %w", err)
	}
	return res, nil
}

func RunRoot(ctx context.Context, jobID, name, command string, args []string, hardening Hardening, runner Runner) (*Result, error) {
	if runner == nil {
		runner = &ExecRunner{}
	}
	if !strings.HasPrefix(command, "/") {
		return nil, fmt.Errorf("rootscope: command must be absolute path")
	}
	for _, arg := range args {
		if strings.ContainsAny(arg, "\x00\n\r") {
			return nil, fmt.Errorf("rootscope: argument contains invalid control characters")
		}
	}

	unit, err := ScopeUnitName(jobID, name)
	if err != nil {
		return nil, err
	}
	argv := []string{
		"--scope",
		"--quiet",
		"--uid=0",
		"--gid=0",
		"--unit", unit,
		"--property=ProtectSystem=strict",
		"--property=NoNewPrivileges=true",
		"--property=PrivateTmp=true",
		"--property=ProtectHome=true",
	}
	if len(hardening.ReadWritePaths) > 0 {
		for _, p := range hardening.ReadWritePaths {
			if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
				return nil, fmt.Errorf("rootscope: invalid ReadWritePath %q", p)
			}
		}
		argv = append(argv, "--property=ReadWritePaths="+strings.Join(hardening.ReadWritePaths, " "))
	}
	if hardening.AppArmorProfile != "" {
		if !isSafeProfileName(hardening.AppArmorProfile) {
			return nil, fmt.Errorf("rootscope: invalid AppArmorProfile %q", hardening.AppArmorProfile)
		}
		argv = append(argv, "--property=AppArmorProfile="+hardening.AppArmorProfile)
	}
	argv = append(argv, "--", command)
	argv = append(argv, args...)
	return runner.Run(ctx, DefaultSystemdRunPath, argv...)
}

// ScopeUnitName returns the canonical systemd scope unit name for a root apply
// sub-command and validates both jobID and operation name tokens.
func ScopeUnitName(jobID, name string) (string, error) {
	if !isSafeToken(name) || !isSafeToken(jobID) {
		return "", fmt.Errorf("rootscope: invalid job/name token")
	}
	return fmt.Sprintf("pmx-sec-apply-%s-%s.scope", jobID, name), nil
}

func isSafeToken(v string) bool {
	if v == "" {
		return false
	}
	for _, c := range v {
		if !(c == '-' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func isSafeProfileName(v string) bool {
	if v == "" {
		return false
	}
	for _, c := range v {
		if !(c == '-' || c == '_' || c == '.' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
