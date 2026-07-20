// Package hardening implements hardening.apply and operation profile handling.
package hardening

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pmx-cloud/agents/security/internal/rootscope"
)

//go:embed profiles/*.sh
var embeddedProfiles embed.FS

var expectedHashes = map[string]string{
	"profiles/auditd_enable.sh":   "08e58666becf50d8e929c4c641ee93da1863c14a9315251506c23593eb63cc56",
	"profiles/disable_rpcbind.sh": "27c2dd1b636a015a709aefee1e8e805f04c9fab066ecb8052e13e0e29491b9c5",
	"profiles/ssh_level1.sh":      "d951c01ead2c5eba7a3763e706b87375b1ccc15c6aed508ebc0a5bfd1925e4e6",
}

var profileOperations = map[string][]string{
	"cis_level1": {"disable_rpcbind", "ssh_level1"},
	"cis_level2": {"disable_rpcbind", "ssh_level1", "auditd_enable"},
}

var operationHardening = map[string]rootscope.Hardening{
	"disable_rpcbind": {ReadWritePaths: []string{"/etc/systemd", "/run/systemd"}, AppArmorProfile: "pmx-security-disable-rpcbind"},
	"ssh_level1":      {ReadWritePaths: []string{"/etc/ssh", "/run/systemd"}, AppArmorProfile: "pmx-security-ssh-harden"},
	"auditd_enable":   {ReadWritePaths: []string{"/etc/audit", "/run/systemd"}, AppArmorProfile: "pmx-security-auditd-enable"},
}

type ApplyParams struct {
	JobID      string   `json:"job_id"`
	Profile    string   `json:"profile"`
	Operations []string `json:"operations"`
	StateDir   string   `json:"state_dir"`
}

type ApplyResult struct {
	Applied []string `json:"applied"`
	Noop    []string `json:"noop"`
}

type RootRunner interface {
	RunRoot(ctx context.Context, jobID, name, command string, args []string, h rootscope.Hardening) (*rootscope.Result, error)
}

type DefaultRootRunner struct{}

func (r *DefaultRootRunner) RunRoot(ctx context.Context, jobID, name, command string, args []string, h rootscope.Hardening) (*rootscope.Result, error) {
	return rootscope.RunRoot(ctx, jobID, name, command, args, h, nil)
}

func Apply(ctx context.Context, params ApplyParams, rr RootRunner) (*ApplyResult, error) {
	if rr == nil {
		rr = &DefaultRootRunner{}
	}
	if params.JobID == "" {
		params.JobID = "local"
	}
	if params.StateDir == "" {
		params.StateDir = "/var/lib/pmx-cloud/security"
	}
	if err := verifyProfileSignatures(); err != nil {
		return nil, err
	}

	ops, err := resolveOperations(params.Profile, params.Operations)
	if err != nil {
		return nil, err
	}
	tracker, err := newApplyTracker(params.StateDir, params.JobID, params.Profile, ops)
	if err != nil {
		return nil, err
	}
	res := &ApplyResult{Applied: []string{}, Noop: []string{}}
	for _, op := range ops {
		scriptPath, err := materializeProfileScript(params.StateDir, op)
		if err != nil {
			_ = tracker.markJobFail(fmt.Sprintf("operation %s materialize failed: %v", op, err))
			return nil, err
		}
		h := operationHardening[op]
		checkUnit, err := rootscope.ScopeUnitName(params.JobID, op+"-check")
		if err != nil {
			_ = tracker.markJobFail(fmt.Sprintf("operation %s invalid unit: %v", op, err))
			return nil, err
		}
		if err := tracker.markOpRunning(op, checkUnit); err != nil {
			return nil, err
		}

		check, checkErr := rr.RunRoot(ctx, params.JobID, op+"-check", "/bin/sh", []string{scriptPath, "--check"}, h)
		if checkErr == nil && check != nil && check.ExitCode == 0 {
			if err := tracker.markOpSuccess(op, true); err != nil {
				return nil, err
			}
			res.Noop = append(res.Noop, op)
			continue
		}
		applyUnit, err := rootscope.ScopeUnitName(params.JobID, op)
		if err != nil {
			_ = tracker.markJobFail(fmt.Sprintf("operation %s invalid apply unit: %v", op, err))
			return nil, err
		}
		if err := tracker.markOpRunning(op, applyUnit); err != nil {
			return nil, err
		}

		runResult, runErr := rr.RunRoot(ctx, params.JobID, op, "/bin/sh", []string{scriptPath}, h)
		if runErr != nil {
			_ = tracker.markOpFail(op, stderrSnippet(runResult))
			_ = tracker.markJobFail(fmt.Sprintf("operation %s failed: %v", op, runErr))
			return nil, fmt.Errorf("hardening.apply operation %s failed: %w", op, runErr)
		}
		if err := tracker.markOpSuccess(op, false); err != nil {
			return nil, err
		}
		res.Applied = append(res.Applied, op)
	}
	if err := tracker.markJobSuccess(); err != nil {
		return nil, err
	}
	return res, nil
}

// ValidateProfiles verifies the embedded hardening profile hashes.
func ValidateProfiles() error {
	return verifyProfileSignatures()
}

func verifyProfileSignatures() error {
	for path, expected := range expectedHashes {
		data, err := fs.ReadFile(embeddedProfiles, path)
		if err != nil {
			return fmt.Errorf("hardening profile missing %s: %w", path, err)
		}
		sum := sha256.Sum256(data)
		actual := hex.EncodeToString(sum[:])
		if actual != expected {
			return fmt.Errorf("hardening profile signature mismatch for %s", path)
		}
	}
	return nil
}

func resolveOperations(profile string, ops []string) ([]string, error) {
	profile = strings.TrimSpace(strings.ToLower(profile))
	if profile == "" {
		profile = "cis_level1"
	}
	if profile == "custom" {
		if len(ops) == 0 {
			return nil, fmt.Errorf("hardening.apply: custom profile requires operations")
		}
		for _, op := range ops {
			if _, ok := operationHardening[op]; !ok {
				return nil, fmt.Errorf("hardening.apply: unknown operation %q", op)
			}
		}
		return dedupeSorted(ops), nil
	}
	resolved, ok := profileOperations[profile]
	if !ok {
		return nil, fmt.Errorf("hardening.apply: unknown profile %q", profile)
	}
	return append([]string(nil), resolved...), nil
}

func materializeProfileScript(stateDir, operation string) (string, error) {
	relPath := "profiles/" + operation + ".sh"
	data, err := fs.ReadFile(embeddedProfiles, relPath)
	if err != nil {
		return "", fmt.Errorf("hardening.apply: missing profile script %s", relPath)
	}
	targetDir := filepath.Join(stateDir, "profiles")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		return "", fmt.Errorf("hardening.apply: mkdir profiles dir: %w", err)
	}
	target := filepath.Join(targetDir, operation+".sh")
	if err := os.WriteFile(target, data, 0o500); err != nil {
		return "", fmt.Errorf("hardening.apply: write profile script: %w", err)
	}
	return target, nil
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func stderrSnippet(r *rootscope.Result) string {
	if r == nil || len(r.Stderr) == 0 {
		return ""
	}
	v := strings.TrimSpace(string(r.Stderr))
	if len(v) <= 512 {
		return v
	}
	return v[:512]
}
