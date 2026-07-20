// Package ssh implements ssh.audit and ssh.harden.
package ssh

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pmx-cloud/agents/security/internal/rootscope"
)

var desiredProfile = map[string]string{
	"PasswordAuthentication":          "no",
	"PermitRootLogin":                 "no",
	"PubkeyAuthentication":            "yes",
	"KbdInteractiveAuthentication":    "no",
	"ChallengeResponseAuthentication": "no",
}

type Drift struct {
	Key      string `json:"key"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

type AuditResult struct {
	Effective map[string]string `json:"effective"`
	Drift     []Drift           `json:"drift"`
}

type HardenParams struct {
	JobID    string `json:"job_id"`
	StateDir string `json:"state_dir"`
}

type RootRunner interface {
	RunRoot(ctx context.Context, jobID, name, command string, args []string, h rootscope.Hardening) (*rootscope.Result, error)
}

type DefaultRootRunner struct{}

func (r *DefaultRootRunner) RunRoot(ctx context.Context, jobID, name, command string, args []string, h rootscope.Hardening) (*rootscope.Result, error) {
	return rootscope.RunRoot(ctx, jobID, name, command, args, h, nil)
}

func Audit(configPath string, dropInDir string) (*AuditResult, error) {
	if configPath == "" {
		configPath = "/etc/ssh/sshd_config"
	}
	if dropInDir == "" {
		dropInDir = "/etc/ssh/sshd_config.d"
	}

	effective := map[string]string{}
	if err := parseConfigFile(configPath, effective); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	dropins, _ := filepath.Glob(filepath.Join(dropInDir, "*.conf"))
	sort.Strings(dropins)
	for _, dropin := range dropins {
		_ = parseConfigFile(dropin, effective)
	}

	drift := []Drift{}
	for key, expected := range desiredProfile {
		actual := strings.ToLower(strings.TrimSpace(effective[key]))
		if actual != expected {
			drift = append(drift, Drift{Key: key, Expected: expected, Actual: actual})
		}
	}
	sort.Slice(drift, func(i, j int) bool { return drift[i].Key < drift[j].Key })

	return &AuditResult{Effective: effective, Drift: drift}, nil
}

func Harden(ctx context.Context, p HardenParams, rr RootRunner) error {
	if rr == nil {
		rr = &DefaultRootRunner{}
	}
	if p.JobID == "" {
		p.JobID = "local"
	}
	if p.StateDir == "" {
		p.StateDir = "/var/lib/pmx-cloud/security"
	}
	workDir := filepath.Join(p.StateDir, "ssh")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return fmt.Errorf("ssh.harden: mkdir workdir: %w", err)
	}
	contentPath := filepath.Join(workDir, "99-pmx-cloud.conf")
	if err := os.WriteFile(contentPath, []byte(desiredDropIn()), 0o600); err != nil {
		return fmt.Errorf("ssh.harden: write desired drop-in: %w", err)
	}
	scriptPath := filepath.Join(workDir, "apply-ssh-harden.sh")
	if err := os.WriteFile(scriptPath, []byte(applyScript()), 0o500); err != nil {
		return fmt.Errorf("ssh.harden: write apply script: %w", err)
	}

	_, err := rr.RunRoot(ctx, p.JobID, "ssh-harden", "/bin/sh", []string{scriptPath, contentPath}, rootscope.Hardening{ReadWritePaths: []string{"/etc/ssh", "/run/systemd"}, AppArmorProfile: "pmx-security-ssh-harden"})
	if err != nil {
		return fmt.Errorf("ssh.harden: %w", err)
	}
	return nil
}

func parseConfigFile(path string, out map[string]string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := fields[0]
		val := strings.Join(fields[1:], " ")
		out[key] = val
	}
	return s.Err()
}

func desiredDropIn() string {
	lines := make([]string, 0, len(desiredProfile))
	keys := make([]string, 0, len(desiredProfile))
	for k := range desiredProfile {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("%s %s", k, desiredProfile[k]))
	}
	return strings.Join(lines, "\n") + "\n"
}

func applyScript() string {
	return `#!/bin/sh
set -eu
SCRIPT="$1"
TARGET="/etc/ssh/sshd_config.d/99-pmx-cloud.conf"
install -D -m 0644 "$SCRIPT" "$TARGET"
if /usr/sbin/sshd -t; then
  systemctl reload ssh
  exit 0
fi
rm -f "$TARGET"
systemctl reload ssh || true
exit 1
`
}
