// Package auditd implements audit.enable, audit.disable, audit.query.
package auditd

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pmx-cloud/agents/security/internal/rootscope"
)

type RootRunner interface {
	RunRoot(ctx context.Context, jobID, name, command string, args []string, h rootscope.Hardening) (*rootscope.Result, error)
}

type DefaultRootRunner struct{}

func (r *DefaultRootRunner) RunRoot(ctx context.Context, jobID, name, command string, args []string, h rootscope.Hardening) (*rootscope.Result, error) {
	return rootscope.RunRoot(ctx, jobID, name, command, args, h, nil)
}

type QueryParams struct {
	Key       string `json:"key"`
	Since     string `json:"since"`
	MaxLines  int    `json:"max_lines"`
	AuditPath string `json:"audit_path"`
}

func Enable(ctx context.Context, jobID, stateDir string, rr RootRunner) error {
	if rr == nil {
		rr = &DefaultRootRunner{}
	}
	if stateDir == "" {
		stateDir = "/var/lib/pmx-cloud/security"
	}
	if jobID == "" {
		jobID = "local"
	}

	workDir := filepath.Join(stateDir, "auditd")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return fmt.Errorf("audit.enable: mkdir workdir: %w", err)
	}
	rulesPath := filepath.Join(workDir, "pmx-cloud.rules")
	if err := os.WriteFile(rulesPath, []byte(defaultRules()), 0o600); err != nil {
		return fmt.Errorf("audit.enable: write rules file: %w", err)
	}
	scriptPath := filepath.Join(workDir, "enable-auditd.sh")
	if err := os.WriteFile(scriptPath, []byte(enableScript()), 0o500); err != nil {
		return fmt.Errorf("audit.enable: write script: %w", err)
	}

	_, err := rr.RunRoot(ctx, jobID, "audit-enable", "/bin/sh", []string{scriptPath, rulesPath}, rootscope.Hardening{ReadWritePaths: []string{"/etc/audit", "/run/systemd"}, AppArmorProfile: "pmx-security-auditd-enable"})
	if err != nil {
		return fmt.Errorf("audit.enable: %w", err)
	}
	return nil
}

func Disable(ctx context.Context, jobID string, rr RootRunner) error {
	if rr == nil {
		rr = &DefaultRootRunner{}
	}
	if jobID == "" {
		jobID = "local"
	}
	_, err := rr.RunRoot(ctx, jobID, "audit-disable", "/bin/systemctl", []string{"disable", "--now", "auditd.service"}, rootscope.Hardening{ReadWritePaths: []string{"/etc/systemd", "/run/systemd"}, AppArmorProfile: "pmx-security-auditd-enable"})
	if err != nil {
		return fmt.Errorf("audit.disable: %w", err)
	}
	return nil
}

func Query(ctx context.Context, p QueryParams) ([]string, error) {
	if p.MaxLines <= 0 {
		p.MaxLines = 200
	}
	if p.MaxLines > 5000 {
		return nil, fmt.Errorf("audit.query: max_lines too large")
	}
	if p.Key == "" {
		p.Key = "pmx"
	}
	if p.Since == "" {
		p.Since = "today"
	}
	if err := validateQueryToken(p.Key, "key"); err != nil {
		return nil, err
	}
	if err := validateQueryToken(p.Since, "since"); err != nil {
		return nil, err
	}

	lines, err := queryAusearch(ctx, p.Key, p.Since)
	if err != nil {
		if p.AuditPath == "" {
			p.AuditPath = "/var/log/pmx-cloud/pmx-security.audit.log"
		}
		return queryLocalAuditLog(p.AuditPath, p.MaxLines)
	}
	if len(lines) > p.MaxLines {
		lines = lines[:p.MaxLines]
	}
	return lines, nil
}

func queryAusearch(ctx context.Context, key, since string) ([]string, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, "/sbin/ausearch", "-i", "-k", key, "-ts", since)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ausearch: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	return splitNonEmptyLines(out.String()), nil
}

func queryLocalAuditLog(path string, max int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("audit.query fallback read %s: %w", path, err)
	}
	defer f.Close()
	return tailNonEmptyLines(f, max)
}

func tailNonEmptyLines(r io.Reader, max int) ([]string, error) {
	if max <= 0 {
		return nil, nil
	}
	lines := make([]string, 0, max)
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if len(lines) < max {
			lines = append(lines, line)
			continue
		}
		copy(lines, lines[1:])
		lines[len(lines)-1] = line
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func validateQueryToken(value, field string) error {
	if strings.TrimSpace(value) == "" || len(value) > 64 || strings.ContainsAny(value, "\x00\n\r") {
		return fmt.Errorf("audit.query: invalid %s", field)
	}
	return nil
}

func splitNonEmptyLines(v string) []string {
	parts := strings.Split(v, "\n")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func defaultRules() string {
	return `-w /etc/ssh/sshd_config -p wa -k pmx-ssh
-w /etc/ssh/sshd_config.d -p wa -k pmx-ssh
-w /etc/passwd -p wa -k pmx-identity
-w /etc/group -p wa -k pmx-identity
`
}

func enableScript() string {
	return `#!/bin/sh
set -eu
SRC="$1"
DST="/etc/audit/rules.d/pmx-cloud.rules"
install -D -m 0640 "$SRC" "$DST"
augenrules --load
systemctl enable --now auditd.service
`
}
