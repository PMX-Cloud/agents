package rootscope_test

import (
	"context"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/security/internal/rootscope"
)

type mockRunner struct {
	binary string
	args   []string
}

func (m *mockRunner) Run(ctx context.Context, binary string, args ...string) (*rootscope.Result, error) {
	m.binary = binary
	m.args = append([]string(nil), args...)
	return &rootscope.Result{ExitCode: 0}, nil
}

func TestRunRootBuildsSystemdRunCommand(t *testing.T) {
	m := &mockRunner{}
	_, err := rootscope.RunRoot(context.Background(), "job1", "ssh_harden", "/usr/bin/systemctl", []string{"reload", "ssh"}, rootscope.Hardening{ReadWritePaths: []string{"/etc/ssh"}, AppArmorProfile: "pmx-security-ssh-harden"}, m)
	if err != nil {
		t.Fatalf("RunRoot: %v", err)
	}
	if m.binary != rootscope.DefaultSystemdRunPath {
		t.Fatalf("expected systemd-run binary, got %s", m.binary)
	}
	joined := strings.Join(m.args, " ")
	if !strings.Contains(joined, "--scope") || !strings.Contains(joined, "--uid=0") || !strings.Contains(joined, "--unit") {
		t.Fatalf("unexpected args: %v", m.args)
	}
	if !strings.Contains(joined, "ReadWritePaths=/etc/ssh") {
		t.Fatalf("missing ReadWritePaths in args: %v", m.args)
	}
	if !strings.Contains(joined, "AppArmorProfile=pmx-security-ssh-harden") {
		t.Fatalf("missing AppArmorProfile in args: %v", m.args)
	}
	if strings.Contains(joined, "--collect") {
		t.Fatalf("recoverable root scopes must not be collected before reconciliation: %v", m.args)
	}
}

func TestRunRootRejectsNonAbsoluteCommand(t *testing.T) {
	_, err := rootscope.RunRoot(context.Background(), "job1", "bad", "systemctl", []string{"status"}, rootscope.Hardening{}, &mockRunner{})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute path error, got %v", err)
	}
}

func TestScopeUnitNameRejectsUnsafeTokens(t *testing.T) {
	_, err := rootscope.ScopeUnitName("../bad", "ssh_harden")
	if err == nil {
		t.Fatal("expected token validation error")
	}
}
