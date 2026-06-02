package siblings_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/core/internal/siblings"
)

func TestDaemonReload_NotInstalled(t *testing.T) {
	m := siblings.NewManager(
		[]string{"pmx-telemetry.service"},
		nil, nil,
	)
	// This will fail on macOS (no systemctl), but should not panic.
	// Error is acceptable; the important thing is no panic.
	ctx := context.Background()
	_ = m.DaemonReload(ctx)
}

func TestStatus_NotInAllowlist(t *testing.T) {
	m := siblings.NewManager(
		[]string{"pmx-telemetry.service"},
		nil, nil,
	)
	_, err := m.Status(context.Background(), "sshd.service")
	if err == nil {
		t.Fatal("expected error for non-allowlisted unit")
	}
}

func TestStart_NotInAllowlist(t *testing.T) {
	m := siblings.NewManager(
		[]string{"pmx-telemetry.service"},
		nil, nil,
	)
	err := m.Start(context.Background(), "sshd.service")
	if err == nil {
		t.Fatal("expected error for non-allowlisted unit")
	}
}

func TestStop_NotInAllowlist(t *testing.T) {
	m := siblings.NewManager(
		[]string{"pmx-telemetry.service"},
		nil, nil,
	)
	err := m.Stop(context.Background(), "sshd.service")
	if err == nil {
		t.Fatal("expected error for non-allowlisted unit")
	}
}

func TestEnable_NotInAllowlist(t *testing.T) {
	m := siblings.NewManager(
		[]string{"pmx-telemetry.service"},
		nil, nil,
	)
	err := m.Enable(context.Background(), "sshd.service")
	if err == nil {
		t.Fatal("expected error for non-allowlisted unit")
	}
}

func TestDisable_NotInAllowlist(t *testing.T) {
	m := siblings.NewManager(
		[]string{"pmx-telemetry.service"},
		nil, nil,
	)
	err := m.Disable(context.Background(), "sshd.service")
	if err == nil {
		t.Fatal("expected error for non-allowlisted unit")
	}
}

func TestRestart_NotInAllowlist(t *testing.T) {
	m := siblings.NewManager(
		[]string{"pmx-telemetry.service"},
		nil, nil,
	)
	err := m.Restart(context.Background(), "sshd.service")
	if err == nil {
		t.Fatal("expected error for non-allowlisted unit")
	}
}
