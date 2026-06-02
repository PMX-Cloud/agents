package siblings_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/core/internal/siblings"
)

// ── Allowlist logic (no systemctl needed) ─────────────────────────────────────

func TestAllow_ExactMatch(t *testing.T) {
	m := siblings.NewManager(
		[]string{"pmx-telemetry.service", "pmx-hypervisor.service"},
		nil, nil,
	)
	if !m.Allow("pmx-telemetry.service") {
		t.Fatal("pmx-telemetry.service must be allowed")
	}
	if !m.Allow("pmx-hypervisor.service") {
		t.Fatal("pmx-hypervisor.service must be allowed")
	}
}

func TestAllow_EphemeralTemplate(t *testing.T) {
	m := siblings.NewManager(
		[]string{"pmx-telemetry.service"},
		[]string{"pmx-hardware-installer@.service", "pmx-updater@.service"},
		nil,
	)
	if !m.Allow("pmx-hardware-installer@job-001.service") {
		t.Fatal("ephemeral instance must be allowed")
	}
	if !m.Allow("pmx-updater@v2.service") {
		t.Fatal("ephemeral updater instance must be allowed")
	}
}

func TestAllow_NotAllowed(t *testing.T) {
	m := siblings.NewManager(
		[]string{"pmx-telemetry.service"},
		nil, nil,
	)
	if m.Allow("sshd.service") {
		t.Fatal("sshd.service must NOT be allowed")
	}
	if m.Allow("pmx-telemetry.service.evil") {
		t.Fatal("suffix-spoofed name must NOT be allowed")
	}
}

func TestAllow_Empty(t *testing.T) {
	m := siblings.NewManager(nil, nil, nil)
	if m.Allow("pmx-telemetry.service") {
		t.Fatal("nothing must be allowed with empty list")
	}
}

// ── Gated operations — use real systemctl (expected to fail on CI / macOS) ────

func TestEnable_NotAllowlisted(t *testing.T) {
	m := siblings.NewManager([]string{"pmx-telemetry.service"}, nil, nil)
	err := m.Enable(context.Background(), "cron.service")
	if err == nil {
		t.Fatal("Enable must fail for non-allowlisted unit")
	}
}

func TestDisable_NotAllowlisted(t *testing.T) {
	m := siblings.NewManager([]string{"pmx-telemetry.service"}, nil, nil)
	err := m.Disable(context.Background(), "cron.service")
	if err == nil {
		t.Fatal("Disable must fail for non-allowlisted unit")
	}
}

func TestStatus_AllowedUnit_ErrorOrResult(t *testing.T) {
	m := siblings.NewManager([]string{"pmx-telemetry.service"}, nil, nil)
	// May return an error on macOS (no systemctl), but must not panic.
	_, _ = m.Status(context.Background(), "pmx-telemetry.service")
}

func TestNewManager_NilLogger(t *testing.T) {
	// Must not panic.
	m := siblings.NewManager([]string{"pmx-telemetry.service"}, nil, nil)
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}
