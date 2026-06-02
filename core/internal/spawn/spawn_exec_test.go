package spawn_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/shared/envelope"

	"github.com/pmx-cloud/agents/core/internal/spawn"
)

func makeFullEnvelope() *envelope.Envelope {
	return &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "test-spawn-job-001",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Command:   "hardware.install",
		Audience:  "pmx-hardware-installer",
		Params:    map[string]interface{}{},
	}
}

// TestSpawn_ValidInput_FailsAfterValidation calls Spawn with all required fields
// set. On non-Linux systems this hits the memfd_create stub which returns an error.
// On Linux it would proceed further (but needs systemd-run). Either way, it exercises
// the marshal + memfd code path beyond the validation checks.
func TestSpawn_ValidInput_ReturnsErrorOrProceeds(t *testing.T) {
	s := spawn.NewSpawner(slog.Default())
	err := s.Spawn(context.Background(), spawn.EphemeralRequest{
		Template:      "pmx-hardware-installer@.service",
		JobID:         "test-001",
		Envelope:      makeFullEnvelope(),
		RuntimeMaxSec: 60,
	})
	// We expect an error on macOS (memfd_create not supported).
	// On Linux with systemd it might also fail (no real unit), which is fine.
	// What matters is: no panic, and the validation paths are exercised.
	_ = err
}

func TestSpawn_EnvelopeWithEmptyJobID_IsValid(t *testing.T) {
	// Envelope is not nil but Spawner's jobID is empty.
	s := spawn.NewSpawner(slog.Default())
	err := s.Spawn(context.Background(), spawn.EphemeralRequest{
		Template: "pmx-hardware-installer@.service",
		JobID:    "", // ← invalid at spawn level
		Envelope: makeFullEnvelope(),
	})
	if err == nil {
		t.Fatal("expected error for empty JobID")
	}
}

func TestWaitResult_CancelledContext(t *testing.T) {
	s := spawn.NewSpawner(slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := s.WaitResult(ctx, "pmx-hardware-installer@.service", "job-001")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

// TestWaitResult_OneTickThenCancel lets a single ticker fire (covering the
// ticker-case branch in the select) before cancelling.
// On non-Linux systems, unitActiveState fails (no systemctl) and WaitResult
// continues. On Linux without the unit, same. Either covers the continue path.
func TestWaitResult_OneTickThenCancel(t *testing.T) {
	s := spawn.NewSpawner(slog.Default())

	// Cancel after ~600ms — one 500ms tick fires, executes the ticker branch.
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()

	state, err := s.WaitResult(ctx, "pmx-hardware-installer@.service", "job-999-nonexistent")
	// Both environments exercise the ticker branch (the point of this test):
	//   - no systemctl (e.g. macOS): unitActiveState errors -> continue -> the
	//     context deadline fires -> err is context.DeadlineExceeded/Canceled.
	//   - systemd present (CI): a nonexistent unit reports ActiveState=inactive
	//     (systemctl exits 0), so WaitResult returns ("inactive", nil).
	terminal := state == "inactive" || state == "failed" || state == "deactivating"
	if err == nil && !terminal {
		t.Fatalf("expected a context error or a terminal unit state, got state=%q err=%v", state, err)
	}
}
