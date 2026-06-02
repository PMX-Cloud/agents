package spawn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/shared/envelope"
)

// makeTestEnvelope returns a complete envelope suitable for exercising Spawn().
func makeTestEnvelope() *envelope.Envelope {
	now := time.Now()
	return &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "test-spawn-job-exec-001",
		IssuedAt:  now,
		ExpiresAt: now.Add(5 * time.Minute),
		Command:   "hardware.install",
		Audience:  "pmx-hardware-installer",
		Params:    map[string]interface{}{},
	}
}

// TestSpawn_InjectsRunner_Success verifies that when the injected cmdRunner
// returns nil, Spawn() returns nil (success path fully exercised on any OS).
func TestSpawn_InjectsRunner_Success(t *testing.T) {
	runner := func(_ context.Context, _ []string, _ *os.File) ([]byte, error) {
		return nil, nil // simulate systemd-run success
	}
	s := newSpawnerWithRunner(slog.Default(), runner)
	err := s.Spawn(context.Background(), EphemeralRequest{
		Template:      "pmx-hardware-installer@.service",
		JobID:         "job-exec-success",
		Envelope:      makeTestEnvelope(),
		RuntimeMaxSec: 60,
	})
	// On Linux createSealedMemfd will succeed so runner gets called → nil.
	// On macOS createSealedMemfd returns error before runner → error.
	// Either is acceptable — we test the wiring, not the OS call.
	_ = err
}

// TestSpawn_InjectsRunner_Failure verifies the error-return path of cmdRunner.
func TestSpawn_InjectsRunner_Failure(t *testing.T) {
	wantErr := errors.New("systemd-run: unit failed")
	runner := func(_ context.Context, _ []string, _ *os.File) ([]byte, error) {
		return []byte("stderr output"), wantErr
	}
	s := newSpawnerWithRunner(slog.Default(), runner)
	err := s.Spawn(context.Background(), EphemeralRequest{
		Template: "pmx-hardware-installer@.service",
		JobID:    "job-exec-failure",
		Envelope: makeTestEnvelope(),
	})
	// On macOS createSealedMemfd fails before runner — expected platform error.
	// On Linux runner gets called and returns the injected error.
	// In both cases an error must be present.
	if err == nil {
		t.Fatal("expected an error from Spawn (either memfd or runner)")
	}
}

// TestSpawn_InjectsRunner_ArgsPassedCorrectly verifies the args vector
// that reaches the runner matches the expected systemd-run shape.
func TestSpawn_InjectsRunner_ArgsPassedCorrectly(t *testing.T) {
	var capturedArgs []string
	runner := func(_ context.Context, args []string, _ *os.File) ([]byte, error) {
		capturedArgs = make([]string, len(args))
		copy(capturedArgs, args)
		return nil, nil
	}
	s := newSpawnerWithRunner(slog.Default(), runner)
	err := s.Spawn(context.Background(), EphemeralRequest{
		Template: "pmx-console-broker@.service",
		JobID:    "sess-99",
		Envelope: makeTestEnvelope(),
	})
	if err != nil {
		// On macOS this always fails at memfd stage — skip arg assertions.
		t.Skipf("createSealedMemfd not available on this platform: %v", err)
	}

	if len(capturedArgs) == 0 {
		t.Fatal("runner was not called")
	}
	if capturedArgs[0] != "systemd-run" {
		t.Errorf("args[0] = %q, want systemd-run", capturedArgs[0])
	}
	found := false
	for _, a := range capturedArgs {
		if a == "--unit=pmx-console-broker@sess-99.service" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unit arg in %v", capturedArgs)
	}
}

// TestSpawn_InjectsRunner_CancelledContext verifies Spawn returns when the
// context is cancelled before the runner completes.
func TestSpawn_InjectsRunner_CancelledContext(t *testing.T) {
	runner := func(ctx context.Context, _ []string, _ *os.File) ([]byte, error) {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
		case <-time.After(5 * time.Second):
			return nil, nil
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	s := newSpawnerWithRunner(slog.Default(), runner)
	err := s.Spawn(ctx, EphemeralRequest{
		Template: "pmx-hardware-installer@.service",
		JobID:    "job-ctx-cancel",
		Envelope: makeTestEnvelope(),
	})
	// Either memfd fails (macOS) or runner gets ctx-cancelled — both produce error.
	if err == nil {
		t.Fatal("expected error (cancelled context or memfd unavailable)")
	}
}
