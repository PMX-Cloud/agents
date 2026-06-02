package spawn

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/shared/envelope"
)

// tmpfileMemfd is a non-Linux substitute for createSealedMemfd: it writes the
// bytes to a tempfile and returns the file descriptor. This lets dev machines
// exercise the full Spawn() happy path without memfd_create.
func tmpfileMemfd(b []byte) (int, error) {
	f, err := os.CreateTemp("", "pmx-spawn-test-*.envelope")
	if err != nil {
		return -1, err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(f.Name())
		return -1, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		os.Remove(f.Name())
		return -1, err
	}
	// Returning the fd transfers ownership; Spawn() wraps and closes it.
	return int(f.Fd()), nil
}

func okEnvelope() *envelope.Envelope {
	now := time.Now()
	return &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "happy-001",
		IssuedAt:  now,
		ExpiresAt: now.Add(5 * time.Minute),
		Command:   "hardware.install",
		Audience:  "pmx-hardware-installer",
		Params:    map[string]interface{}{},
	}
}

func TestSpawn_FullHappyPath(t *testing.T) {
	var gotArgs []string
	var gotFD *os.File
	runner := func(_ context.Context, args []string, fd *os.File) ([]byte, error) {
		gotArgs = append([]string(nil), args...)
		gotFD = fd
		return nil, nil
	}
	s := newSpawnerWithRunnerAndMemfd(slog.Default(), runner, tmpfileMemfd)
	err := s.Spawn(context.Background(), EphemeralRequest{
		Template:      "pmx-hardware-installer@.service",
		JobID:         "happy-001",
		Envelope:      okEnvelope(),
		RuntimeMaxSec: 60,
	})
	if err != nil {
		t.Fatalf("Spawn returned error: %v", err)
	}
	if len(gotArgs) == 0 || gotArgs[0] != "systemd-run" {
		t.Fatalf("expected systemd-run as args[0], got %v", gotArgs)
	}
	if gotFD == nil {
		t.Fatal("runner did not receive extra file")
	}
}

func TestSpawn_RunnerErrorIsWrapped(t *testing.T) {
	want := errors.New("systemd-run boom")
	runner := func(_ context.Context, _ []string, _ *os.File) ([]byte, error) {
		return []byte("stderr"), want
	}
	s := newSpawnerWithRunnerAndMemfd(slog.Default(), runner, tmpfileMemfd)
	err := s.Spawn(context.Background(), EphemeralRequest{
		Template: "pmx-hardware-installer@.service",
		JobID:    "boom-001",
		Envelope: okEnvelope(),
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, want) {
		t.Fatalf("expected wrapped error %v, got %v", want, err)
	}
}

func TestSpawn_MemfdErrorBubbles(t *testing.T) {
	failMemfd := func([]byte) (int, error) {
		return -1, errors.New("memfd: nope")
	}
	runnerNotCalled := func(_ context.Context, _ []string, _ *os.File) ([]byte, error) {
		t.Fatal("runner must not be called when memfd fails")
		return nil, nil
	}
	s := newSpawnerWithRunnerAndMemfd(slog.Default(), runnerNotCalled, failMemfd)
	err := s.Spawn(context.Background(), EphemeralRequest{
		Template: "pmx-hardware-installer@.service",
		JobID:    "memfd-fail-001",
		Envelope: okEnvelope(),
	})
	if err == nil {
		t.Fatal("expected memfd error")
	}
}

func TestSpawn_ConsoleBrokerProfileWiresAppArmor(t *testing.T) {
	var gotArgs []string
	runner := func(_ context.Context, args []string, _ *os.File) ([]byte, error) {
		gotArgs = append([]string(nil), args...)
		return nil, nil
	}
	s := newSpawnerWithRunnerAndMemfd(slog.Default(), runner, tmpfileMemfd)
	err := s.Spawn(context.Background(), EphemeralRequest{
		Template: "pmx-console-broker@.service",
		JobID:    "sess-77",
		Envelope: okEnvelope(),
	})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	hasAA := false
	for _, a := range gotArgs {
		if a == "--property=AppArmorProfile=pmx-console-broker" {
			hasAA = true
		}
	}
	if !hasAA {
		t.Fatalf("expected AppArmorProfile arg for console-broker, got %v", gotArgs)
	}
}
