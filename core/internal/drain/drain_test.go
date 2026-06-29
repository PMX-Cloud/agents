package drain_test

import (
	"context"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/core/internal/drain"
	"github.com/pmx-cloud/agents/core/internal/siblings"
	envpkg "github.com/pmx-cloud/agents/shared/envelope"
)

func makeManager() *siblings.Manager {
	return siblings.NewManager(
		[]string{"pmx-telemetry.service"},
		[]string{"pmx-hardware-installer@.service"},
		nil,
	)
}

func makeEnvelope(cmd string) *envpkg.Envelope {
	return &envpkg.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "drain-test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * time.Minute),
		Audience:  "pmx-core",
		Command:   cmd,
		Params:    map[string]interface{}{},
	}
}

func TestDrainer_NotDrainingInitially(t *testing.T) {
	d := drain.NewDrainer(makeManager(), func() {}, nil)
	if d.IsDraining() {
		t.Fatal("should not be draining before Handle is called")
	}
}

func TestDrainer_RejectIfDraining_NotDraining(t *testing.T) {
	d := drain.NewDrainer(makeManager(), func() {}, nil)
	payload, draining := d.RejectIfDraining()
	if draining {
		t.Fatal("should not report draining initially")
	}
	if payload != nil {
		t.Fatal("payload should be nil when not draining")
	}
}

func TestDrainer_Handle_StartsDrain(t *testing.T) {
	cancelled := make(chan struct{})
	cancelRoot := func() { close(cancelled) }
	d := drain.NewDrainer(makeManager(), cancelRoot, nil)

	result, err := d.Handle(context.Background(), makeEnvelope("core.shutdown"))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !d.IsDraining() {
		t.Fatal("should be draining after Handle")
	}

	// Wait for background drain to call cancelRoot (with short timeout).
	select {
	case <-cancelled:
		// Good: drain completed and cancelled the root context.
	case <-time.After(10 * time.Second):
		t.Fatal("drain did not complete within 10s")
	}
}

func TestDrainer_Handle_AlreadyDraining(t *testing.T) {
	d := drain.NewDrainer(makeManager(), func() {}, nil)
	d.Handle(context.Background(), makeEnvelope("core.shutdown"))

	// Second call must return already_draining.
	result, err := d.Handle(context.Background(), makeEnvelope("core.shutdown"))
	if err != nil {
		t.Fatalf("Handle (2nd): %v", err)
	}
	if string(result) == "" {
		t.Fatal("expected non-empty result")
	}
}

func TestDrainer_Status(t *testing.T) {
	d := drain.NewDrainer(makeManager(), func() {}, nil)
	if d.Status().Draining {
		t.Fatal("status should show not draining initially")
	}
}

func TestDrainer_RejectIfDraining_WhileDraining(t *testing.T) {
	d := drain.NewDrainer(makeManager(), func() {}, nil)
	d.Handle(context.Background(), makeEnvelope("core.shutdown"))

	payload, draining := d.RejectIfDraining()
	if !draining {
		t.Fatal("should report draining after Handle")
	}
	if payload == nil {
		t.Fatal("payload should not be nil when draining")
	}
}
