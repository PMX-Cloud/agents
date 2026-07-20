package wire_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/core/internal/wire"
	"github.com/pmx-cloud/agents/shared/envelope"
)

func makeEnvelope(command string) *envelope.Envelope {
	return &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "test-job-1",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * time.Minute),
		Audience:  "pmx-core",
		Command:   command,
		Params:    map[string]interface{}{},
	}
}

func TestRouter_RegisterAndDispatch(t *testing.T) {
	r := wire.NewRouter(nil)
	r.Register("core.ping", func(ctx context.Context, env *envelope.Envelope) (json.RawMessage, error) {
		return json.RawMessage(`{"ok":true}`), nil
	})

	result, err := r.Dispatch(context.Background(), makeEnvelope("core.ping"))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	var m map[string]bool
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !m["ok"] {
		t.Fatal("expected ok:true")
	}
}

func TestRouter_UnknownCommand(t *testing.T) {
	r := wire.NewRouter(nil)
	result, err := r.Dispatch(context.Background(), makeEnvelope("core.does.not.exist"))
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
	var ukErr *wire.ErrUnknownCommand
	if !errors.As(err, &ukErr) {
		t.Fatalf("expected ErrUnknownCommand, got %T: %v", err, err)
	}
	if ukErr.Command != "core.does.not.exist" {
		t.Fatalf("wrong command in error: %q", ukErr.Command)
	}
	// result should be a JSON error payload
	var payload map[string]string
	if err2 := json.Unmarshal(result, &payload); err2 != nil {
		t.Fatalf("result should be JSON: %v", err2)
	}
	if payload["error"] != "UNKNOWN_COMMAND" {
		t.Fatalf("wrong error code: %q", payload["error"])
	}
}

func TestRouter_DuplicateRegisterPanics(t *testing.T) {
	r := wire.NewRouter(nil)
	r.Register("core.dup", func(ctx context.Context, env *envelope.Envelope) (json.RawMessage, error) {
		return nil, nil
	})
	defer func() {
		if rec := recover(); rec == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	r.Register("core.dup", func(ctx context.Context, env *envelope.Envelope) (json.RawMessage, error) {
		return nil, nil
	})
}

func TestRouter_Commands(t *testing.T) {
	r := wire.NewRouter(nil)
	r.Register("core.a", func(ctx context.Context, env *envelope.Envelope) (json.RawMessage, error) { return nil, nil })
	r.Register("core.b", func(ctx context.Context, env *envelope.Envelope) (json.RawMessage, error) { return nil, nil })
	cmds := r.Commands()
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
}
