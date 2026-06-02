package wsclient_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/shared/envelope"
	"github.com/pmx-cloud/agents/shared/wsclient"
)

// minimal valid KeySet / ReplayCache for construction tests.
func testKeySet(t *testing.T) *envelope.KeySet {
	t.Helper()
	ks, err := envelope.ParseKeySet("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
	if err != nil {
		t.Fatalf("ParseKeySet: %v", err)
	}
	return ks
}

func testReplayCache() *envelope.ReplayCache {
	return envelope.NewReplayCache(1024, 0) // tiny, for tests
}

type noopHandler struct{}

func (h *noopHandler) OnEnvelope(_ context.Context, _ *envelope.Envelope) ([]byte, error) {
	return nil, nil
}
func (h *noopHandler) OnConnect(_ context.Context, _ *wsclient.Client) error { return nil }

// ── New() validation ──────────────────────────────────────────────────────────

func TestNew_MissingURL(t *testing.T) {
	_, err := wsclient.New(wsclient.Config{
		AgentClass:  "pmx-test",
		KeySet:      testKeySet(t),
		ReplayCache: testReplayCache(),
		Handler:     &noopHandler{},
	})
	if err == nil {
		t.Fatal("expected error for missing BackendURL")
	}
}

func TestNew_NonWSSURL(t *testing.T) {
	_, err := wsclient.New(wsclient.Config{
		BackendURL:  "ws://insecure",
		AgentClass:  "pmx-test",
		KeySet:      testKeySet(t),
		ReplayCache: testReplayCache(),
		Handler:     &noopHandler{},
	})
	if err == nil {
		t.Fatal("expected error for non-wss:// URL")
	}
}

func TestNew_MissingAgentClass(t *testing.T) {
	_, err := wsclient.New(wsclient.Config{
		BackendURL:  "wss://api.example.com/ws",
		KeySet:      testKeySet(t),
		ReplayCache: testReplayCache(),
		Handler:     &noopHandler{},
	})
	if err == nil {
		t.Fatal("expected error for missing AgentClass")
	}
}

func TestNew_MissingKeySet(t *testing.T) {
	_, err := wsclient.New(wsclient.Config{
		BackendURL:  "wss://api.example.com/ws",
		AgentClass:  "pmx-test",
		ReplayCache: testReplayCache(),
		Handler:     &noopHandler{},
	})
	if err == nil {
		t.Fatal("expected error for missing KeySet")
	}
}

func TestNew_MissingReplayCache(t *testing.T) {
	_, err := wsclient.New(wsclient.Config{
		BackendURL: "wss://api.example.com/ws",
		AgentClass: "pmx-test",
		KeySet:     testKeySet(t),
		Handler:    &noopHandler{},
	})
	if err == nil {
		t.Fatal("expected error for missing ReplayCache")
	}
}

func TestNew_MissingHandler(t *testing.T) {
	_, err := wsclient.New(wsclient.Config{
		BackendURL:  "wss://api.example.com/ws",
		AgentClass:  "pmx-test",
		KeySet:      testKeySet(t),
		ReplayCache: testReplayCache(),
	})
	if err == nil {
		t.Fatal("expected error for missing Handler")
	}
}

func TestNew_ValidConfig(t *testing.T) {
	c, err := wsclient.New(wsclient.Config{
		BackendURL:  "wss://api.example.com/ws",
		AgentClass:  "pmx-test",
		KeySet:      testKeySet(t),
		ReplayCache: testReplayCache(),
		Handler:     &noopHandler{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNew_DefaultsApplied(t *testing.T) {
	// Zero HeartbeatInterval must be filled with the default.
	c, err := wsclient.New(wsclient.Config{
		BackendURL:  "wss://api.example.com/ws",
		AgentClass:  "pmx-test",
		KeySet:      testKeySet(t),
		ReplayCache: testReplayCache(),
		Handler:     &noopHandler{},
		// HeartbeatInterval deliberately not set
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = c
}

// ── Run cancels immediately ───────────────────────────────────────────────────

func TestRun_CancelledContext(t *testing.T) {
	c, err := wsclient.New(wsclient.Config{
		BackendURL:  "wss://127.0.0.1:1", // nothing listening; will fail dial
		AgentClass:  "pmx-test",
		KeySet:      testKeySet(t),
		ReplayCache: testReplayCache(),
		Handler:     &noopHandler{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	err = c.Run(ctx)
	// Must return context.Canceled — not hang.
	if err == nil {
		t.Fatal("expected error from Run with cancelled ctx")
	}
}

// ── Constants sanity ─────────────────────────────────────────────────────────

func TestConstants(t *testing.T) {
	if wsclient.DefaultHeartbeatInterval == 0 {
		t.Fatal("DefaultHeartbeatInterval must not be zero")
	}
	if wsclient.BackoffMin >= wsclient.BackoffMax {
		t.Fatal("BackoffMin must be less than BackoffMax")
	}
	if wsclient.MaxMessageBytes <= 0 {
		t.Fatal("MaxMessageBytes must be positive")
	}
}
