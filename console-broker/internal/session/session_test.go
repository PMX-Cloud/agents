package session_test

import (
	"strings"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/console-broker/internal/session"
	envpkg "github.com/pmx-cloud/agents/shared/envelope"
)

func TestFromEnvelope_Valid(t *testing.T) {
	t.Parallel()

	env := &envpkg.Envelope{
		JobID:     "job-1",
		Command:   "console.open",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Params: map[string]any{
			"vmId":            101,
			"displayProtocol": "vnc",
			"sessionToken":    "token-abc",
			"backendWsUrl":    "wss://api.pmxcloud.example/ws/agent/console/session-1",
		},
	}

	req, err := session.FromEnvelope(env, 100, []string{".pmxcloud.example"})
	if err != nil {
		t.Fatalf("FromEnvelope() error = %v", err)
	}
	if req.VMID != 101 {
		t.Fatalf("vmid = %d", req.VMID)
	}
	if req.RateLimitMbps != 100 {
		t.Fatalf("rate limit = %d", req.RateLimitMbps)
	}
}

func TestFromEnvelope_RejectsUnsupportedCommand(t *testing.T) {
	t.Parallel()

	env := &envpkg.Envelope{Command: "other", ExpiresAt: time.Now().Add(time.Minute)}
	_, err := session.FromEnvelope(env, 100, nil)
	if err == nil {
		t.Fatal("expected unsupported command error")
	}
}

func TestFromEnvelope_RejectsNonWSS(t *testing.T) {
	t.Parallel()

	env := &envpkg.Envelope{
		Command:   "console.open",
		ExpiresAt: time.Now().Add(time.Minute),
		Params: map[string]any{
			"vmId":            101,
			"displayProtocol": "vnc",
			"sessionToken":    "token-abc",
			"backendWsUrl":    "ws://localhost/ws/agent/console/session-1",
		},
	}
	_, err := session.FromEnvelope(env, 100, nil)
	if err == nil {
		t.Fatal("expected non-wss rejection")
	}
}

func TestFromEnvelope_RequiresBackendHostAllowlist(t *testing.T) {
	t.Parallel()

	env := validEnvelope()
	_, err := session.FromEnvelope(env, 100, nil)
	if err == nil || !strings.Contains(err.Error(), "allowed suffixes") {
		t.Fatalf("expected allowlist error, got %v", err)
	}
}

func TestFromEnvelope_RejectsConsolePathWithExtraSegments(t *testing.T) {
	t.Parallel()

	env := validEnvelope()
	env.Params["backendWsUrl"] = "wss://api.pmxcloud.example/ws/agent/console/session-1/extra"
	_, err := session.FromEnvelope(env, 100, []string{".pmxcloud.example"})
	if err == nil {
		t.Fatal("expected backend path rejection")
	}
}

func validEnvelope() *envpkg.Envelope {
	return &envpkg.Envelope{
		JobID:     "job-1",
		Command:   "console.open",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Params: map[string]any{
			"vmId":            101,
			"displayProtocol": "vnc",
			"sessionToken":    "token-abc",
			"backendWsUrl":    "wss://api.pmxcloud.example/ws/agent/console/session-1",
		},
	}
}
