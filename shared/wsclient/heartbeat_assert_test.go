/*
Package wsclient_test provides heartbeat assertion tests per agent (Phase D4).

A shared helper RecordHeartbeats connects to a mock WS server and captures
heartbeat frames. Per-agent parameterised assertions verify:
  - interval ≈ 15s ±1s
  - auditChainHead non-empty + monotonic
  - agentClass matches expected value
*/
package wsclient_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pmx-cloud/agents/shared/envelope"
	"github.com/pmx-cloud/agents/shared/wsclient"
)

// heartbeatFrame is the JSON structure of an agent.heartbeat frame.
type heartbeatFrame struct {
	Version   string `json:"version"`
	Type      string `json:"type"`
	Timestamp int64  `json:"timestamp"`
	Payload   struct {
		AgentClass     string `json:"agentClass"`
		AuditChainHead string `json:"auditChainHead"`
	} `json:"payload"`
}

// recordedHeartbeat holds one captured heartbeat.
type recordedHeartbeat struct {
	ReceivedAt     time.Time
	Frame          heartbeatFrame
	AuditChainHead string
}

// RecordHeartbeats connects a wsclient to the given WS server and records
// heartbeats for the specified duration. It returns the captured heartbeats.
func RecordHeartbeats(ctx context.Context, t *testing.T, server *httptest.Server, agentClass string, auditHead func() string, dur time.Duration) []recordedHeartbeat {
	t.Helper()

	ks, _ := mustGenerateKeySet(t)
	rc := envelope.NewReplayCache(1000, 24*time.Hour)

	cfg := wsclient.Config{
		BackendURL:        "ws://" + strings.TrimPrefix(server.URL, "http://"),
		AgentClass:        agentClass,
		KeySet:            ks,
		ReplayCache:       rc,
		HostFingerprint:   "test-fingerprint",
		HeartbeatInterval: 15 * time.Second,
		AuditChainHead:    auditHead,
		AllowInsecureWS:   true,
		Handler:           &noopHandler{},
	}

	client, err := wsclient.New(cfg)
	if err != nil {
		t.Fatalf("wsclient.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()

	// Capture heartbeats from the server side.
	var mu sync.Mutex
	var beats []recordedHeartbeat

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		go func() {
			<-ctx.Done()
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(time.Second))
		}()

		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var frame heartbeatFrame
			if err := json.Unmarshal(msg, &frame); err != nil {
				continue
			}
			if frame.Type == "agent.heartbeat" {
				mu.Lock()
				beats = append(beats, recordedHeartbeat{
					ReceivedAt:     time.Now(),
					Frame:          frame,
					AuditChainHead: frame.Payload.AuditChainHead,
				})
				mu.Unlock()
			}
		}
	})

	go func() { _ = client.Run(ctx) }()

	// Wait for the duration to elapse.
	<-ctx.Done()

	mu.Lock()
	defer mu.Unlock()
	return beats
}

// mustGenerateKeySet creates a test keyset with one Ed25519 key.
func mustGenerateKeySet(t *testing.T) (*envelope.KeySet, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	ks, err := envelope.ParseKeySet(hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("parse keyset: %v", err)
	}
	return ks, priv
}

// agentHeartbeatParams is the parameter set for per-agent heartbeat tests.
type agentHeartbeatParams struct {
	AgentClass string
}

// allAgents returns the 10 fleet agents for parameterised testing.
func allAgents() []agentHeartbeatParams {
	return []agentHeartbeatParams{
		{AgentClass: "pmx-core"},
		{AgentClass: "pmx-telemetry"},
		{AgentClass: "pmx-hypervisor"},
		{AgentClass: "pmx-storage"},
		{AgentClass: "pmx-network"},
		{AgentClass: "pmx-security"},
		{AgentClass: "pmx-backup"},
		{AgentClass: "pmx-console-broker"},
		{AgentClass: "pmx-hardware-installer"},
		{AgentClass: "pmx-updater"},
	}
}

// TestHeartbeatAssertionPerAgent verifies heartbeat properties for each agent.
func TestHeartbeatAssertionPerAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heartbeat assertion in short mode")
	}

	for _, agent := range allAgents() {
		t.Run(agent.AgentClass, func(t *testing.T) {
			t.Parallel()

			// Simulated audit chain head that increments each call.
			callCount := 0
			auditHead := func() string {
				callCount++
				return fmt.Sprintf("sha256-%s-audit-%d", agent.AgentClass, callCount)
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			defer server.Close()

			beats := RecordHeartbeats(context.Background(), t, server, agent.AgentClass, auditHead, 50*time.Second)

			if len(beats) < 2 {
				t.Fatalf("expected ≥2 heartbeats, got %d (agent may not have connected)", len(beats))
			}

			// 1. Verify agentClass matches.
			for i, b := range beats {
				if b.Frame.Payload.AgentClass != agent.AgentClass {
					t.Errorf("beat[%d]: agentClass = %q, want %q", i, b.Frame.Payload.AgentClass, agent.AgentClass)
				}
			}

			// 2. Verify interval ≈ 15s ±1s between consecutive heartbeats.
			for i := 1; i < len(beats); i++ {
				gap := beats[i].ReceivedAt.Sub(beats[i-1].ReceivedAt)
				if gap < 14*time.Second || gap > 16*time.Second {
					t.Errorf("beat[%d→%d]: interval = %v, want ≈15s±1s", i-1, i, gap)
				}
			}

			// 3. Verify auditChainHead is non-empty and monotonic.
			for i, b := range beats {
				if b.AuditChainHead == "" {
					t.Errorf("beat[%d]: auditChainHead is empty", i)
				}
				if i > 0 && b.AuditChainHead <= beats[i-1].AuditChainHead {
					t.Errorf("beat[%d]: auditChainHead %q not monotonic after %q",
						i, b.AuditChainHead, beats[i-1].AuditChainHead)
				}
			}
		})
	}
}
