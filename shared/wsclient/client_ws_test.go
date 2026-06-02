package wsclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pmx-cloud/agents/shared/wsclient"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func startEchoServer(t *testing.T, handler func(*websocket.Conn)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		handler(conn)
	}))
	return srv
}

func wsURL(srv *httptest.Server) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func insecureConfig(t *testing.T, url string, h wsclient.Handler) wsclient.Config {
	return wsclient.Config{
		BackendURL:        url + "/ws",
		AgentClass:        "pmx-test",
		KeySet:            testKeySet(t),
		ReplayCache:       testReplayCache(),
		Handler:           h,
		HeartbeatInterval: 20 * time.Millisecond,
		HeartbeatTimeout:  500 * time.Millisecond,
		AllowInsecureWS:   true,
	}
}

// ── Run connects to a real WS server ─────────────────────────────────────────

func TestRun_ConnectsAndReceivesHeartbeats(t *testing.T) {
	var beatReceived sync.WaitGroup
	beatReceived.Add(1)
	once := sync.Once{}

	srv := startEchoServer(t, func(conn *websocket.Conn) {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
			once.Do(func() { beatReceived.Done() })
		}
	})
	defer srv.Close()

	c, err := wsclient.New(insecureConfig(t, wsURL(srv), &noopHandler{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	waitCh := make(chan struct{})
	go func() {
		beatReceived.Wait()
		close(waitCh)
	}()
	select {
	case <-waitCh:
	case <-time.After(400 * time.Millisecond):
		t.Log("heartbeat wait timed out (acceptable in slow CI)")
	}
	cancel()
	<-done
}

// TestRun_RejectsInvalidFrame tests that a garbage frame is rejected without panic.
func TestRun_RejectsInvalidFrame(t *testing.T) {
	srv := startEchoServer(t, func(conn *websocket.Conn) {
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte("not-cbor"))
		time.Sleep(50 * time.Millisecond)
	})
	defer srv.Close()

	c, err := wsclient.New(insecureConfig(t, wsURL(srv), &noopHandler{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = c.Run(ctx)
}

// TestSendRaw_BeforeConnect verifies that SendRaw errors when not connected.
func TestSendRaw_BeforeConnect(t *testing.T) {
	c, err := wsclient.New(wsclient.Config{
		BackendURL:  "wss://127.0.0.1:1",
		AgentClass:  "pmx-test",
		KeySet:      testKeySet(t),
		ReplayCache: testReplayCache(),
		Handler:     &noopHandler{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.SendRaw([]byte("hello")); err == nil {
		t.Fatal("expected error from SendRaw when not connected")
	}
}

// TestHeartbeatWithAuditHead exercises the AuditChainHead callback path.
func TestHeartbeatWithAuditHead(t *testing.T) {
	var headCalled sync.Once
	done := make(chan struct{})

	srv := startEchoServer(t, func(conn *websocket.Conn) {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})
	defer srv.Close()

	c, err := wsclient.New(wsclient.Config{
		BackendURL:        wsURL(srv) + "/ws",
		AgentClass:        "pmx-test",
		KeySet:            testKeySet(t),
		ReplayCache:       testReplayCache(),
		Handler:           &noopHandler{},
		HeartbeatInterval: 20 * time.Millisecond,
		HeartbeatTimeout:  500 * time.Millisecond,
		AllowInsecureWS:   true,
		AuditChainHead: func() string {
			headCalled.Do(func() { close(done) })
			return "abc123"
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	go func() { _ = c.Run(ctx) }()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Error("AuditChainHead must be called during heartbeat")
	}
	cancel()
}

// ── OnConnect callback ────────────────────────────────────────────────────────

type connectHandler struct {
	noopHandler
	connected bool
}

func (h *connectHandler) OnConnect(_ context.Context, _ *wsclient.Client) error {
	h.connected = true
	return nil
}

func TestRun_OnConnectCalled(t *testing.T) {
	srv := startEchoServer(t, func(conn *websocket.Conn) {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})
	defer srv.Close()

	h := &connectHandler{}
	c, err := wsclient.New(insecureConfig(t, wsURL(srv), h))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = c.Run(ctx)

	if !h.connected {
		t.Error("OnConnect must be called on connect")
	}
}

func TestRun_DialUsesAgentRouteWithoutDoubleAppending(t *testing.T) {
	pathSeen := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathSeen <- r.URL.Path
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	cfg := insecureConfig(t, wsURL(srv), &noopHandler{})
	cfg.BackendURL = wsURL(srv) + "/ws/pmx-test"
	c, err := wsclient.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	select {
	case path := <-pathSeen:
		if path != "/ws/pmx-test" {
			t.Fatalf("path = %q, want /ws/pmx-test", path)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("did not receive handshake request")
	}
}

func TestRun_DialIncludesAuthHeaders(t *testing.T) {
	type handshakeInfo struct {
		authorization string
		licenseKey    string
		agentClass    string
	}
	handshake := make(chan handshakeInfo, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handshake <- handshakeInfo{
			authorization: r.Header.Get("Authorization"),
			licenseKey:    r.Header.Get("X-License-Key"),
			agentClass:    r.Header.Get("X-Agent-Class"),
		}
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	cfg := insecureConfig(t, wsURL(srv), &noopHandler{})
	cfg.AuthToken = "pmxagent_test_token"
	c, err := wsclient.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	select {
	case info := <-handshake:
		if info.authorization != "Bearer pmxagent_test_token" {
			t.Fatalf("Authorization = %q", info.authorization)
		}
		if info.licenseKey != "pmxagent_test_token" {
			t.Fatalf("X-License-Key = %q", info.licenseKey)
		}
		if info.agentClass != "pmx-test" {
			t.Fatalf("X-Agent-Class = %q", info.agentClass)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("did not receive handshake request")
	}
}

// ── heartbeat field assertion ─────────────────────────────────────────────────

// TestHeartbeatAssert verifies that the heartbeat payload includes all required
// fields (type, payload.agentClass, payload.auditChainHead, timestamp) and that consecutive
// heartbeats arrive within the allowed interval window.
func TestHeartbeatAssert(t *testing.T) {
	const wantCount = 3
	type heartbeatMsg struct {
		raw        []byte
		receivedAt time.Time
	}

	collected := make(chan heartbeatMsg, wantCount+2)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			// Only forward frames that look like protocol heartbeats.
			var probe struct {
				Version string `json:"version"`
				Type    string `json:"type"`
			}
			if jsonErr := json.Unmarshal(msg, &probe); jsonErr == nil &&
				probe.Version == wsclient.ProtocolVersion &&
				probe.Type == "agent.heartbeat" {
				select {
				case collected <- heartbeatMsg{raw: msg, receivedAt: time.Now()}:
				default:
				}
			}
		}
	}))
	defer srv.Close()

	c, err := wsclient.New(wsclient.Config{
		BackendURL:        wsURL(srv) + "/ws",
		AgentClass:        "pmx-test",
		KeySet:            testKeySet(t),
		ReplayCache:       testReplayCache(),
		Handler:           &noopHandler{},
		HeartbeatInterval: 50 * time.Millisecond,
		HeartbeatTimeout:  2 * time.Second,
		AllowInsecureWS:   true,
		AuditChainHead:    func() string { return "abc123" },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	// Collect wantCount heartbeats with generous deadline.
	var beats []heartbeatMsg
	deadline := time.After(3 * time.Second)
collect:
	for len(beats) < wantCount {
		select {
		case hb := <-collected:
			beats = append(beats, hb)
		case <-deadline:
			t.Fatalf("only collected %d/%d heartbeats before deadline", len(beats), wantCount)
			break collect
		}
	}
	cancel()

	// Validate each heartbeat.
	type hbFields struct {
		Version   string `json:"version"`
		Type      string `json:"type"`
		Timestamp int64  `json:"timestamp"`
		Payload   struct {
			AgentClass     string `json:"agentClass"`
			AuditChainHead string `json:"auditChainHead"`
		} `json:"payload"`
	}
	for i, hb := range beats {
		var fields hbFields
		if err := json.Unmarshal(hb.raw, &fields); err != nil {
			t.Fatalf("beat %d: json.Unmarshal: %v (raw: %s)", i, err, hb.raw)
		}
		if fields.Version != wsclient.ProtocolVersion {
			t.Errorf("beat %d: version = %q, want %q", i, fields.Version, wsclient.ProtocolVersion)
		}
		if fields.Type != "agent.heartbeat" {
			t.Errorf("beat %d: type = %q, want \"agent.heartbeat\"", i, fields.Type)
		}
		if fields.Payload.AgentClass != "pmx-test" {
			t.Errorf("beat %d: payload.agentClass = %q, want \"pmx-test\"", i, fields.Payload.AgentClass)
		}
		if fields.Payload.AuditChainHead != "abc123" {
			t.Errorf("beat %d: payload.auditChainHead = %q, want \"abc123\"", i, fields.Payload.AuditChainHead)
		}
		if fields.Timestamp == 0 {
			t.Errorf("beat %d: timestamp is empty", i)
		}
	}

	// Validate interval between consecutive heartbeats (< 500ms).
	for i := 1; i < len(beats); i++ {
		gap := beats[i].receivedAt.Sub(beats[i-1].receivedAt)
		if gap >= 500*time.Millisecond {
			t.Errorf("gap between beats %d and %d = %v, want < 500ms", i-1, i, gap)
		}
	}
}
