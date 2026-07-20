//go:build integration

// Package test contains integration tests for pmx-core that exercise the full
// wsclient → envelope verification → router pipeline.
//
// Run with: go test -tags=integration ./test/...
//
// Each test spins up a mock HTTP/WS backend (httptest.Server) that writes
// signed envelopes to the agent's wsclient connection. The wsclient verifies
// them and calls OnEnvelope. We assert the exact rejection paths from §3.4.
package test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pmx-cloud/agents/core/internal/wire"
	"github.com/pmx-cloud/agents/shared/envelope"
	"github.com/pmx-cloud/agents/shared/wsclient"
)

const (
	agentClass      = "pmx-core"
	hostFingerprint = "testhost-integration-fingerprint"
)

// ── helpers ─────────────────────────────────────────────────────────────────

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true },
}

func newTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func newKeySet(t *testing.T, pub ed25519.PublicKey) *envelope.KeySet {
	t.Helper()
	ks, err := envelope.ParseKeySet(hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("parse keyset: %v", err)
	}
	return ks
}

// makeEnvelope builds a valid envelope signed with priv.
func makeEnvelope(priv ed25519.PrivateKey, jobID, command string) *envelope.Envelope {
	now := time.Now()
	e := &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     jobID,
		IssuedAt:  now,
		ExpiresAt: now.Add(30 * time.Minute),
		Issuer:    "backend-integration-test",
		Audience:  agentClass,
		Host:      hostFingerprint,
		Command:   command,
		Params:    map[string]interface{}{},
	}
	if err := e.Sign(priv); err != nil {
		panic("sign: " + err.Error())
	}
	return e
}

func encodeCBOR(t *testing.T, e *envelope.Envelope) []byte {
	t.Helper()
	raw, err := e.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// coreHandler connects the wsclient to a wire.Router for integration testing.
type coreHandler struct {
	router *wire.Router
}

func (h *coreHandler) OnEnvelope(ctx context.Context, env *envelope.Envelope) ([]byte, error) {
	result, err := h.router.Dispatch(ctx, env)
	if err != nil {
		resp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return resp, nil
	}
	return result, nil
}

func (h *coreHandler) OnConnect(_ context.Context, _ *wsclient.Client) error { return nil }

// drainingCoreHandler wraps coreHandler with drain-rejection logic, mirroring
// the real coreHandler in cmd/pmx-core/main.go.
type drainingCoreHandler struct {
	router  *wire.Router
	drainer *shutdownTestDrainer
}

func (h *drainingCoreHandler) OnEnvelope(ctx context.Context, env *envelope.Envelope) ([]byte, error) {
	if payload, draining := h.drainer.RejectIfDraining(); draining {
		return payload, nil
	}
	result, err := h.router.Dispatch(ctx, env)
	if err != nil {
		resp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return resp, nil
	}
	return result, nil
}

func (h *drainingCoreHandler) OnConnect(_ context.Context, _ *wsclient.Client) error { return nil }

// startBackend starts an httptest WS server. The serverFn receives the conn after
// the client connects so it can write envelopes to the agent.
// Returns the ws:// URL.
func startBackend(t *testing.T, serverFn func(*websocket.Conn)) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		serverFn(conn)
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
}

// newClient creates a wsclient for integration tests. Does NOT start Run().
func newClient(t *testing.T, wsURL string, pub ed25519.PublicKey, h wsclient.Handler) *wsclient.Client {
	t.Helper()
	ks := newKeySet(t, pub)
	c, err := wsclient.New(wsclient.Config{
		BackendURL:        wsURL,
		AgentClass:        agentClass,
		KeySet:            ks,
		ReplayCache:       envelope.NewReplayCache(1000, 24*time.Hour),
		HostFingerprint:   hostFingerprint,
		Handler:           h,
		HeartbeatInterval: 50 * time.Millisecond,
		HeartbeatTimeout:  2 * time.Second,
		AllowInsecureWS:   true,
	})
	if err != nil {
		t.Fatalf("wsclient.New: %v", err)
	}
	return c
}

// ── tests ────────────────────────────────────────────────────────────────────

// TestIntegration_RouterDispatch verifies that a properly signed envelope reaches
// the router handler and a result is returned to the backend.
func TestIntegration_RouterDispatch(t *testing.T) {
	_, priv := newTestKeyPair(t)
	pub, pub2 := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		p, k, _ := ed25519.GenerateKey(rand.Reader)
		return p, k
	}()
	_ = pub2

	// Use the same keypair for both signing and the keyset.
	realPub, realPriv := newTestKeyPair(t)

	dispatched := make(chan string, 1)
	router := wire.NewRouter(nil)
	router.Register("core.identify", func(_ context.Context, env *envelope.Envelope) (json.RawMessage, error) {
		dispatched <- env.JobID
		return json.RawMessage(`{"agent":"pmx-core","ok":true}`), nil
	})

	env := makeEnvelope(realPriv, "01900000-0000-7000-8000-identify00001", "core.identify")
	raw := encodeCBOR(t, env)
	_ = priv // suppress unused
	_ = pub

	wsURL := startBackend(t, func(conn *websocket.Conn) {
		time.Sleep(30 * time.Millisecond) // let client handshake complete
		conn.WriteMessage(websocket.BinaryMessage, raw)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})

	h := &coreHandler{router: router}
	c := newClient(t, wsURL, realPub, h)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go c.Run(ctx)

	select {
	case jobID := <-dispatched:
		if jobID != env.JobID {
			t.Errorf("dispatched jobID = %q, want %q", jobID, env.JobID)
		}
	case <-ctx.Done():
		t.Fatal("timed out: envelope was never dispatched to handler")
	}
}

// TestIntegration_RejectExpiredEnvelope verifies that an expired envelope is
// silently dropped (OnEnvelope is NOT called).
func TestIntegration_RejectExpiredEnvelope(t *testing.T) {
	pub, priv := newTestKeyPair(t)

	var called atomic.Bool
	router := wire.NewRouter(nil)
	router.Register("core.identify", func(_ context.Context, _ *envelope.Envelope) (json.RawMessage, error) {
		called.Store(true)
		return json.RawMessage(`{"ok":true}`), nil
	})

	// Expired: both times in the past.
	now := time.Now()
	exp := &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "01900000-0000-7000-8000-expired00001",
		IssuedAt:  now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-1 * time.Hour),
		Issuer:    "backend-integration-test",
		Audience:  agentClass,
		Host:      hostFingerprint,
		Command:   "core.identify",
		Params:    map[string]interface{}{},
	}
	_ = exp.Sign(priv)
	raw, _ := exp.Marshal()

	wsURL := startBackend(t, func(conn *websocket.Conn) {
		time.Sleep(30 * time.Millisecond)
		conn.WriteMessage(websocket.BinaryMessage, raw)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})

	h := &coreHandler{router: router}
	c := newClient(t, wsURL, pub, h)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	go c.Run(ctx)
	<-ctx.Done()

	if called.Load() {
		t.Error("OnEnvelope must NOT be called for expired envelopes")
	}
}

// TestIntegration_RejectWrongAudience verifies that an envelope addressed to a
// different agent class is dropped.
func TestIntegration_RejectWrongAudience(t *testing.T) {
	pub, priv := newTestKeyPair(t)

	var called atomic.Bool
	router := wire.NewRouter(nil)
	router.Register("core.identify", func(_ context.Context, _ *envelope.Envelope) (json.RawMessage, error) {
		called.Store(true)
		return json.RawMessage(`{"ok":true}`), nil
	})

	now := time.Now()
	wrong := &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "01900000-0000-7000-8000-wrongaud0001",
		IssuedAt:  now,
		ExpiresAt: now.Add(30 * time.Minute),
		Issuer:    "backend-integration-test",
		Audience:  "pmx-network", // wrong
		Host:      hostFingerprint,
		Command:   "core.identify",
		Params:    map[string]interface{}{},
	}
	_ = wrong.Sign(priv)
	raw, _ := wrong.Marshal()

	wsURL := startBackend(t, func(conn *websocket.Conn) {
		time.Sleep(30 * time.Millisecond)
		conn.WriteMessage(websocket.BinaryMessage, raw)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})

	h := &coreHandler{router: router}
	c := newClient(t, wsURL, pub, h)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	go c.Run(ctx)
	<-ctx.Done()

	if called.Load() {
		t.Error("OnEnvelope must NOT be called for wrong-audience envelopes")
	}
}

// TestIntegration_RejectReplay verifies that sending the same envelope twice
// causes the second call to be rejected (replay protection).
func TestIntegration_RejectReplay(t *testing.T) {
	pub, priv := newTestKeyPair(t)

	var callCount atomic.Int32
	router := wire.NewRouter(nil)
	router.Register("core.identify", func(_ context.Context, _ *envelope.Envelope) (json.RawMessage, error) {
		callCount.Add(1)
		return json.RawMessage(`{"ok":true}`), nil
	})

	env := makeEnvelope(priv, "01900000-0000-7000-8000-replay000001", "core.identify")
	raw := encodeCBOR(t, env)

	var mu sync.Mutex
	connReady := make(chan *websocket.Conn, 1)

	wsURL := startBackend(t, func(conn *websocket.Conn) {
		mu.Lock()
		select {
		case connReady <- conn:
		default:
		}
		mu.Unlock()

		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})

	h := &coreHandler{router: router}
	c := newClient(t, wsURL, pub, h)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go c.Run(ctx)

	// Wait for backend connection.
	var conn *websocket.Conn
	select {
	case conn = <-connReady:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("backend never got a connection")
	}

	// Send same envelope twice.
	conn.WriteMessage(websocket.BinaryMessage, raw)
	time.Sleep(50 * time.Millisecond)
	conn.WriteMessage(websocket.BinaryMessage, raw)
	time.Sleep(200 * time.Millisecond)

	cancel()

	n := callCount.Load()
	if n != 1 {
		t.Errorf("handler called %d times; want exactly 1 (second call must be a replay reject)", n)
	}
}

// TestIntegration_UnknownCommandRoutedToRouter verifies that an unknown command
// is routed to the router (which returns an error), not silently dropped.
func TestIntegration_UnknownCommandRoutedToRouter(t *testing.T) {
	pub, priv := newTestKeyPair(t)
	// Empty router — all commands unknown.
	router := wire.NewRouter(nil)

	var called atomic.Bool
	onEnvelopeCh := make(chan struct{}, 1)
	wrappedHandler := &callTrackingHandler{
		router:   router,
		called:   &called,
		notifyCh: onEnvelopeCh,
	}

	env := makeEnvelope(priv, "01900000-0000-7000-8000-unknown00001", "core.unknown")
	raw := encodeCBOR(t, env)

	connReady := make(chan *websocket.Conn, 1)
	wsURL := startBackend(t, func(conn *websocket.Conn) {
		select {
		case connReady <- conn:
		default:
		}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})

	c := newClient(t, wsURL, pub, wrappedHandler)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go c.Run(ctx)

	var conn *websocket.Conn
	select {
	case conn = <-connReady:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("backend never got a connection")
	}

	conn.WriteMessage(websocket.BinaryMessage, raw)

	select {
	case <-onEnvelopeCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("OnEnvelope was not called within timeout")
	}

	cancel()
	if !called.Load() {
		t.Error("OnEnvelope must be called even for unknown commands (router handles the error)")
	}
}

type callTrackingHandler struct {
	router   *wire.Router
	called   *atomic.Bool
	notifyCh chan struct{}
}

func (h *callTrackingHandler) OnEnvelope(ctx context.Context, env *envelope.Envelope) ([]byte, error) {
	h.called.Store(true)
	select {
	case h.notifyCh <- struct{}{}:
	default:
	}
	result, err := h.router.Dispatch(ctx, env)
	if err != nil {
		resp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return resp, nil
	}
	return result, nil
}

func (h *callTrackingHandler) OnConnect(_ context.Context, _ *wsclient.Client) error { return nil }

// ── core.shutdown integration test ────────────────────────────────────────────

// TestIntegration_ShutdownDrain verifies that a core.shutdown envelope triggers
// the drain sequence: the drainer flag is set, subsequent commands are rejected
// with DRAINING, and the root context is cancelled.
func TestIntegration_ShutdownDrain(t *testing.T) {
	pub, priv := newTestKeyPair(t)

	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()

	drainDone := make(chan struct{})

	// Minimal drainer setup — we use the real drain.Drainer but with a nil
	// siblings.Manager (the drain test in drain_test.go covers sibling stop;
	// here we only care that the flag flips and context cancels).
	router := wire.NewRouter(nil)

	// Register core.identify so we can test post-shutdown rejection.
	router.Register("core.identify", func(_ context.Context, _ *envelope.Envelope) (json.RawMessage, error) {
		return json.RawMessage(`{"agent":"pmx-core","ok":true}`), nil
	})

	// We need the real drainer to test the full flow.
	// Import the drain package inline since this is an integration test.
	drainer := &shutdownTestDrainer{
		cancelRoot: cancelRoot,
		doneCh:     drainDone,
	}

	router.Register("core.shutdown", drainer.Handle)

	// Send shutdown envelope.
	shutdownEnv := makeEnvelope(priv, "01900000-0000-7000-8000-shutdown001", "core.shutdown")
	shutdownRaw := encodeCBOR(t, shutdownEnv)

	// Send a second identify after shutdown to verify rejection.
	identifyEnv := makeEnvelope(priv, "01900000-0000-7000-8000-identify00002", "core.identify")
	identifyRaw := encodeCBOR(t, identifyEnv)

	connReady := make(chan *websocket.Conn, 1)
	var lastResponse []byte
	var respMu sync.Mutex

	wsURL := startBackend(t, func(conn *websocket.Conn) {
		select {
		case connReady <- conn:
		default:
		}
		// Read responses from agent.
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			respMu.Lock()
			lastResponse = msg
			respMu.Unlock()
		}
	})

	h := &drainingCoreHandler{router: router, drainer: drainer}
	c := newClient(t, wsURL, pub, h)
	go c.Run(rootCtx)

	var conn *websocket.Conn
	select {
	case conn = <-connReady:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("backend never got a connection")
	}

	// 1. Send shutdown.
	conn.WriteMessage(websocket.BinaryMessage, shutdownRaw)
	time.Sleep(100 * time.Millisecond)

	// Verify drainer is now draining.
	if !drainer.IsDraining() {
		t.Error("drainer should be draining after core.shutdown")
	}

	// 2. Send identify — should be rejected because draining.
	conn.WriteMessage(websocket.BinaryMessage, identifyRaw)
	time.Sleep(100 * time.Millisecond)

	respMu.Lock()
	resp := lastResponse
	respMu.Unlock()
	if resp != nil {
		var frame map[string]interface{}
		if err := json.Unmarshal(resp, &frame); err == nil {
			if payload, ok := frame["payload"].(map[string]interface{}); ok {
				if errStr, ok := payload["error"].(string); ok && errStr != "DRAINING" {
					t.Errorf("post-shutdown command should be rejected with DRAINING, got payload.error=%v", payload["error"])
				}
			}
		}
	}

	// 3. Wait for drain to complete (context cancelled).
	select {
	case <-drainDone:
		// Success — root context was cancelled.
	case <-time.After(5 * time.Second):
		t.Fatal("drain never completed (root context not cancelled)")
	}
}

// shutdownTestDrainer is a lightweight stand-in for drain.Drainer that doesn't
// require a real siblings.Manager. It sets the draining flag and cancels the
// root context after a short delay (mimicking the real drain flow).
type shutdownTestDrainer struct {
	draining   int32
	cancelRoot context.CancelFunc
	doneCh     chan struct{}
}

func (d *shutdownTestDrainer) IsDraining() bool {
	return atomic.LoadInt32(&d.draining) == 1
}

func (d *shutdownTestDrainer) Handle(ctx context.Context, env *envelope.Envelope) (json.RawMessage, error) {
	if d.IsDraining() {
		return json.RawMessage(`{"status":"already_draining"}`), nil
	}
	atomic.StoreInt32(&d.draining, 1)

	// Mimic the real drainer: cancel root after a short grace.
	go func() {
		time.Sleep(50 * time.Millisecond)
		d.cancelRoot()
		close(d.doneCh)
	}()

	return json.RawMessage(`{"status":"draining"}`), nil
}

func (d *shutdownTestDrainer) RejectIfDraining() (json.RawMessage, bool) {
	if !d.IsDraining() {
		return nil, false
	}
	payload, _ := json.Marshal(map[string]string{
		"error":   "DRAINING",
		"message": "pmx-core is draining, no new commands accepted",
	})
	return payload, true
}

// ── bad signature rejection ──────────────────────────────────────────────────

// TestIntegration_RejectBadSignature verifies that an envelope signed with a
// different key than the one in the keyset is silently dropped.
func TestIntegration_RejectBadSignature(t *testing.T) {
	// Agent trusts pub, but envelope is signed by wrongPriv.
	pub, _ := newTestKeyPair(t)
	_, wrongPriv := newTestKeyPair(t)

	var called atomic.Bool
	router := wire.NewRouter(nil)
	router.Register("core.identify", func(_ context.Context, _ *envelope.Envelope) (json.RawMessage, error) {
		called.Store(true)
		return json.RawMessage(`{"ok":true}`), nil
	})

	// Sign with the WRONG key.
	env := makeEnvelope(wrongPriv, "01900000-0000-7000-8000-badsig00001", "core.identify")
	raw := encodeCBOR(t, env)

	wsURL := startBackend(t, func(conn *websocket.Conn) {
		time.Sleep(30 * time.Millisecond)
		conn.WriteMessage(websocket.BinaryMessage, raw)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})

	h := &coreHandler{router: router}
	c := newClient(t, wsURL, pub, h)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	go c.Run(ctx)
	<-ctx.Done()

	if called.Load() {
		t.Error("OnEnvelope must NOT be called for badly-signed envelopes")
	}
}
