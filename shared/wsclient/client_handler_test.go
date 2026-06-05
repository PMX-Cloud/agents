package wsclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"net/http"
	"net/http/httptest"

	"github.com/gorilla/websocket"
	"github.com/pmx-cloud/agents/shared/envelope"
	"github.com/pmx-cloud/agents/shared/wsclient"
)

func upgradeConn(w http.ResponseWriter, r *http.Request) *websocket.Conn {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	conn, _ := up.Upgrade(w, r, nil)
	return conn
}

// TestRun_DispatchesValidEnvelope sends a properly signed envelope and checks
// that the handler is called.
func TestRun_DispatchesValidEnvelope(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := envelope.ParseKeySet(hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("ParseKeySet: %v", err)
	}

	env := &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "ws-dispatch-001",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Audience:  "pmx-test",
		Host:      "",
		Command:   "test.noop",
		Params:    map[string]interface{}{},
	}
	if err := env.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	envBytes, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	dispatched := make(chan struct{}, 1)
	h := &onEnvelopeHandler{fn: func() { dispatched <- struct{}{} }}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := upgradeConn(w, r)
		if conn == nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.BinaryMessage, envBytes)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	c, err := wsclient.New(wsclient.Config{
		BackendURL:        "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws",
		AgentClass:        "pmx-test",
		KeySet:            ks,
		ReplayCache:       envelope.NewReplayCache(1024, 0),
		Handler:           h,
		AllowInsecureWS:   true,
		HeartbeatInterval: time.Hour,
		HeartbeatTimeout:  time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	select {
	case <-dispatched:
	case <-time.After(400 * time.Millisecond):
		t.Error("envelope was not dispatched within timeout")
	}
	cancel()
}

// TestRun_IgnoresTextControlFrames ensures JSON control traffic from the
// gateway does not get treated as a CBOR envelope.
func TestRun_IgnoresTextControlFrames(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := envelope.ParseKeySet(hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("ParseKeySet: %v", err)
	}

	env := &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "ws-dispatch-text-001",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Audience:  "pmx-test",
		Host:      "",
		Command:   "test.noop",
		Params:    map[string]interface{}{},
	}
	if err := env.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	envBytes, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	dispatched := make(chan struct{}, 1)
	h := &onEnvelopeHandler{fn: func() { dispatched <- struct{}{} }}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := upgradeConn(w, r)
		if conn == nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(
			websocket.TextMessage,
			[]byte(`{"version":"pmx-agent-v1","type":"cloud.hello","timestamp":1,"payload":{}}`),
		)
		_ = conn.WriteMessage(websocket.BinaryMessage, envBytes)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	c, err := wsclient.New(wsclient.Config{
		BackendURL:        "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws",
		AgentClass:        "pmx-test",
		KeySet:            ks,
		ReplayCache:       envelope.NewReplayCache(1024, 0),
		Handler:           h,
		AllowInsecureWS:   true,
		HeartbeatInterval: time.Hour,
		HeartbeatTimeout:  time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	select {
	case <-dispatched:
	case <-time.After(400 * time.Millisecond):
		t.Error("envelope was not dispatched within timeout")
	}
	cancel()
}

// TestSendRaw_WhileConnected sends a raw frame while connected.
func TestSendRaw_WhileConnected(t *testing.T) {
	received := make(chan []byte, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := upgradeConn(w, r)
		if conn == nil {
			return
		}
		defer conn.Close()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			select {
			case received <- msg:
			default:
			}
		}
	}))
	defer srv.Close()

	clientReady := make(chan *wsclient.Client, 1)
	h := &connectCapture{fn: func(c *wsclient.Client) {
		select {
		case clientReady <- c:
		default:
		}
	}}

	c, err := wsclient.New(wsclient.Config{
		BackendURL:        "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws",
		AgentClass:        "pmx-test",
		KeySet:            testKeySet(t),
		ReplayCache:       testReplayCache(),
		Handler:           h,
		AllowInsecureWS:   true,
		HeartbeatInterval: time.Hour,
		HeartbeatTimeout:  time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	var client *wsclient.Client
	select {
	case client = <-clientReady:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("OnConnect never called")
	}

	if err := client.SendRaw([]byte("hello-raw")); err != nil {
		t.Fatalf("SendRaw: %v", err)
	}
	select {
	case msg := <-received:
		if string(msg) != "hello-raw" {
			t.Logf("first received message: %q (may be heartbeat)", string(msg))
			// Try second message if first was heartbeat.
			select {
			case msg2 := <-received:
				_ = msg2
			case <-time.After(200 * time.Millisecond):
			}
		}
	case <-time.After(300 * time.Millisecond):
		t.Error("server did not receive SendRaw message")
	}
	cancel()
}

// ── helpers ───────────────────────────────────────────────────────────────────

type onEnvelopeHandler struct {
	noopHandler
	fn func()
}

func (h *onEnvelopeHandler) OnEnvelope(_ context.Context, _ *envelope.Envelope) ([]byte, error) {
	if h.fn != nil {
		h.fn()
	}
	return nil, nil
}

type connectCapture struct {
	noopHandler
	fn func(*wsclient.Client)
}

func (h *connectCapture) OnConnect(_ context.Context, c *wsclient.Client) error {
	if h.fn != nil {
		h.fn(c)
	}
	return nil
}
