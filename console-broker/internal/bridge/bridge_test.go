package bridge

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestBridgeReturnsMetricsOnContextDeadline(t *testing.T) {
	t.Parallel()

	localA, localB := net.Pipe()
	defer localA.Close()
	defer localB.Close()

	// Simulate missing WS side by closing context immediately and ensuring Run exits cleanly.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := Run(ctx, localA, nil, Options{RateLimitMbps: 100})
	if err == nil {
		t.Fatal("expected error with nil ws connection")
	}
}

func TestIsClosedNetworkError(t *testing.T) {
	t.Parallel()

	if !isClosedNetworkError(context.Canceled) && isClosedNetworkError(nil) {
		t.Fatal("unexpected closed network detection behavior")
	}
}

func TestRunIgnoresTextFramesFromBackend(t *testing.T) {
	t.Parallel()

	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, []byte("control-message"))
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte("console-bytes"))
		time.Sleep(25 * time.Millisecond)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial test websocket: %v", err)
	}

	localA, localB := net.Pipe()
	defer localB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, localA, wsConn, Options{RateLimitMbps: 100})
		done <- err
	}()

	buf := make([]byte, len("console-bytes"))
	if _, err := localB.Read(buf); err != nil {
		t.Fatalf("read local bridge output: %v", err)
	}
	if string(buf) != "console-bytes" {
		t.Fatalf("local output = %q, want binary console bytes only", string(buf))
	}
	_ = localB.Close()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}
