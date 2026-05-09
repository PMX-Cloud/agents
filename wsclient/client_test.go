package wsclient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestConnectSendsConfiguredAgentVersionHeader(t *testing.T) {
	versionCh := make(chan string, 1)
	upgrader := websocket.Upgrader{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		versionCh <- r.Header.Get("X-Agent-Version")
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade websocket: %v", err)
		}
		_ = conn.Close()
	}))
	defer server.Close()

	client, err := New(Config{
		ServerURL:         "ws" + strings.TrimPrefix(server.URL, "http"),
		Token:             "pmx_test_token",
		MachineId:         "machine-1",
		WireguardPubkey:   "wg-pubkey",
		AgentVersion:      "9.8.7-test",
		ReconnectInterval: time.Hour,
		HeartbeatInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if err := client.connect(); err != nil {
		t.Fatalf("connect returned error: %v", err)
	}
	defer client.Stop()

	select {
	case got := <-versionCh:
		if got != "9.8.7-test" {
			t.Fatalf("expected X-Agent-Version 9.8.7-test, got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for websocket request")
	}
}
