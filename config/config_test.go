package config

import "testing"

func TestValidateRequiresWebSocketServerURL(t *testing.T) {
	cfg := &Config{
		Token:     "pmx_test_token",
		ServerURL: "https://api.pmxcloud.cloud/ws/agent",
		DataDir:   "/var/lib/pmx-cloud",
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected non-websocket server_url to be rejected")
	}
}

func TestValidateAcceptsSecureWebSocketServerURL(t *testing.T) {
	cfg := &Config{
		Token:     "pmx_test_token",
		ServerURL: "wss://ws.pmxcloud.cloud/ws/agent",
		DataDir:   "/var/lib/pmx-cloud",
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected secure websocket server_url to be accepted, got %v", err)
	}
}
