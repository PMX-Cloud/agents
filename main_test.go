package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/AraaRashek/pmx-cloud/agent/config"
)

func TestNormalizeSHA256HashAcceptsRawAndPrefixedHex(t *testing.T) {
	hash := sha256.Sum256([]byte("pmx-cloud-agent"))
	raw := hex.EncodeToString(hash[:])

	normalized, err := normalizeSHA256Hash("sha256:" + raw)
	if err != nil {
		t.Fatalf("normalizeSHA256Hash returned error: %v", err)
	}
	if normalized != raw {
		t.Fatalf("expected %s, got %s", raw, normalized)
	}

	normalized, err = normalizeSHA256Hash(raw)
	if err != nil {
		t.Fatalf("normalizeSHA256Hash returned error: %v", err)
	}
	if normalized != raw {
		t.Fatalf("expected %s, got %s", raw, normalized)
	}
}

func TestNormalizeSHA256HashRejectsInvalidHash(t *testing.T) {
	if _, err := normalizeSHA256Hash("sha256:not-a-valid-hash"); err == nil {
		t.Fatal("expected invalid hash error")
	}
}

func TestSystemMachineIdFallsBackToHostnameWhenMachineIdFilesAreMissing(t *testing.T) {
	machineID, err := systemMachineIdFromSources(
		func(string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
		func() (string, error) {
			return "pmx-test-host", nil
		},
	)
	if err != nil {
		t.Fatalf("systemMachineIdFromSources returned error: %v", err)
	}
	if machineID != "hostname:pmx-test-host" {
		t.Fatalf("expected hostname fallback, got %s", machineID)
	}
}

func TestPrimaryMacAddressFromInterfacesSelectsFirstActiveNonLoopbackInterface(t *testing.T) {
	mac, err := primaryMacAddressFromInterfaces([]net.Interface{
		{
			Name:         "lo",
			Flags:        net.FlagUp | net.FlagLoopback,
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 1},
		},
		{
			Name:         "down0",
			Flags:        0,
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 2},
		},
		{
			Name:         "eth0",
			Flags:        net.FlagUp,
			HardwareAddr: net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x02},
		},
	})
	if err != nil {
		t.Fatalf("primaryMacAddressFromInterfaces returned error: %v", err)
	}
	if mac != "02:42:ac:11:00:02" {
		t.Fatalf("expected eth0 MAC, got %s", mac)
	}
}

func TestDownloadAndVerifyUpdateWritesVerifiedPayload(t *testing.T) {
	payload := []byte("new-agent-binary")
	hash := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	destination := filepath.Join(t.TempDir(), "agent-update")
	err := downloadAndVerifyUpdate(context.Background(), server.URL, hex.EncodeToString(hash[:]), destination)
	if err != nil {
		t.Fatalf("downloadAndVerifyUpdate returned error: %v", err)
	}

	written, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("read staged update: %v", err)
	}
	if string(written) != string(payload) {
		t.Fatalf("expected %q, got %q", payload, written)
	}
}

func TestDownloadAndVerifyUpdateRejectsHashMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("unexpected-binary"))
	}))
	defer server.Close()

	expected := sha256.Sum256([]byte("expected-binary"))
	destination := filepath.Join(t.TempDir(), "agent-update")
	if err := downloadAndVerifyUpdate(context.Background(), server.URL, hex.EncodeToString(expected[:]), destination); err == nil {
		t.Fatal("expected hash mismatch error")
	}
}

func TestRunPreflightCreatesIdentityAndWireGuardKeys(t *testing.T) {
	dataDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "agent.conf")
	cfg := config.Config{
		Token:     "pmx_test_token",
		ServerURL: "wss://ws.pmxcloud.cloud/ws/agent",
		DataDir:   dataDir,
	}
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("save config: %v", err)
	}

	if err := runPreflight(configPath); err != nil {
		t.Fatalf("runPreflight returned error: %v", err)
	}

	for _, path := range []string{"machine-id", "wg-privatekey", "wg-publickey"} {
		if _, err := os.Stat(filepath.Join(dataDir, path)); err != nil {
			t.Fatalf("expected %s to be created: %v", path, err)
		}
	}
}
