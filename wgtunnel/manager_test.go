package wgtunnel

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestEnsureKeysDerivesPublicKeyFromPrivateKey(t *testing.T) {
	dataDir := t.TempDir()

	publicKey, err := EnsureKeys(dataDir)
	if err != nil {
		t.Fatalf("EnsureKeys returned error: %v", err)
	}

	privateKeyBytes, err := os.ReadFile(filepath.Join(dataDir, "wg-privatekey"))
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}

	privateKey, err := decodeWireGuardKey(string(privateKeyBytes))
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}

	expectedPublicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}

	expectedPublicKeyB64 := base64.StdEncoding.EncodeToString(expectedPublicKey)
	if publicKey != expectedPublicKeyB64 {
		t.Fatalf("expected public key %s, got %s", expectedPublicKeyB64, publicKey)
	}

	savedPublicKey, err := os.ReadFile(filepath.Join(dataDir, "wg-publickey"))
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	if string(savedPublicKey) != expectedPublicKeyB64 {
		t.Fatalf("expected saved public key %s, got %s", expectedPublicKeyB64, string(savedPublicKey))
	}
}

func TestDecodeWireGuardKeyRejectsInvalidLength(t *testing.T) {
	shortKey := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := decodeWireGuardKey(shortKey); err == nil {
		t.Fatal("expected invalid key length error")
	}
}
