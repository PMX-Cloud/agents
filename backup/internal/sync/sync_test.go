package sync

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.bin")
	outPath := filepath.Join(dir, "out.bin")
	payload := make([]byte, 2*1024*1024+123)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand.Read payload: %v", err)
	}
	if err := os.WriteFile(plainPath, payload, 0o644); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read key: %v", err)
	}

	encryptedPath, err := encryptToTemp(plainPath, key, nil)
	if err != nil {
		t.Fatalf("encryptToTemp() error = %v", err)
	}
	defer os.Remove(encryptedPath)
	if filepath.Dir(encryptedPath) != dir {
		t.Fatalf("encrypted temp dir = %q, want %q", filepath.Dir(encryptedPath), dir)
	}

	if err := decryptFile(encryptedPath, outPath, key, nil); err != nil {
		t.Fatalf("decryptFile() error = %v", err)
	}
	decrypted, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if hex.EncodeToString(payload) != hex.EncodeToString(decrypted) {
		t.Fatal("round-trip payload mismatch")
	}
}

func TestParseEncryptionKey(t *testing.T) {
	t.Parallel()

	if _, err := parseEncryptionKey("short"); err == nil {
		t.Fatal("expected parseEncryptionKey to reject short key")
	}
}
