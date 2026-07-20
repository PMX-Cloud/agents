package keyset_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/core/internal/keyset"
	envpkg "github.com/pmx-cloud/agents/shared/envelope"
)

func newKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func newKeySet(t *testing.T, pub ed25519.PublicKey) *envpkg.KeySet {
	t.Helper()
	ks, err := envpkg.ParseKeySet(hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("parse keyset: %v", err)
	}
	return ks
}

func makeEnvelope(cmd string, params map[string]interface{}) *envpkg.Envelope {
	if params == nil {
		params = map[string]interface{}{}
	}
	return &envpkg.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "keyset-test-" + cmd,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * time.Minute),
		Audience:  "pmx-core",
		Command:   cmd,
		Params:    params,
	}
}

func TestRotator_HappyPath(t *testing.T) {
	pub, _ := newKeyPair(t)
	ks := newKeySet(t, pub)

	// New keyset with a different key.
	pub2, _ := newKeyPair(t)
	newKeyLine := hex.EncodeToString(pub2)

	tmpDir := t.TempDir()
	keysetPath := filepath.Join(tmpDir, "keyset.pub")
	os.WriteFile(keysetPath, []byte(hex.EncodeToString(pub)), 0o444)

	rotator := &keyset.Rotator{
		KeysetPath:    keysetPath,
		CurrentKeySet: ks,
	}

	env := makeEnvelope("core.keyset.update", map[string]interface{}{
		"keys": []interface{}{newKeyLine},
	})

	result, err := rotator.Handle(context.Background(), env)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// The keyset file must have been updated.
	data, _ := os.ReadFile(keysetPath)
	if string(data) != newKeyLine {
		t.Fatalf("keyset file not updated: %q", data)
	}
}

func TestRotator_MissingKeysParam(t *testing.T) {
	pub, _ := newKeyPair(t)
	ks := newKeySet(t, pub)
	rotator := &keyset.Rotator{KeysetPath: "/tmp/test.pub", CurrentKeySet: ks}

	result, err := rotator.Handle(context.Background(), makeEnvelope("core.keyset.update", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return a structured error payload.
	if string(result) == "" {
		t.Fatal("expected non-empty result for missing param")
	}
}

func TestRotator_InvalidKeyset(t *testing.T) {
	pub, _ := newKeyPair(t)
	ks := newKeySet(t, pub)
	rotator := &keyset.Rotator{KeysetPath: "/tmp/test.pub", CurrentKeySet: ks}

	env := makeEnvelope("core.keyset.update", map[string]interface{}{
		"keys": []interface{}{"not-valid-hex"},
	})
	result, err := rotator.Handle(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result) == "" {
		t.Fatal("expected error payload for invalid keyset")
	}
}
