package keyset_test

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/core/internal/keyset"
)

func TestRotator_EmptyNewKeys(t *testing.T) {
	pub, _ := newKeyPair(t)
	ks := newKeySet(t, pub)
	rotator := &keyset.Rotator{
		KeysetPath:    filepath.Join(t.TempDir(), "keyset.pub"),
		CurrentKeySet: ks,
	}
	env := makeEnvelope("core.keyset.update", map[string]interface{}{
		"keys": []interface{}{},
	})
	result, err := rotator.Handle(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("expected non-empty result payload for empty keyset")
	}
}

func TestRotator_MultipleKeys(t *testing.T) {
	pub, _ := newKeyPair(t)
	ks := newKeySet(t, pub)

	pub2, _ := newKeyPair(t)
	pub3, _ := newKeyPair(t)

	tmpDir := t.TempDir()
	keysetPath := filepath.Join(tmpDir, "keyset.pub")
	os.WriteFile(keysetPath, []byte(hex.EncodeToString(pub)), 0o444)

	rotator := &keyset.Rotator{
		KeysetPath:    keysetPath,
		CurrentKeySet: ks,
	}
	env := makeEnvelope("core.keyset.update", map[string]interface{}{
		"keys": []interface{}{
			hex.EncodeToString(pub2),
			hex.EncodeToString(pub3),
		},
	})
	result, err := rotator.Handle(context.Background(), env)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	data, _ := os.ReadFile(keysetPath)
	if len(data) == 0 {
		t.Fatal("keyset file must not be empty after update")
	}
}

func TestRotator_KeyWithNotAfter(t *testing.T) {
	pub, _ := newKeyPair(t)
	ks := newKeySet(t, pub)

	pub2, _ := newKeyPair(t)
	notAfter := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	keyLine := hex.EncodeToString(pub2) + " " + notAfter

	tmpDir := t.TempDir()
	keysetPath := filepath.Join(tmpDir, "keyset.pub")
	os.WriteFile(keysetPath, []byte(hex.EncodeToString(pub)), 0o444)

	rotator := &keyset.Rotator{
		KeysetPath:    keysetPath,
		CurrentKeySet: ks,
	}
	env := makeEnvelope("core.keyset.update", map[string]interface{}{
		"keys": []interface{}{keyLine},
	})
	_, err := rotator.Handle(context.Background(), env)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
}

func TestRotator_WrongCommand(t *testing.T) {
	pub, _ := newKeyPair(t)
	ks := newKeySet(t, pub)
	rotator := &keyset.Rotator{
		KeysetPath:    filepath.Join(t.TempDir(), "keyset.pub"),
		CurrentKeySet: ks,
	}
	env := makeEnvelope("wrong.command", map[string]interface{}{
		"keys": []interface{}{hex.EncodeToString(pub)},
	})
	// Should not crash; result or error are both acceptable.
	_, _ = rotator.Handle(context.Background(), env)
}
