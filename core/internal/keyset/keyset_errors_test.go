package keyset_test

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/pmx-cloud/agents/core/internal/keyset"
	envpkg "github.com/pmx-cloud/agents/shared/envelope"
)

func TestRotator_KeysAsString(t *testing.T) {
	pub, _ := newKeyPair(t)
	ks := newKeySet(t, pub)
	pub2, _ := newKeyPair(t)
	key2Hex := hex.EncodeToString(pub2)

	tmpDir := t.TempDir()
	keysetPath := filepath.Join(tmpDir, "keyset.pub")
	os.WriteFile(keysetPath, []byte(hex.EncodeToString(pub)), 0o644)

	rotator := &keyset.Rotator{
		KeysetPath:    keysetPath,
		CurrentKeySet: ks,
	}
	// Keys as a single newline-joined string (not array)
	env := makeEnvelope("core.keyset.update", map[string]interface{}{
		"keys": key2Hex, // string, not []interface{}
	})
	result, err := rotator.Handle(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = result
}

func TestRotator_KeysWrongType(t *testing.T) {
	pub, _ := newKeyPair(t)
	ks := newKeySet(t, pub)
	rotator := &keyset.Rotator{
		KeysetPath:    filepath.Join(t.TempDir(), "keyset.pub"),
		CurrentKeySet: ks,
	}
	env := makeEnvelope("core.keyset.update", map[string]interface{}{
		"keys": 12345, // wrong type
	})
	result, err := rotator.Handle(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("expected error payload for wrong type")
	}
}

func TestRotator_KeysArrayWithNonString(t *testing.T) {
	pub, _ := newKeyPair(t)
	ks := newKeySet(t, pub)
	rotator := &keyset.Rotator{
		KeysetPath:    filepath.Join(t.TempDir(), "keyset.pub"),
		CurrentKeySet: ks,
	}
	env := makeEnvelope("core.keyset.update", map[string]interface{}{
		"keys": []interface{}{42, "valid-but-after-error"}, // first element is int
	})
	result, err := rotator.Handle(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("expected error payload for non-string array element")
	}
}

func TestRotator_WriteFailsOnReadOnlyDir(t *testing.T) {
	pub, _ := newKeyPair(t)
	ks := newKeySet(t, pub)
	pub2, _ := newKeyPair(t)

	// Point to a non-existent directory so CreateTemp fails.
	rotator := &keyset.Rotator{
		KeysetPath:    "/nonexistent/dir/keyset.pub",
		CurrentKeySet: ks,
	}
	env := makeEnvelope("core.keyset.update", map[string]interface{}{
		"keys": []interface{}{hex.EncodeToString(pub2)},
	})
	_, err := rotator.Handle(context.Background(), env)
	if err == nil {
		t.Fatal("expected error when writing to non-existent directory")
	}
}

// Verify ParseKeySet is accessible for testing purposes.
func TestParseKeySet_Valid(t *testing.T) {
	pub, _ := newKeyPair(t)
	_, err := envpkg.ParseKeySet(hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("ParseKeySet: %v", err)
	}
}
