package envelope_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/shared/envelope"
)

// helpers ---------------------------------------------------------------

func newKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func newKeySet(t *testing.T, pub ed25519.PublicKey) *envelope.KeySet {
	t.Helper()
	content := hex.EncodeToString(pub)
	ks, err := envelope.ParseKeySet(content)
	if err != nil {
		t.Fatalf("parse keyset: %v", err)
	}
	return ks
}

func goodEnvelope(pub ed25519.PublicKey, priv ed25519.PrivateKey) *envelope.Envelope {
	now := time.Now()
	e := &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "01900000-0000-7000-8000-000000000001",
		IssuedAt:  now,
		ExpiresAt: now.Add(30 * time.Minute),
		Issuer:    "backend-dev-1",
		Audience:  "pmx-network",
		Host:      "aabbccdd",
		Command:   "network.tunnel.up",
		Params:    map[string]interface{}{"iface": "wg0"},
	}
	if err := e.Sign(priv); err != nil {
		panic("sign: " + err.Error())
	}
	return e
}

func makeCache() *envelope.ReplayCache {
	return envelope.NewReplayCache(1000, 24*time.Hour)
}

func deterministicInteropEnvelope(t *testing.T) (ed25519.PublicKey, *envelope.Envelope) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	e := &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "01900000-0000-7000-8000-000000000001",
		IssuedAt:  now,
		ExpiresAt: now.Add(30 * time.Minute),
		Issuer:    "backend-dev-1",
		Audience:  "pmx-network",
		Host:      "aabbccdd",
		Command:   "network.tunnel.up",
		Params:    map[string]interface{}{"iface": "wg0"},
	}
	if err := e.Sign(priv); err != nil {
		t.Fatalf("sign deterministic interop envelope: %v", err)
	}
	return pub, e
}

// TestVerify_HappyPath --------------------------------------------------

func TestVerify_HappyPath(t *testing.T) {
	pub, priv := newKeypair(t)
	ks := newKeySet(t, pub)
	cache := makeCache()
	defer cache.Close()

	e := goodEnvelope(pub, priv)
	if err := e.Verify(ks, "pmx-network", "aabbccdd", cache); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

// TestVerify_BadVersion -------------------------------------------------

func TestVerify_BadVersion(t *testing.T) {
	pub, priv := newKeypair(t)
	ks := newKeySet(t, pub)
	cache := makeCache()
	defer cache.Close()

	e := goodEnvelope(pub, priv)
	e.Version = "pmx-agent-v0"
	// Re-sign so the only failure is the version check.
	_ = e.Sign(priv)

	err := e.Verify(ks, "pmx-network", "aabbccdd", cache)
	if !errors.Is(err, envelope.ErrVersionUnsupported) {
		t.Fatalf("expected ErrVersionUnsupported, got %v", err)
	}
}

// TestVerify_Expired ----------------------------------------------------

func TestVerify_Expired(t *testing.T) {
	pub, priv := newKeypair(t)
	ks := newKeySet(t, pub)
	cache := makeCache()
	defer cache.Close()

	now := time.Now()
	e := &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "01900000-0000-7000-8000-000000000002",
		IssuedAt:  now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-1 * time.Hour), // clearly expired
		Issuer:    "backend-dev-1",
		Audience:  "pmx-network",
		Host:      "aabbccdd",
		Command:   "network.tunnel.up",
		Params:    map[string]interface{}{},
	}
	_ = e.Sign(priv)

	err := e.Verify(ks, "pmx-network", "aabbccdd", cache)
	if !errors.Is(err, envelope.ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

// TestVerify_TooLongLived -----------------------------------------------

func TestVerify_TooLongLived(t *testing.T) {
	pub, priv := newKeypair(t)
	ks := newKeySet(t, pub)
	cache := makeCache()
	defer cache.Close()

	now := time.Now()
	e := &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     "01900000-0000-7000-8000-000000000003",
		IssuedAt:  now,
		ExpiresAt: now.Add(2 * time.Hour), // > 1h cap
		Issuer:    "backend-dev-1",
		Audience:  "pmx-network",
		Host:      "aabbccdd",
		Command:   "network.tunnel.up",
		Params:    map[string]interface{}{},
	}
	_ = e.Sign(priv)

	err := e.Verify(ks, "pmx-network", "aabbccdd", cache)
	if !errors.Is(err, envelope.ErrTooLongLived) {
		t.Fatalf("expected ErrTooLongLived, got %v", err)
	}
}

// TestVerify_WrongAudience ----------------------------------------------

func TestVerify_WrongAudience(t *testing.T) {
	pub, priv := newKeypair(t)
	ks := newKeySet(t, pub)
	cache := makeCache()
	defer cache.Close()

	e := goodEnvelope(pub, priv)
	err := e.Verify(ks, "pmx-storage", "aabbccdd", cache) // wrong agent class
	if !errors.Is(err, envelope.ErrAudienceMismatch) {
		t.Fatalf("expected ErrAudienceMismatch, got %v", err)
	}
}

// TestVerify_WrongHost --------------------------------------------------

func TestVerify_WrongHost(t *testing.T) {
	pub, priv := newKeypair(t)
	ks := newKeySet(t, pub)
	cache := makeCache()
	defer cache.Close()

	e := goodEnvelope(pub, priv)
	err := e.Verify(ks, "pmx-network", "deadbeef", cache) // wrong fingerprint
	if !errors.Is(err, envelope.ErrHostMismatch) {
		t.Fatalf("expected ErrHostMismatch, got %v", err)
	}
}

// TestVerify_BadSig -----------------------------------------------------

func TestVerify_BadSig(t *testing.T) {
	pub, _ := newKeypair(t)
	ks := newKeySet(t, pub)
	cache := makeCache()
	defer cache.Close()

	// Sign with a different private key — verification must fail.
	_, wrongPriv := newKeypair(t)
	e := goodEnvelope(pub, wrongPriv)

	err := e.Verify(ks, "pmx-network", "aabbccdd", cache)
	if !errors.Is(err, envelope.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

// TestVerify_Replay -----------------------------------------------------

func TestVerify_Replay(t *testing.T) {
	pub, priv := newKeypair(t)
	ks := newKeySet(t, pub)
	cache := makeCache()
	defer cache.Close()

	e := goodEnvelope(pub, priv)

	if err := e.Verify(ks, "pmx-network", "aabbccdd", cache); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	// Second call with same jobId must be rejected.
	err := e.Verify(ks, "pmx-network", "aabbccdd", cache)
	if !errors.Is(err, envelope.ErrReplay) {
		t.Fatalf("expected ErrReplay, got %v", err)
	}
}

// TestInterop_GoSignedDumpFile ------------------------------------------
// Writes a signed CBOR envelope to testdata/envelope-v1.cbor for use by the
// Rust cross-language interop test. Also writes the public key in hex.
func TestInterop_GoSignedDumpFile(t *testing.T) {
	pub, e := deterministicInteropEnvelope(t)

	raw, err := e.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	td := filepath.Join("testdata")
	if err := os.MkdirAll(td, 0o755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(td, "envelope-v1.cbor"), raw, 0o644); err != nil {
		t.Fatalf("write cbor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(td, "pubkey.hex"), []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}
	t.Logf("testdata written to %s", td)
}
