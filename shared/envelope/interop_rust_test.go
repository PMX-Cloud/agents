package envelope_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/shared/envelope"
)

// TestInterop_RustSignedEnvelopeVerifies reads the CBOR envelope and public
// key written by the Rust interop_writes_rust_signed_envelope test and verifies
// the envelope using the Go implementation.
//
// This closes the Rust→Go direction of the cross-language interop proof:
//   - Go→Rust is covered by envelope_test.go:interop_go_signed_envelope (Rust).
//   - Rust→Go is covered here.
//
// Run this after:
//
//	cd agents/shared-rust && cargo test interop_writes_rust_signed_envelope
//
// The Rust test writes to agents/shared-rust/testdata/; this test reads from
// there via the relative path ../../shared-rust/testdata/.
func TestInterop_RustSignedEnvelopeVerifies(t *testing.T) {
	// Paths relative to the package directory (agents/shared/envelope/).
	cborPath := filepath.Join("..", "..", "shared-rust", "testdata", "envelope-v1-rust.cbor")
	pubkeyPath := filepath.Join("..", "..", "shared-rust", "testdata", "pubkey-rust.hex")

	// Skip gracefully if Rust testdata hasn't been generated yet.
	if _, err := os.Stat(cborPath); os.IsNotExist(err) {
		t.Skipf("Rust testdata not found at %s — run: cd agents/shared-rust && cargo test interop_writes_rust_signed_envelope", cborPath)
	}

	cborBytes, err := os.ReadFile(cborPath)
	if err != nil {
		t.Fatalf("read CBOR: %v", err)
	}

	pubkeyHex, err := os.ReadFile(pubkeyPath)
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}

	// Parse the Rust-written public key (64 hex chars = 32 bytes Ed25519).
	pubBytes, err := hex.DecodeString(string(pubkeyHex))
	if err != nil {
		t.Fatalf("decode pubkey hex: %v", err)
	}

	ks, err := envelope.ParseKeySet(hex.EncodeToString(pubBytes))
	if err != nil {
		t.Fatalf("parse keyset: %v", err)
	}

	// Decode the Rust-written CBOR envelope.
	env, err := envelope.Unmarshal(cborBytes)
	if err != nil {
		t.Fatalf("unmarshal CBOR: %v", err)
	}

	// The Rust-side fixture has a 30-minute exp window. If
	// `cargo test interop_writes_rust_signed_envelope` hasn't been run
	// for a while, the fixture is stale — skip so local Go-only runs stay
	// green. CI runs both back-to-back.
	if env.ExpiresAt.Before(time.Now()) {
		t.Skipf("Rust-signed fixture expired at %s — run: cd agents/shared-rust && cargo test interop_writes_rust_signed_envelope", env.ExpiresAt.Format(time.RFC3339))
	}

	cache := envelope.NewReplayCache(1000, 24*time.Hour)
	defer cache.Close()

	// The Rust test writes the envelope with:
	//   audience = "pmx-network"
	//   host     = "aabbccdd"
	if err := env.Verify(ks, "pmx-network", "aabbccdd", cache); err != nil {
		t.Errorf("Rust-signed envelope must verify in Go: %v", err)
	}
}
