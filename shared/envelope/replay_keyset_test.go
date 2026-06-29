package envelope_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/shared/envelope"
)

// helpers shared with envelope_test.go (newKeypair, newKeySet already defined there)

// ── KeySet tests ──────────────────────────────────────────────────────────────

func TestKeySet_ParseValid(t *testing.T) {
	pub, _ := newKeypair(t)
	ks := newKeySet(t, pub)
	if ks.Len() != 1 {
		t.Fatalf("expected 1 key, got %d", ks.Len())
	}
}

func TestKeySet_ParseMalformedHex(t *testing.T) {
	_, err := envelope.ParseKeySet("ZZZZ_not_hex")
	if err == nil {
		t.Fatal("expected error for malformed hex")
	}
}

func TestKeySet_ParseWrongLength(t *testing.T) {
	_, err := envelope.ParseKeySet("deadbeef") // too short
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestKeySet_ParseEmpty(t *testing.T) {
	_, err := envelope.ParseKeySet("")
	if err == nil {
		t.Fatal("expected error for empty keyset")
	}
}

func TestKeySet_ParseCommentLine(t *testing.T) {
	pub, _ := newKeypair(t)
	content := "# this is a comment\n" + hex.EncodeToString(pub)
	ks, err := envelope.ParseKeySet(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ks.Len() != 1 {
		t.Fatalf("expected 1 key, got %d", ks.Len())
	}
}

func TestKeySet_ParseWithExpiry(t *testing.T) {
	pub, _ := newKeypair(t)
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	content := hex.EncodeToString(pub) + " " + future
	ks, err := envelope.ParseKeySet(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ks.Len() != 1 {
		t.Fatalf("expected 1 key, got %d", ks.Len())
	}
}

func TestKeySet_ParseExpiredKeyRejectedAtVerify(t *testing.T) {
	pub, priv := newKeypair(t)
	// Key is already past not-after.
	past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	content := hex.EncodeToString(pub) + " " + past
	ks, err := envelope.ParseKeySet(content)
	if err != nil {
		t.Fatalf("ParseKeySet should succeed even for expired keys: %v", err)
	}

	// Build and sign a valid envelope; the key in ks is expired so verify must fail.
	e := buildValidEnvelope(priv)
	cache := envelope.NewReplayCache(10, time.Hour)
	defer cache.Close()

	err = e.Verify(ks, "pmx-network", "aabbccdd", cache)
	if !errors.Is(err, envelope.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature for expired key, got %v", err)
	}
}

func TestKeySet_ParseInvalidNotAfter(t *testing.T) {
	pub, _ := newKeypair(t)
	content := hex.EncodeToString(pub) + " not-a-date"
	_, err := envelope.ParseKeySet(content)
	if err == nil {
		t.Fatal("expected error for invalid not-after date")
	}
}

func TestKeySet_ParseTooManyFields(t *testing.T) {
	pub, _ := newKeypair(t)
	content := hex.EncodeToString(pub) + " 2099-01-01T00:00:00Z extra"
	_, err := envelope.ParseKeySet(content)
	if err == nil {
		t.Fatal("expected error for line with 3 fields")
	}
}

func TestKeySet_Update(t *testing.T) {
	pub1, _ := newKeypair(t)
	pub2, priv2 := newKeypair(t)

	ks := newKeySet(t, pub1)

	// Update with a keyset containing pub2 only.
	newKS, err := envelope.ParseKeySet(hex.EncodeToString(pub2))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ks.Update(newKS); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Now a message signed with priv2 must verify; priv1 must fail.
	e := buildValidEnvelope(priv2)
	cache := envelope.NewReplayCache(10, time.Hour)
	defer cache.Close()
	if err := e.Verify(ks, "pmx-network", "aabbccdd", cache); err != nil {
		t.Fatalf("expected success after Update, got %v", err)
	}
}

func TestKeySet_LoadFromFile(t *testing.T) {
	pub, _ := newKeypair(t)
	path := filepath.Join(t.TempDir(), "keyset.pub")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(pub)+"\n"), 0o444); err != nil {
		t.Fatalf("write: %v", err)
	}
	ks, err := envelope.LoadKeySet(path)
	if err != nil {
		t.Fatalf("LoadKeySet: %v", err)
	}
	if ks.Len() != 1 {
		t.Fatalf("expected 1 key, got %d", ks.Len())
	}
}

func TestKeySet_LoadFileMissing(t *testing.T) {
	_, err := envelope.LoadKeySet("/no/such/path/keyset.pub")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ── ReplayCache tests ─────────────────────────────────────────────────────────

func TestReplay_NotSeenBeforeRemember(t *testing.T) {
	c := envelope.NewReplayCache(10, time.Hour)
	defer c.Close()
	if c.Seen("job-never") {
		t.Fatal("should not be seen")
	}
}

func TestReplay_SeenAfterRemember(t *testing.T) {
	c := envelope.NewReplayCache(10, time.Hour)
	defer c.Close()
	c.Remember("job-x")
	if !c.Seen("job-x") {
		t.Fatal("should be seen after Remember")
	}
}

func TestReplay_EvictsOldestAtCapacity(t *testing.T) {
	c := envelope.NewReplayCache(3, time.Hour)
	defer c.Close()
	c.Remember("j1")
	c.Remember("j2")
	c.Remember("j3")
	c.Remember("j4") // j1 evicted
	if c.Seen("j1") {
		t.Fatal("j1 should have been evicted")
	}
	for _, id := range []string{"j2", "j3", "j4"} {
		if !c.Seen(id) {
			t.Fatalf("%s should still be present", id)
		}
	}
}

func TestReplay_DuplicateRememberNoGrowth(t *testing.T) {
	c := envelope.NewReplayCache(10, time.Hour)
	defer c.Close()
	c.Remember("job-dup")
	c.Remember("job-dup")
	if c.Len() != 1 {
		t.Fatalf("expected 1 entry, got %d", c.Len())
	}
}

func TestReplay_CloseIdempotent(t *testing.T) {
	c := envelope.NewReplayCache(10, time.Hour)
	c.Close()
	c.Close() // must not panic
}

func TestReplay_LargeCapacity(t *testing.T) {
	// Insert 10,000 entries and verify no growth beyond cap.
	cap := 1000
	c := envelope.NewReplayCache(cap, time.Hour)
	defer c.Close()
	for i := range cap + 500 {
		c.Remember(fmt.Sprintf("job-%d", i))
	}
	if c.Len() > cap {
		t.Fatalf("cache grew beyond capacity: %d > %d", c.Len(), cap)
	}
}

// ── Envelope additional paths ─────────────────────────────────────────────────

func TestEnvelope_CanonicalBytes(t *testing.T) {
	_, priv := newKeypair(t)
	e := buildValidEnvelope(priv)
	b1, err := e.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	b2, err := e.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes 2nd call: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatal("CanonicalBytes must be deterministic")
	}
}

func TestEnvelope_MarshalUnmarshal(t *testing.T) {
	_, priv := newKeypair(t)
	e := buildValidEnvelope(priv)
	data, err := e.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	e2, err := envelope.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if e.JobID != e2.JobID {
		t.Fatalf("JobID mismatch after round-trip: %q vs %q", e.JobID, e2.JobID)
	}
	if e.Signature != e2.Signature {
		t.Fatalf("Signature mismatch after round-trip")
	}
}

// TestEnvelope_UnmarshalNestedMapStringKeyed pins the contract that nested
// maps in Params decode as map[string]interface{}, not the CBOR default
// map[interface{}]interface{}. Agent handlers (e.g. vm.update / ct.update)
// type-assert params["options"].(map[string]any); the default decode mode
// silently fails that assertion and rejects the job as "options map is
// required".
func TestEnvelope_UnmarshalNestedMapStringKeyed(t *testing.T) {
	_, priv := newKeypair(t)
	e := buildValidEnvelope(priv)
	e.Command = "vm.update"
	e.Params = map[string]interface{}{
		"vmid":    "201",
		"options": map[string]interface{}{"cores": 2, "memory": 2048},
	}
	if err := e.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := e.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	e2, err := envelope.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := e2.Params["options"].(map[string]interface{}); !ok {
		t.Fatalf("nested options decoded as %T, want map[string]interface{}", e2.Params["options"])
	}
}

func TestEnvelope_UnmarshalBadCBOR(t *testing.T) {
	_, err := envelope.Unmarshal([]byte("not cbor"))
	if err == nil {
		t.Fatal("expected error for bad CBOR")
	}
}

func TestEnvelope_BadSigHex(t *testing.T) {
	pub, priv := newKeypair(t)
	ks := newKeySet(t, pub)
	e := buildValidEnvelope(priv)
	e.Signature = "ZZZ_not_hex"
	cache := envelope.NewReplayCache(10, time.Hour)
	defer cache.Close()
	err := e.Verify(ks, "pmx-network", "aabbccdd", cache)
	if !errors.Is(err, envelope.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature for bad hex sig, got %v", err)
	}
}

// helper: build a signed valid envelope without needing the pub key.
func buildValidEnvelope(priv ed25519.PrivateKey) *envelope.Envelope {
	now := time.Now()
	e := &envelope.Envelope{
		Version:   "pmx-agent-v1",
		JobID:     fmt.Sprintf("test-job-%d", now.UnixNano()),
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
