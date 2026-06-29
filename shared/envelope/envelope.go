/*
Package envelope implements the PMX-Cloud signed job envelope (architecture §3.4).

Wire format: canonical CBOR (RFC 7049 map, keys sorted lexicographically using
CoreDetEncOptions). The signature covers all fields EXCEPT the "signature" field
itself, encoded with the same options.

Signing algorithm: Ed25519 (RFC 8032), raw 64-byte signature hex-encoded.
*/
package envelope

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"reflect"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	// SupportedVersion is the only accepted envelope version string.
	SupportedVersion = "pmx-agent-v1"

	// MaxLifetime is the upper bound on expiresAt - issuedAt (architecture §3.4).
	MaxLifetime = time.Hour

	// NTPSkewTolerance allows a 30 second backwards clock skew when evaluating expiry.
	NTPSkewTolerance = 30 * time.Second
)

// cborEM is the module-level deterministic CBOR encoding mode (sorted keys).
// It is initialised once so the configuration is shared across all calls.
var cborEM cbor.EncMode

// cborDM is the module-level decoding mode. It forces nested maps decoded into
// interface{} slots (e.g. Params["options"]) to use map[string]interface{}
// instead of the fxamacker/cbor default map[interface{}]interface{}. Agent
// handlers type-assert params["options"].(map[string]any); without this the
// assertion silently fails and nested-map commands (vm.update / ct.update)
// are rejected with "options map is required".
var cborDM cbor.DecMode

func init() {
	opts := cbor.CoreDetEncOptions()
	// Encode time.Time as RFC3339Nano text strings so Rust/ciborium + chrono
	// can deserialize them without a custom visitor. The default (TimeUnix)
	// produces integer epoch seconds which ciborium cannot decode into DateTime.
	opts.Time = cbor.TimeRFC3339Nano
	em, err := opts.EncMode()
	if err != nil {
		panic("envelope: failed to create CBOR encoding mode: " + err.Error())
	}
	cborEM = em

	dm, err := cbor.DecOptions{
		DefaultMapType: reflect.TypeOf(map[string]interface{}(nil)),
	}.DecMode()
	if err != nil {
		panic("envelope: failed to create CBOR decoding mode: " + err.Error())
	}
	cborDM = dm
}

// Envelope is the canonical job envelope exchanged between the backend and every
// agent (architecture §3.4). All fields are required; a missing field is treated
// as a verification failure.
type Envelope struct {
	Version   string                 `cbor:"version"   json:"version"`
	JobID     string                 `cbor:"jobId"     json:"jobId"`
	IssuedAt  time.Time              `cbor:"issuedAt"  json:"issuedAt"`
	ExpiresAt time.Time              `cbor:"expiresAt" json:"expiresAt"`
	Issuer    string                 `cbor:"issuer"    json:"issuer"`
	Audience  string                 `cbor:"audience"  json:"audience"`
	Host      string                 `cbor:"host"      json:"host"`
	Command   string                 `cbor:"command"   json:"command"`
	Params    map[string]interface{} `cbor:"params"    json:"params"`
	Signature string                 `cbor:"signature" json:"signature"`
}

// sigPayload mirrors Envelope for canonical-bytes production with the
// signature field omitted.
type sigPayload struct {
	Version   string                 `cbor:"version"`
	JobID     string                 `cbor:"jobId"`
	IssuedAt  time.Time              `cbor:"issuedAt"`
	ExpiresAt time.Time              `cbor:"expiresAt"`
	Issuer    string                 `cbor:"issuer"`
	Audience  string                 `cbor:"audience"`
	Host      string                 `cbor:"host"`
	Command   string                 `cbor:"command"`
	Params    map[string]interface{} `cbor:"params"`
}

// CanonicalBytes returns the deterministic CBOR encoding of the envelope with
// the "signature" field excluded. This is the byte slice that is actually
// signed and must be verified.
func (e *Envelope) CanonicalBytes() ([]byte, error) {
	// Normalise times to UTC so the canonical bytes are timezone-independent.
	// fxamacker/cbor with TimeRFC3339Nano preserves the time.Time Location, so
	// a local-timezone time would produce a different string than the UTC equivalent.
	// Both Go and Rust must produce "...Z" (UTC) for the signature to be verifiable
	// cross-language.
	p := sigPayload{
		Version:   e.Version,
		JobID:     e.JobID,
		IssuedAt:  e.IssuedAt.UTC(),
		ExpiresAt: e.ExpiresAt.UTC(),
		Issuer:    e.Issuer,
		Audience:  e.Audience,
		Host:      e.Host,
		Command:   e.Command,
		Params:    e.Params,
	}
	return cborEM.Marshal(p)
}

// Verify checks the envelope against the supplied keyset and context parameters.
// It enforces every rejection path from architecture §3.4 in the documented order:
//
//  1. Version check          → ErrVersionUnsupported
//  2. Expiry (with skew)     → ErrExpired
//  3. Lifetime cap           → ErrTooLongLived
//  4. Audience match         → ErrAudienceMismatch
//  5. Host fingerprint match → ErrHostMismatch
//  6. Signature check        → ErrBadSignature
//  7. Replay check           → ErrReplay
//
// thisAgentClass must be the agent's own class string (e.g. "pmx-network").
// thisHostFingerprint must be the SHA-256 hex string of the host identity.
// cache is the replay cache that persists across calls; it is mutated on success.
func (e *Envelope) Verify(
	keyset *KeySet,
	thisAgentClass string,
	thisHostFingerprint string,
	cache *ReplayCache,
) error {
	// 1. Version
	if e.Version != SupportedVersion {
		return fmt.Errorf("%w: got %q", ErrVersionUnsupported, e.Version)
	}

	now := time.Now()

	// 2. Expiry (NTP skew tolerance)
	if e.ExpiresAt.Before(now.Add(-NTPSkewTolerance)) {
		return fmt.Errorf("%w: expired at %s", ErrExpired, e.ExpiresAt.Format(time.RFC3339))
	}

	// 3. Lifetime cap
	if e.ExpiresAt.Sub(e.IssuedAt) > MaxLifetime {
		return fmt.Errorf("%w: lifetime %v", ErrTooLongLived, e.ExpiresAt.Sub(e.IssuedAt))
	}

	// 4. Audience
	if e.Audience != thisAgentClass {
		return fmt.Errorf("%w: expected %q, got %q", ErrAudienceMismatch, thisAgentClass, e.Audience)
	}

	// 5. Host fingerprint
	if e.Host != thisHostFingerprint {
		return fmt.Errorf("%w: expected %q, got %q", ErrHostMismatch, thisHostFingerprint, e.Host)
	}

	// 6. Signature
	canonical, err := e.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("envelope: canonical encoding: %w", err)
	}
	sigBytes, err := hex.DecodeString(e.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature is not valid hex", ErrBadSignature)
	}
	if !keyset.Verify(canonical, sigBytes) {
		return ErrBadSignature
	}

	// 7. Replay
	if cache.Seen(e.JobID) {
		return fmt.Errorf("%w: job %s", ErrReplay, e.JobID)
	}
	cache.Remember(e.JobID)

	return nil
}

// Sign encodes the envelope and signs it with the provided Ed25519 private key,
// setting e.Signature in place. This is used by the backend (and tests).
func (e *Envelope) Sign(priv ed25519.PrivateKey) error {
	canonical, err := e.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("envelope: sign: canonical: %w", err)
	}
	sig := ed25519.Sign(priv, canonical)
	e.Signature = hex.EncodeToString(sig)
	return nil
}

// Unmarshal decodes a CBOR-encoded wire message into an Envelope.
func Unmarshal(data []byte) (*Envelope, error) {
	var e Envelope
	if err := cborDM.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("envelope: unmarshal: %w", err)
	}
	return &e, nil
}

// Marshal encodes the envelope to CBOR (including the signature field).
func (e *Envelope) Marshal() ([]byte, error) {
	b, err := cborEM.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("envelope: marshal: %w", err)
	}
	return b, nil
}
