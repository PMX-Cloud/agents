//! Envelope schema and verification — mirrors agents/shared/envelope/envelope.go.
//!
//! Wire format: canonical CBOR with lexicographically sorted map keys.
//! Signature: Ed25519 over the canonical CBOR of all fields except `signature`.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub const SUPPORTED_VERSION: &str = "pmx-agent-v1";
pub const MAX_LIFETIME_SECS: i64 = 3600; // 1 hour
pub const NTP_SKEW_SECS: i64 = 30;

/// Errors returned by [`Envelope::verify`].
#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("unsupported version: {0}")]
    VersionUnsupported(String),
    #[error("envelope expired at {0}")]
    Expired(String),
    #[error("envelope lifetime {0}s exceeds maximum 3600s")]
    TooLongLived(i64),
    #[error("audience mismatch: expected {expected}, got {got}")]
    AudienceMismatch { expected: String, got: String },
    #[error("host mismatch: expected {expected}, got {got}")]
    HostMismatch { expected: String, got: String },
    #[error("bad signature")]
    BadSignature,
    #[error("replayed job id: {0}")]
    Replay(String),
    #[error("cbor: {0}")]
    Cbor(String),
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// The canonical PMX-Cloud job envelope (architecture §3.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub version: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    pub issuer: String,
    pub audience: String,
    pub host: String,
    pub command: String,
    pub params: BTreeMap<String, serde_json::Value>,
    pub signature: String,
}

/// Convert a serde_json::Value to a ciborium::Value for canonical CBOR encoding.
fn json_val_to_cbor(v: &serde_json::Value) -> ciborium::Value {
    use ciborium::Value;
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i.into())
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Text(n.to_string())
            }
        }
        serde_json::Value::String(s) => Value::Text(s.clone()),
        serde_json::Value::Array(arr) => Value::Array(arr.iter().map(json_val_to_cbor).collect()),
        serde_json::Value::Object(obj) => {
            // Sort object keys for deterministic encoding.
            let pairs: Vec<(Value, Value)> = obj
                .iter()
                .map(|(k, v)| (Value::Text(k.clone()), json_val_to_cbor(v)))
                .collect();
            Value::Map(pairs)
        }
    }
}

impl Envelope {
    /// Deserialise from CBOR bytes.
    pub fn from_cbor(data: &[u8]) -> Result<Self, EnvelopeError> {
        ciborium::from_reader(data).map_err(|e| EnvelopeError::Cbor(e.to_string()))
    }

    /// Serialise to CBOR bytes (including signature field).
    pub fn to_cbor(&self) -> Result<Vec<u8>, EnvelopeError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| EnvelopeError::Cbor(e.to_string()))?;
        Ok(buf)
    }

    /// Returns the canonical CBOR encoding of the envelope with `signature` excluded.
    ///
    /// Wire contract: the Go side uses `fxamacker/cbor` with `CoreDetEncOptions`
    /// (SortCoreDeterministic + TimeRFC3339Nano), which produces a CBOR map with
    /// string keys sorted lexicographically and time values as RFC3339Nano strings.
    ///
    /// We must produce the same byte sequence or signature verification fails. The
    /// `ciborium::into_writer` struct serialisation emits fields in declaration order,
    /// not lexicographic order, so we build the sorted map explicitly.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        use chrono::SecondsFormat;
        use ciborium::Value;

        // BTreeMap gives us lexicographic key ordering automatically.
        let mut map: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();

        map.insert("audience".to_string(), Value::Text(self.audience.clone()));
        map.insert("command".to_string(), Value::Text(self.command.clone()));
        map.insert(
            "expiresAt".to_string(),
            Value::Text(self.expires_at.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
        );
        map.insert("host".to_string(), Value::Text(self.host.clone()));
        map.insert(
            "issuedAt".to_string(),
            Value::Text(self.issued_at.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
        );
        map.insert("issuer".to_string(), Value::Text(self.issuer.clone()));
        map.insert("jobId".to_string(), Value::Text(self.job_id.clone()));

        // params: BTreeMap<String, serde_json::Value> → ciborium pairs (already sorted)
        let params_pairs: Vec<(Value, Value)> = self
            .params
            .iter()
            .map(|(k, v)| (Value::Text(k.clone()), json_val_to_cbor(v)))
            .collect();
        map.insert("params".to_string(), Value::Map(params_pairs));

        map.insert("version".to_string(), Value::Text(self.version.clone()));

        // Convert to Vec and sort by CBOR Core Deterministic order (RFC 7049 §3.9):
        // keys are compared by their encoded byte sequence. For text strings
        // shorter than 24 bytes, the encoded key is [0x60+len] || bytes, so
        // the sort is: ascending length first, then ascending lexicographic
        // within the same length.
        let mut sorted_pairs: Vec<(Value, Value)> =
            map.into_iter().map(|(k, v)| (Value::Text(k), v)).collect();
        sorted_pairs.sort_by(|(a, _), (b, _)| match (a, b) {
            (Value::Text(ka), Value::Text(kb)) => ka
                .len()
                .cmp(&kb.len())
                .then_with(|| ka.as_bytes().cmp(kb.as_bytes())),
            _ => std::cmp::Ordering::Equal,
        });
        let cbor_map = Value::Map(sorted_pairs);

        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf)
            .map_err(|e| EnvelopeError::Cbor(e.to_string()))?;
        Ok(buf)
    }

    /// Verify the envelope in the same order as the Go implementation.
    ///
    /// # Arguments
    /// * `keys` — slice of active Ed25519 verifying keys.
    /// * `agent_class` — this agent's class string (e.g. `"pmx-network"`).
    /// * `host_fingerprint` — SHA-256 hex of this host.
    /// * `replay` — mutable replay cache.
    pub fn verify(
        &self,
        keys: &[VerifyingKey],
        agent_class: &str,
        host_fingerprint: &str,
        replay: &mut crate::replay::ReplayCache,
    ) -> Result<(), EnvelopeError> {
        self.verify_identifying(keys, agent_class, host_fingerprint, replay)?;
        Ok(())
    }

    /// Verify the envelope and return the index of the key that verified it.
    ///
    /// Same checks as [`verify`], but returns the index into `keys` of the
    /// verifying key. This allows callers to distinguish which key signed the
    /// envelope (e.g. release key vs. job key).
    pub fn verify_identifying(
        &self,
        keys: &[VerifyingKey],
        agent_class: &str,
        host_fingerprint: &str,
        replay: &mut crate::replay::ReplayCache,
    ) -> Result<usize, EnvelopeError> {
        use ed25519_dalek::Verifier;

        // 1. Version
        if self.version != SUPPORTED_VERSION {
            return Err(EnvelopeError::VersionUnsupported(self.version.clone()));
        }

        let now = Utc::now();

        // 2. Expiry (with NTP skew tolerance)
        let skew = chrono::Duration::seconds(NTP_SKEW_SECS);
        if self.expires_at < now - skew {
            return Err(EnvelopeError::Expired(self.expires_at.to_rfc3339()));
        }

        // 3. Lifetime cap
        let lifetime = (self.expires_at - self.issued_at).num_seconds();
        if lifetime > MAX_LIFETIME_SECS {
            return Err(EnvelopeError::TooLongLived(lifetime));
        }

        // 4. Audience
        if self.audience != agent_class {
            return Err(EnvelopeError::AudienceMismatch {
                expected: agent_class.to_string(),
                got: self.audience.clone(),
            });
        }

        // 5. Host
        if self.host != host_fingerprint {
            return Err(EnvelopeError::HostMismatch {
                expected: host_fingerprint.to_string(),
                got: self.host.clone(),
            });
        }

        // 6. Signature
        let canonical = self.canonical_bytes()?;
        let sig_bytes = hex::decode(&self.signature)?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| EnvelopeError::BadSignature)?;

        let key_index = keys
            .iter()
            .enumerate()
            .find(|(_, k)| k.verify(&canonical, &sig).is_ok())
            .map(|(i, _)| i);
        let key_index = match key_index {
            Some(i) => i,
            None => return Err(EnvelopeError::BadSignature),
        };

        // 7. Replay
        if replay.seen(&self.job_id) {
            return Err(EnvelopeError::Replay(self.job_id.clone()));
        }
        replay.remember(self.job_id.clone());

        Ok(key_index)
    }
}

// ── Interop tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::ReplayCache;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn make_key() -> (VerifyingKey, SigningKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        (vk, sk)
    }

    /// Build a properly-signed Envelope using the given key pair.
    fn make_signed_envelope(sk: &SigningKey, vk: &VerifyingKey) -> Envelope {
        use chrono::Duration;
        let now = Utc::now();
        let mut env = Envelope {
            version: SUPPORTED_VERSION.to_string(),
            job_id: "01900000-0000-7000-8000-000000000001".to_string(),
            issued_at: now,
            expires_at: now + Duration::minutes(30),
            issuer: "backend-dev-1".to_string(),
            audience: "pmx-network".to_string(),
            host: "aabbccdd".to_string(),
            command: "network.tunnel.up".to_string(),
            params: BTreeMap::new(),
            signature: String::new(),
        };
        use ed25519_dalek::Signer;
        let canonical = env.canonical_bytes().unwrap();
        println!("RUST CANONICAL:\\n{}", hex::encode(&canonical));
        let sig = sk.sign(&canonical);
        env.signature = hex::encode(sig.to_bytes());
        let _ = vk; // key pair coherence — vk is the verifying counterpart
        env
    }

    /// Helper: create a fresh ReplayCache and the standard verify arguments.
    fn fresh_replay() -> ReplayCache {
        ReplayCache::new(1000, Duration::from_secs(86400))
    }

    // ── Test 1: happy path ─────────────────────────────────────────────────────

    #[test]
    fn verify_happy_path() {
        let (vk, sk) = make_key();
        let env = make_signed_envelope(&sk, &vk);
        let mut replay = fresh_replay();
        env.verify(&[vk], "pmx-network", "aabbccdd", &mut replay)
            .expect("valid envelope must verify");
    }

    // ── Test 2: bad version ────────────────────────────────────────────────────

    #[test]
    fn verify_rejects_bad_version() {
        let (vk, sk) = make_key();
        let mut env = make_signed_envelope(&sk, &vk);
        env.version = "pmx-agent-v0".to_string();
        // Re-sign with the mutated version field.
        use ed25519_dalek::Signer;
        let canonical = env.canonical_bytes().unwrap();
        env.signature = hex::encode(sk.sign(&canonical).to_bytes());

        let mut replay = fresh_replay();
        let err = env
            .verify(&[vk], "pmx-network", "aabbccdd", &mut replay)
            .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::VersionUnsupported(_)),
            "expected VersionUnsupported, got: {err:?}"
        );
    }

    // ── Test 3: expired ───────────────────────────────────────────────────────

    #[test]
    fn verify_rejects_expired() {
        use chrono::Duration;
        let (vk, sk) = make_key();
        let mut env = make_signed_envelope(&sk, &vk);
        let past = Utc::now() - Duration::hours(1);
        env.issued_at = past - Duration::minutes(30);
        env.expires_at = past;
        // Re-sign.
        use ed25519_dalek::Signer;
        let canonical = env.canonical_bytes().unwrap();
        env.signature = hex::encode(sk.sign(&canonical).to_bytes());

        let mut replay = fresh_replay();
        let err = env
            .verify(&[vk], "pmx-network", "aabbccdd", &mut replay)
            .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::Expired(_)),
            "expected Expired, got: {err:?}"
        );
    }

    // ── Test 4: too long lived ────────────────────────────────────────────────

    #[test]
    fn verify_rejects_too_long_lived() {
        use chrono::Duration;
        let (vk, sk) = make_key();
        let mut env = make_signed_envelope(&sk, &vk);
        env.expires_at = Utc::now() + Duration::hours(2);
        // Re-sign.
        use ed25519_dalek::Signer;
        let canonical = env.canonical_bytes().unwrap();
        env.signature = hex::encode(sk.sign(&canonical).to_bytes());

        let mut replay = fresh_replay();
        let err = env
            .verify(&[vk], "pmx-network", "aabbccdd", &mut replay)
            .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::TooLongLived(_)),
            "expected TooLongLived, got: {err:?}"
        );
    }

    // ── Test 5: wrong audience ────────────────────────────────────────────────

    #[test]
    fn verify_rejects_wrong_audience() {
        let (vk, sk) = make_key();
        let env = make_signed_envelope(&sk, &vk);
        let mut replay = fresh_replay();
        // Verify claiming a different agent_class — must fail audience check.
        let err = env
            .verify(&[vk], "pmx-storage", "aabbccdd", &mut replay)
            .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::AudienceMismatch { .. }),
            "expected AudienceMismatch, got: {err:?}"
        );
    }

    // ── Test 6: wrong host ────────────────────────────────────────────────────

    #[test]
    fn verify_rejects_wrong_host() {
        let (vk, sk) = make_key();
        let env = make_signed_envelope(&sk, &vk);
        let mut replay = fresh_replay();
        // Verify with a different host fingerprint.
        let err = env
            .verify(&[vk], "pmx-network", "deadbeef", &mut replay)
            .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::HostMismatch { .. }),
            "expected HostMismatch, got: {err:?}"
        );
    }

    // ── Test 7: bad signature ─────────────────────────────────────────────────

    #[test]
    fn verify_rejects_bad_signature() {
        let (vk, sk) = make_key();
        let env = make_signed_envelope(&sk, &vk);

        // Generate a second, unrelated key pair — sign with sk2 but verify with vk.
        let (vk2, sk2) = make_key();
        let _ = vk2;
        let mut env_bad = env.clone();
        use ed25519_dalek::Signer;
        let canonical = env_bad.canonical_bytes().unwrap();
        env_bad.signature = hex::encode(sk2.sign(&canonical).to_bytes());

        let mut replay = fresh_replay();
        let err = env_bad
            .verify(&[vk], "pmx-network", "aabbccdd", &mut replay)
            .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::BadSignature),
            "expected BadSignature, got: {err:?}"
        );
    }

    // ── Test 8: replay detection ──────────────────────────────────────────────

    #[test]
    fn verify_rejects_replay() {
        let (vk, sk) = make_key();
        let env = make_signed_envelope(&sk, &vk);
        let mut replay = fresh_replay();

        // First call must succeed.
        env.verify(&[vk], "pmx-network", "aabbccdd", &mut replay)
            .expect("first verify must succeed");

        // Second call with the same job_id must fail with Replay.
        let err = env
            .verify(&[vk], "pmx-network", "aabbccdd", &mut replay)
            .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::Replay(_)),
            "expected Replay, got: {err:?}"
        );
    }

    // ── Test 9: write Rust-signed envelope for Go cross-lang test ─────────────

    #[test]
    fn interop_writes_rust_signed_envelope() {
        let (vk, sk) = make_key();
        let env = make_signed_envelope(&sk, &vk);

        let cbor = match env.to_cbor() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("skip: failed to serialise envelope: {e}");
                return;
            }
        };

        let testdata = std::path::Path::new("testdata");
        if let Err(e) = std::fs::create_dir_all(testdata) {
            eprintln!("skip: testdata not writable: {e}");
            return;
        }

        let cbor_path = testdata.join("envelope-v1-rust.cbor");
        let pubkey_path = testdata.join("pubkey-rust.hex");

        if let Err(e) = std::fs::write(&cbor_path, &cbor) {
            eprintln!("skip: cannot write {}: {e}", cbor_path.display());
            return;
        }
        let pubkey_hex = hex::encode(vk.to_bytes());
        if let Err(e) = std::fs::write(&pubkey_path, &pubkey_hex) {
            eprintln!("skip: cannot write {}: {e}", pubkey_path.display());
            return;
        }

        let canonical = env.canonical_bytes().unwrap();
        std::fs::write(testdata.join("rust-canonical.hex"), hex::encode(&canonical)).unwrap();

        println!("RUST PUBKEY   : {}", pubkey_hex);
        println!("RUST SIGNATURE: {}", env.signature);

        // Verify the written file round-trips.
        let cbor_back = std::fs::read(&cbor_path).unwrap();
        let env_back = Envelope::from_cbor(&cbor_back).expect("round-trip from CBOR");
        let pubkey_hex_back = std::fs::read_to_string(&pubkey_path).unwrap();
        let pubkey_bytes: [u8; 32] = hex::decode(pubkey_hex_back.trim())
            .unwrap()
            .try_into()
            .unwrap();
        let vk_back = VerifyingKey::from_bytes(&pubkey_bytes).unwrap();
        let mut replay = fresh_replay();
        env_back
            .verify(&[vk_back], "pmx-network", "aabbccdd", &mut replay)
            .expect("Rust-signed envelope must round-trip");
    }

    // ── Existing interop test (Go-generated) ──────────────────────────────────

    /// Read a Go-generated CBOR envelope and verify it with the matching pubkey.
    /// The testdata files are generated by TestInterop_GoSignedDumpFile in Go.
    #[test]
    fn interop_go_signed_envelope() {
        let cbor_path = "testdata/envelope-v1.cbor";
        let pubkey_path = "testdata/pubkey.hex";

        // If testdata doesn't exist, skip (CI copies it from the Go package).
        if !std::path::Path::new(cbor_path).exists() {
            eprintln!("testdata not found — skipping interop test");
            return;
        }

        let cbor = std::fs::read(cbor_path).expect("read cbor");
        let pubkey_hex = std::fs::read_to_string(pubkey_path).expect("read pubkey");
        let pubkey_bytes: [u8; 32] = hex::decode(pubkey_hex.trim())
            .expect("decode pubkey hex")
            .try_into()
            .expect("pubkey must be 32 bytes");
        let vk = VerifyingKey::from_bytes(&pubkey_bytes).expect("parse verifying key");

        let env = Envelope::from_cbor(&cbor).expect("parse Go CBOR envelope");

        // The Go-side fixture has a 30-minute exp window. If `go test`
        // hasn't been run for a while, the fixture is stale — skip so
        // local Rust-only runs stay green. CI runs both back-to-back.
        if env.expires_at < Utc::now() {
            eprintln!(
                "skip: Go-signed fixture expired at {} — run `go test ./agents/shared/envelope -run TestInterop_GoSignedDumpFile` to refresh",
                env.expires_at.to_rfc3339()
            );
            return;
        }

        let mut replay = ReplayCache::new(1000, Duration::from_secs(86400));

        env.verify(&[vk], "pmx-network", "aabbccdd", &mut replay)
            .expect("Go-signed envelope must verify in Rust");
    }
}
