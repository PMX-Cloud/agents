//! Keyset with rotation overlap — mirrors agents/shared/envelope/keyset.go.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parking_lot::RwLock;
use std::sync::Arc;

/// One Ed25519 verifying key with an optional not-after timestamp.
pub struct KeyEntry {
    pub key: VerifyingKey,
    /// None means the key never expires.
    pub not_after: Option<DateTime<Utc>>,
}

impl KeyEntry {
    pub fn is_active(&self) -> bool {
        match self.not_after {
            None => true,
            Some(t) => Utc::now() < t,
        }
    }
}

/// A set of Ed25519 public keys used to verify envelope signatures.
pub struct KeySet {
    inner: Arc<RwLock<Vec<KeyEntry>>>,
}

impl KeySet {
    /// Parse a keyset from a multiline string (same format as the Go version).
    ///
    /// Each line: `<64-hex-char pubkey> [<RFC-3339 not-after>]`
    /// Lines starting with `#` or empty lines are ignored.
    pub fn parse(content: &str) -> Result<Self, String> {
        let mut entries = Vec::new();
        for (i, line) in content.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() || parts.len() > 2 {
                return Err(format!("line {}: expected 1 or 2 fields", i + 1));
            }
            let key_bytes =
                hex::decode(parts[0]).map_err(|e| format!("line {}: hex decode: {}", i + 1, e))?;
            let key_arr: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| format!("line {}: key must be 32 bytes", i + 1))?;
            let key = VerifyingKey::from_bytes(&key_arr)
                .map_err(|e| format!("line {}: invalid key: {}", i + 1, e))?;

            let not_after = if parts.len() == 2 {
                let t = DateTime::parse_from_rfc3339(parts[1])
                    .map_err(|e| format!("line {}: invalid not-after: {}", i + 1, e))?
                    .with_timezone(&Utc);
                Some(t)
            } else {
                None
            };

            entries.push(KeyEntry { key, not_after });
        }
        if entries.is_empty() {
            return Err("keyset contains no keys".to_string());
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(entries)),
        })
    }

    /// Returns true if `signature` is valid over `message` using any active key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.verify_identifying(message, signature).is_some()
    }

    /// Returns the index of the active key that verified `signature` over `message`,
    /// or `None` if no key verified. Index corresponds to the key's position in the
    /// parsed keyset file (0 = first line, 1 = second line, etc.).
    pub fn verify_identifying(&self, message: &[u8], signature: &[u8]) -> Option<usize> {
        let sig = match Signature::from_slice(signature) {
            Ok(s) => s,
            Err(_) => return None,
        };
        let inner = self.inner.read();
        inner
            .iter()
            .enumerate()
            .filter(|(_, e)| e.is_active())
            .find(|(_, e)| e.key.verify(message, &sig).is_ok())
            .map(|(i, _)| i)
    }

    /// Returns the verifying key at the given index, if it exists and is active.
    pub fn active_key_at(&self, index: usize) -> Option<VerifyingKey> {
        let inner = self.inner.read();
        inner
            .get(index)
            .filter(|e| e.is_active())
            .map(|e| e.key)
    }

    /// Returns the active verifying keys (for use with envelope::Envelope::verify).
    pub fn active_keys(&self) -> Vec<VerifyingKey> {
        self.inner
            .read()
            .iter()
            .filter(|e| e.is_active())
            .map(|e| e.key)
            .collect()
    }

    /// Atomically replace the keyset, dropping expired keys.
    pub fn update(&self, new_set: KeySet) {
        let active: Vec<KeyEntry> = {
            let inner = new_set.inner.read();
            inner
                .iter()
                .filter(|e| e.is_active())
                .map(|e| KeyEntry {
                    key: e.key,
                    not_after: e.not_after,
                })
                .collect()
        };
        *self.inner.write() = active;
    }

    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
