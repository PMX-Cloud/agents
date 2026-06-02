use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

/// Hex-encoded Ed25519 release public key baked in at compile time by build.rs.
/// Empty on dev / pre-ceremony builds — callers fall back to the config key.
pub const BAKED_RELEASE_PUBKEY_HEX: &str = env!("RELEASE_PUBKEY_HEX");

/// Returns the baked-in `VerifyingKey`, or `None` when the binary was built
/// before the key ceremony (BAKED_RELEASE_PUBKEY_HEX is empty).
pub fn baked_release_pubkey() -> Option<VerifyingKey> {
    if BAKED_RELEASE_PUBKEY_HEX.is_empty() {
        return None;
    }
    load_pubkey(BAKED_RELEASE_PUBKEY_HEX).ok()
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("bad manifest signature")]
    BadManifestSignature,
    #[error("bad binary signature")]
    BadBinarySignature,
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("key: {0}")]
    Key(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Verify an Ed25519 signature over `bytes` using `pubkey`.
pub fn verify_manifest(
    bytes: &[u8],
    sig_bytes: &[u8],
    pubkey: &VerifyingKey,
) -> Result<(), VerifyError> {
    let sig = Signature::from_slice(sig_bytes)
        .map_err(|_| VerifyError::BadManifestSignature)?;
    pubkey
        .verify(bytes, &sig)
        .map_err(|_| VerifyError::BadManifestSignature)
}

/// Reads `path`, computes SHA-256, verifies it matches `expected_sha256`,
/// then verifies an Ed25519 signature over the SHA-256 hash bytes (not the full file).
pub fn verify_binary(
    path: &Path,
    expected_sha256: &str,
    sig_hex: &str,
    pubkey: &VerifyingKey,
) -> Result<(), VerifyError> {
    let data = std::fs::read(path)?;
    let actual = hex::encode(Sha256::digest(&data));
    if actual != expected_sha256 {
        return Err(VerifyError::HashMismatch {
            expected: expected_sha256.to_string(),
            actual,
        });
    }

    // Sig is over sha256(binary), i.e., the 32 raw digest bytes.
    let digest_bytes = Sha256::digest(&data);
    let sig_raw = hex::decode(sig_hex)?;
    let sig = Signature::from_slice(&sig_raw).map_err(|_| VerifyError::BadBinarySignature)?;
    pubkey
        .verify(digest_bytes.as_slice(), &sig)
        .map_err(|_| VerifyError::BadBinarySignature)
}

/// Loads a `VerifyingKey` from a 64-hex-character public key string.
pub fn load_pubkey(pem_or_hex: &str) -> Result<VerifyingKey, VerifyError> {
    let trimmed = pem_or_hex.trim();
    if trimmed.len() != 64 {
        return Err(VerifyError::Key(format!(
            "expected 64 hex chars, got {}",
            trimmed.len()
        )));
    }
    let raw = hex::decode(trimmed)?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| VerifyError::Key("not 32 bytes".to_string()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| VerifyError::Key(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn fresh_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn verify_manifest_happy_path() {
        let (signing_key, verifying_key) = fresh_keypair();
        let data = b"test manifest payload";
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(data);
        verify_manifest(data, sig.to_bytes().as_ref(), &verifying_key).expect("should verify");
    }

    #[test]
    fn verify_manifest_bad_sig() {
        let (signing_key, verifying_key) = fresh_keypair();
        let data = b"test manifest payload";
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(data);
        let mut bad_sig = sig.to_bytes();
        bad_sig[0] ^= 0xff; // flip a byte
        let err = verify_manifest(data, &bad_sig, &verifying_key).expect_err("should fail");
        assert!(matches!(err, VerifyError::BadManifestSignature));
    }

    #[test]
    fn verify_binary_happy_path() {
        let (signing_key, verifying_key) = fresh_keypair();
        let content = b"agent binary content";

        let mut tmp = NamedTempFile::new().expect("tempfile");
        tmp.write_all(content).expect("write");
        tmp.flush().expect("flush");

        let sha256 = hex::encode(Sha256::digest(content));
        // Sign sha256(binary)
        let digest_bytes = Sha256::digest(content);
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(digest_bytes.as_slice());
        let sig_hex = hex::encode(sig.to_bytes());

        verify_binary(tmp.path(), &sha256, &sig_hex, &verifying_key).expect("should verify");
    }

    #[test]
    fn verify_binary_hash_mismatch() {
        let (signing_key, verifying_key) = fresh_keypair();
        let content = b"agent binary content";

        let mut tmp = NamedTempFile::new().expect("tempfile");
        tmp.write_all(content).expect("write");
        tmp.flush().expect("flush");

        let wrong_sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
        let digest_bytes = Sha256::digest(content);
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(digest_bytes.as_slice());
        let sig_hex = hex::encode(sig.to_bytes());

        let err = verify_binary(tmp.path(), wrong_sha256, &sig_hex, &verifying_key)
            .expect_err("should fail on hash mismatch");
        assert!(matches!(err, VerifyError::HashMismatch { .. }));
    }

    #[test]
    fn load_pubkey_valid() {
        let (_, verifying_key) = fresh_keypair();
        let hex_str = hex::encode(verifying_key.to_bytes());
        let loaded = load_pubkey(&hex_str).expect("load pubkey");
        assert_eq!(loaded.to_bytes(), verifying_key.to_bytes());
    }

    #[test]
    fn load_pubkey_bad_length() {
        let err = load_pubkey("tooshort").expect_err("should fail");
        assert!(matches!(err, VerifyError::Key(_)));
    }
}
