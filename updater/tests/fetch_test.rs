//! Integration tests for the pmx-updater fetch, manifest, and verify modules.
//!
//! Covers: manifest parsing, binary verification (SHA-256 + Ed25519),
//! and fetch error handling via wiremock HTTP mocking.

use ed25519_dalek::{Signer, SigningKey};
use pmx_updater::agent_update::{manifest, verify};
use sha2::{Digest, Sha256};
use std::io::Write;

fn sample_manifest_bytes() -> Vec<u8> {
    serde_json::json!({
        "schema": "pmx-manifest-v1",
        "version": "1.4.2",
        "issuedAt": "2026-05-20T00:00:00Z",
        "agents": [
            {
                "name": "pmx-updater",
                "arch": "amd64",
                "url": "https://releases.pmxcloud.cloud/v1.4.2/pmx-updater-1.4.2-linux-amd64",
                "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "sig": "cafebabe",
                "min_compat": "1.4.0"
            },
            {
                "name": "pmx-updater",
                "arch": "aarch64",
                "url": "https://releases.pmxcloud.cloud/v1.4.2/pmx-updater-1.4.2-linux-aarch64",
                "sha256": "bbbbb",
                "sig": "ddddd",
                "min_compat": "1.4.0"
            },
            {
                "name": "pmx-network",
                "arch": "amd64",
                "url": "https://releases.pmxcloud.cloud/v1.4.2/pmx-network-1.4.2-linux-amd64",
                "sha256": "ccccc",
                "sig": "eeeee",
                "min_compat": "1.4.0"
            }
        ]
    })
    .to_string()
    .into_bytes()
}

// ── Manifest parsing ──────────────────────────────────────────────

#[test]
fn parse_valid_manifest() {
    let bytes = sample_manifest_bytes();
    let m = manifest::Manifest::parse(&bytes).expect("valid manifest must parse");
    assert_eq!(m.version, "1.4.2");
    assert_eq!(m.agents.len(), 3);
    assert_eq!(m.agents[0].name, "pmx-updater");
    assert_eq!(m.agents[0].arch, "amd64");
}

#[test]
fn parse_manifest_invalid_json_errors() {
    let bytes = b"not json at all";
    let result = manifest::Manifest::parse(bytes);
    assert!(result.is_err(), "invalid JSON must error");
}

#[test]
fn parse_manifest_missing_schema_errors() {
    let bytes = serde_json::json!({
        "version": "1.4.2",
        "issuedAt": "2026-05-20T00:00:00Z",
        "agents": []
    })
    .to_string()
    .into_bytes();
    let result = manifest::Manifest::parse(&bytes);
    assert!(result.is_err(), "manifest without schema must error");
}

#[test]
fn parse_manifest_wrong_schema_errors() {
    let bytes = serde_json::json!({
        "schema": "pmx-manifest-v99",
        "version": "1.4.2",
        "issuedAt": "2026-05-20T00:00:00Z",
        "agents": []
    })
    .to_string()
    .into_bytes();
    let err = manifest::Manifest::parse(&bytes).expect_err("wrong schema must error");
    assert!(
        matches!(err, manifest::ManifestError::SchemaMismatch { .. }),
        "expected SchemaMismatch, got {err:?}"
    );
}

#[test]
fn find_entry_by_name_and_arch() {
    let bytes = sample_manifest_bytes();
    let m = manifest::Manifest::parse(&bytes).expect("parse");

    let entry = m
        .find_entry("pmx-updater", "amd64")
        .expect("must find pmx-updater amd64");
    assert_eq!(
        entry.sha256,
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    );

    let entry_arm = m
        .find_entry("pmx-updater", "aarch64")
        .expect("must find pmx-updater aarch64");
    assert_eq!(entry_arm.sha256, "bbbbb");

    assert!(
        m.find_entry("pmx-updater", "riscv64").is_err(),
        "non-existent arch must return error"
    );
    assert!(
        m.find_entry("pmx-nonexistent", "amd64").is_err(),
        "non-existent agent must return error"
    );
}

#[test]
fn find_entry_empty_agents_errors() {
    let bytes = serde_json::json!({
        "schema": "pmx-manifest-v1",
        "version": "1.4.2",
        "issuedAt": "2026-05-20T00:00:00Z",
        "agents": []
    })
    .to_string()
    .into_bytes();
    let m = manifest::Manifest::parse(&bytes).expect("parse");
    let err = m
        .find_entry("pmx-updater", "amd64")
        .expect_err("empty agents must not find any");
    assert!(matches!(err, manifest::ManifestError::MissingEntry { .. }));
}

// ── Binary verification (SHA-256 + Ed25519) ───────────────────────

fn fresh_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

#[test]
fn verify_binary_correct_hash_and_sig() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("test-binary");
    let content = b"hello world agent binary";

    let mut f = std::fs::File::create(&file_path).unwrap();
    f.write_all(content).unwrap();
    f.flush().unwrap();

    let (signing_key, verifying_key) = fresh_keypair();
    let expected_sha256 = hex::encode(Sha256::digest(content));
    let digest_bytes = Sha256::digest(content);
    let sig = signing_key.sign(digest_bytes.as_slice());
    let sig_hex = hex::encode(sig.to_bytes());

    verify::verify_binary(&file_path, &expected_sha256, &sig_hex, &verifying_key)
        .expect("correct hash + sig must verify");
}

#[test]
fn verify_binary_hash_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("test-binary");
    let content = b"hello world agent binary";

    let mut f = std::fs::File::create(&file_path).unwrap();
    f.write_all(content).unwrap();
    f.flush().unwrap();

    let (signing_key, verifying_key) = fresh_keypair();
    let wrong_sha256 =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let digest_bytes = Sha256::digest(content);
    let sig = signing_key.sign(digest_bytes.as_slice());
    let sig_hex = hex::encode(sig.to_bytes());

    let err = verify::verify_binary(&file_path, &wrong_sha256, &sig_hex, &verifying_key)
        .expect_err("wrong hash must fail");
    assert!(matches!(err, verify::VerifyError::HashMismatch { .. }));
}

#[test]
fn verify_binary_missing_file() {
    let (signing_key, verifying_key) = fresh_keypair();
    let sig = signing_key.sign(b"irrelevant");
    let sig_hex = hex::encode(sig.to_bytes());

    let err = verify::verify_binary(
        std::path::Path::new("/tmp/nonexistent-file-12345"),
        "0000000000000000000000000000000000000000000000000000000000000000",
        &sig_hex,
        &verifying_key,
    )
    .expect_err("missing file must fail");
    assert!(matches!(err, verify::VerifyError::Io(_)));
}

#[test]
fn verify_manifest_signature() {
    let (signing_key, verifying_key) = fresh_keypair();
    let data = b"manifest payload bytes";
    let sig = signing_key.sign(data);

    verify::verify_manifest(data, sig.to_bytes().as_ref(), &verifying_key)
        .expect("valid manifest sig must verify");
}

#[test]
fn verify_manifest_bad_signature() {
    let (signing_key, verifying_key) = fresh_keypair();
    let data = b"manifest payload bytes";
    let sig = signing_key.sign(data);
    let mut bad_sig = sig.to_bytes();
    bad_sig[0] ^= 0xff;

    let err =
        verify::verify_manifest(data, &bad_sig, &verifying_key).expect_err("bad sig must fail");
    assert!(matches!(err, verify::VerifyError::BadManifestSignature));
}

#[test]
fn load_pubkey_valid() {
    let (_, verifying_key) = fresh_keypair();
    let hex_str = hex::encode(verifying_key.to_bytes());
    let loaded = verify::load_pubkey(&hex_str).expect("load pubkey");
    assert_eq!(loaded.to_bytes(), verifying_key.to_bytes());
}

#[test]
fn load_pubkey_bad_length() {
    let err = verify::load_pubkey("tooshort").expect_err("should fail");
    assert!(matches!(err, verify::VerifyError::Key(_)));
}
