//! Integration tests for the pmx-updater envelope module.
//!
//! Covers: empty stdin, bad CBOR, missing keyset, missing host fingerprint,
//! wrong audience, wrong host, replay detection, and dual-key identification.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

fn make_keypair() -> (VerifyingKey, SigningKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    (vk, sk)
}

/// Build a properly-signed CBOR envelope for pmx-updater.
fn make_updater_envelope(sk: &SigningKey, command: &str, host_fp: &str) -> Vec<u8> {
    use chrono::{Duration, Utc};
    let now = Utc::now();
    let mut params = BTreeMap::new();
    params.insert("override_window".to_string(), serde_json::json!(false));

    let env = pmx_shared::envelope::Envelope {
        version: pmx_shared::envelope::SUPPORTED_VERSION.to_string(),
        job_id: format!("test-{}", uuid::Uuid::new_v4()),
        issued_at: now,
        expires_at: now + Duration::minutes(30),
        issuer: "backend-test".to_string(),
        audience: "pmx-updater".to_string(),
        host: host_fp.to_string(),
        command: command.to_string(),
        params,
        signature: String::new(),
    };

    let canonical = env.canonical_bytes().unwrap();
    let sig = sk.sign(&canonical);
    let mut env = env;
    env.signature = hex::encode(sig.to_bytes());

    env.to_cbor().unwrap()
}

/// Write a keyset file with one or more public keys.
fn write_keyset(dir: &std::path::Path, keys: &[VerifyingKey]) -> std::path::PathBuf {
    let path = dir.join("keyset.pub");
    let content: String = keys
        .iter()
        .map(|k| hex::encode(k.to_bytes()))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, content).unwrap();
    path
}

/// Write a host fingerprint file.
fn write_host_fingerprint(dir: &std::path::Path, fp: &str) -> std::path::PathBuf {
    let path = dir.join("host-fingerprint");
    std::fs::write(&path, fp).unwrap();
    path
}

#[test]
fn empty_stdin_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (vk, _sk) = make_keypair();
    let ks_path = write_keyset(dir.path(), &[vk]);
    let fp_path = write_host_fingerprint(dir.path(), "aabbccdd");

    let err = pmx_updater::envelope::read_and_verify_envelope(
        &[],
        ks_path.to_str().unwrap(),
        fp_path.to_str().unwrap(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("empty envelope"));
}

#[test]
fn bad_cbor_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (vk, _sk) = make_keypair();
    let ks_path = write_keyset(dir.path(), &[vk]);
    let fp_path = write_host_fingerprint(dir.path(), "aabbccdd");

    let err = pmx_updater::envelope::read_and_verify_envelope(
        b"this is not cbor",
        ks_path.to_str().unwrap(),
        fp_path.to_str().unwrap(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("cbor") || err.to_string().contains("CBOR"));
}

#[test]
fn missing_keyset_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (vk, sk) = make_keypair();
    let _ = vk;
    let fp_path = write_host_fingerprint(dir.path(), "aabbccdd");
    let cbor = make_updater_envelope(&sk, "update.agent.check", "aabbccdd");

    let err = pmx_updater::envelope::read_and_verify_envelope(
        &cbor,
        "/tmp/nonexistent-keyset-12345.pub",
        fp_path.to_str().unwrap(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("keyset") || err.to_string().contains("read"));
}

#[test]
fn empty_host_fingerprint_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (vk, sk) = make_keypair();
    let ks_path = write_keyset(dir.path(), &[vk]);
    // Write empty fingerprint
    let fp_path = dir.path().join("host-fingerprint");
    std::fs::write(&fp_path, "").unwrap();

    let cbor = make_updater_envelope(&sk, "update.agent.check", "aabbccdd");

    let err = pmx_updater::envelope::read_and_verify_envelope(
        &cbor,
        ks_path.to_str().unwrap(),
        fp_path.to_str().unwrap(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("fingerprint") || err.to_string().contains("empty"));
}

#[test]
fn wrong_audience_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (vk, sk) = make_keypair();
    let ks_path = write_keyset(dir.path(), &[vk]);
    let fp_path = write_host_fingerprint(dir.path(), "aabbccdd");

    // Build envelope with wrong audience
    use chrono::{Duration, Utc};
    let now = Utc::now();
    let env = pmx_shared::envelope::Envelope {
        version: pmx_shared::envelope::SUPPORTED_VERSION.to_string(),
        job_id: format!("test-{}", uuid::Uuid::new_v4()),
        issued_at: now,
        expires_at: now + Duration::minutes(30),
        issuer: "backend-test".to_string(),
        audience: "pmx-network".to_string(), // wrong audience
        host: "aabbccdd".to_string(),
        command: "update.agent.check".to_string(),
        params: BTreeMap::new(),
        signature: String::new(),
    };
    let canonical = env.canonical_bytes().unwrap();
    let sig = sk.sign(&canonical);
    let mut env = env;
    env.signature = hex::encode(sig.to_bytes());
    let cbor = env.to_cbor().unwrap();

    let err = pmx_updater::envelope::read_and_verify_envelope(
        &cbor,
        ks_path.to_str().unwrap(),
        fp_path.to_str().unwrap(),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("audience") || err.to_string().contains("AudienceMismatch"),
        "expected audience error, got: {err}"
    );
}

#[test]
fn wrong_host_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (vk, sk) = make_keypair();
    let ks_path = write_keyset(dir.path(), &[vk]);
    let fp_path = write_host_fingerprint(dir.path(), "deadbeef"); // different host

    let cbor = make_updater_envelope(&sk, "update.agent.check", "aabbccdd");

    let err = pmx_updater::envelope::read_and_verify_envelope(
        &cbor,
        ks_path.to_str().unwrap(),
        fp_path.to_str().unwrap(),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("host") || err.to_string().contains("HostMismatch"),
        "expected host error, got: {err}"
    );
}

#[test]
fn bad_signature_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (vk, _sk) = make_keypair();
    let (vk2, sk2) = make_keypair(); // different key
    let _ = vk2;
    let ks_path = write_keyset(dir.path(), &[vk]);
    let fp_path = write_host_fingerprint(dir.path(), "aabbccdd");

    // Sign with sk2 but verify with vk
    let cbor = make_updater_envelope(&sk2, "update.agent.check", "aabbccdd");

    let err = pmx_updater::envelope::read_and_verify_envelope(
        &cbor,
        ks_path.to_str().unwrap(),
        fp_path.to_str().unwrap(),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("signature") || err.to_string().contains("BadSignature"),
        "expected signature error, got: {err}"
    );
}

#[test]
fn replay_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (vk, sk) = make_keypair();
    let ks_path = write_keyset(dir.path(), &[vk]);
    let fp_path = write_host_fingerprint(dir.path(), "aabbccdd");

    let cbor = make_updater_envelope(&sk, "update.agent.check", "aabbccdd");

    // First call succeeds
    pmx_updater::envelope::read_and_verify_envelope(
        &cbor,
        ks_path.to_str().unwrap(),
        fp_path.to_str().unwrap(),
    )
    .expect("first verify must succeed");

    // Second call with same job_id must fail
    let err = pmx_updater::envelope::read_and_verify_envelope(
        &cbor,
        ks_path.to_str().unwrap(),
        fp_path.to_str().unwrap(),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("replay") || err.to_string().contains("Replay"),
        "expected replay error, got: {err}"
    );
}

#[test]
fn dual_key_identification_release_vs_job() {
    // Key 0 = release key, Key 1 = job key
    let dir = tempfile::tempdir().unwrap();
    let (release_vk, release_sk) = make_keypair();
    let (job_vk, job_sk) = make_keypair();
    let ks_path = write_keyset(dir.path(), &[release_vk, job_vk]);
    let fp_path = write_host_fingerprint(dir.path(), "aabbccdd");

    // Sign with release key (index 0)
    let cbor_release = make_updater_envelope(&release_sk, "update.agent.check", "aabbccdd");
    let verified_release = pmx_updater::envelope::read_and_verify_envelope(
        &cbor_release,
        ks_path.to_str().unwrap(),
        fp_path.to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        verified_release.signing_key_index, 0,
        "release key must be index 0"
    );

    // Sign with job key (index 1)
    let cbor_job = make_updater_envelope(&job_sk, "update.agent.check", "aabbccdd");
    let verified_job = pmx_updater::envelope::read_and_verify_envelope(
        &cbor_job,
        ks_path.to_str().unwrap(),
        fp_path.to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(verified_job.signing_key_index, 1, "job key must be index 1");
}

#[test]
fn happy_path_verifies_successfully() {
    let dir = tempfile::tempdir().unwrap();
    let (vk, sk) = make_keypair();
    let ks_path = write_keyset(dir.path(), &[vk]);
    let fp_path = write_host_fingerprint(dir.path(), "aabbccdd");

    let cbor = make_updater_envelope(&sk, "update.agent.check", "aabbccdd");
    let verified = pmx_updater::envelope::read_and_verify_envelope(
        &cbor,
        ks_path.to_str().unwrap(),
        fp_path.to_str().unwrap(),
    )
    .expect("valid envelope must verify");

    assert_eq!(verified.envelope.audience, "pmx-updater");
    assert_eq!(verified.envelope.command, "update.agent.check");
    assert_eq!(verified.signing_key_index, 0);
}
