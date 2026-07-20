//! Integration tests for pmx-updater.
//!
//! These tests exercise the library crate's public API end-to-end,
//! covering dispatch, maintenance window enforcement, agent update
//! check/apply, and OS update paths.

use ed25519_dalek::{Signer, SigningKey};
use pmx_updater::{
    agent_update::{self, health, manifest, swap},
    config::{Config, FilesConfig, IdentityConfig, KeysetConfig},
    maintenance,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

// ── Helpers ──────────────────────────────────────────────────────────

fn test_config(cache_path: &str) -> Config {
    Config {
        identity: IdentityConfig {
            host_fingerprint_file: "/tmp/host-fingerprint".to_string(),
            agent_name: "pmx-updater".to_string(),
            agent_arch: "amd64".to_string(),
        },
        keyset: KeysetConfig {
            path: "/tmp/keyset.pub".to_string(),
            release_pubkey: String::new(),
        },
        files: FilesConfig {
            maintenance_window_cache_path: cache_path.to_string(),
            manifest_url: String::new(),
            agents_base: "/opt/pmx-cloud/agents".to_string(),
            staging_dir: "/var/lib/pmx-cloud/updater/staging".to_string(),
        },
    }
}

// ── Dispatch integration tests ───────────────────────────────────────

#[test]
fn dispatch_maintenance_set_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("window.json");
    let _cfg = test_config(cache_path.to_str().unwrap());

    pmx_updater::maintenance::window::write_cache(
        cache_path.to_str().unwrap(),
        &serde_json::from_value(json!({
            "windows": [{ "days": ["Sun"], "start": "03:00", "end": "05:00", "tz": "UTC" }]
        }))
        .unwrap(),
    )
    .unwrap();

    let loaded =
        pmx_updater::maintenance::window::read_cache(cache_path.to_str().unwrap()).unwrap();
    assert_eq!(loaded.windows.len(), 1);
    assert_eq!(loaded.windows[0].days, vec!["Sun"]);
}

#[test]
fn dispatch_check_no_manifest_url() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("window.json");
    let cfg = test_config(cache_path.to_str().unwrap());

    let result = agent_update::check(&cfg).unwrap();
    assert_eq!(result["available"], json!(false));
    assert_eq!(result["reason"], json!("manifest_url not configured"));
}

#[test]
fn dispatch_apply_no_manifest_url() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("window.json");
    let cfg = test_config(cache_path.to_str().unwrap());

    let err = agent_update::apply(&cfg).unwrap_err();
    assert!(err.to_string().contains("manifest_url is not configured"));
}

// ── Maintenance window enforcement integration ───────────────────────

#[test]
fn maintenance_outside_window_rejected() {
    let windows = serde_json::from_value::<pmx_updater::maintenance::window::WindowSet>(json!({
        "windows": [{ "days": ["Sat"], "start": "02:00", "end": "06:00", "tz": "UTC" }]
    }))
    .unwrap();

    let err = maintenance::check_update_allowed(&windows, false, 0).unwrap_err();
    assert!(err.to_string().contains("outside_maintenance_window"));
}

#[test]
fn maintenance_override_release_key_permitted() {
    let windows = serde_json::from_value::<pmx_updater::maintenance::window::WindowSet>(json!({
        "windows": []
    }))
    .unwrap();

    maintenance::check_update_allowed(&windows, true, 0).unwrap();
}

#[test]
fn maintenance_override_job_key_rejected() {
    let windows = serde_json::from_value::<pmx_updater::maintenance::window::WindowSet>(json!({
        "windows": []
    }))
    .unwrap();

    let err = maintenance::check_update_allowed(&windows, true, 1).unwrap_err();
    assert!(err.to_string().contains("override_requires_release_key"));
}

#[test]
fn maintenance_override_job_key_index_2_also_rejected() {
    let windows = serde_json::from_value::<pmx_updater::maintenance::window::WindowSet>(json!({
        "windows": []
    }))
    .unwrap();

    let err = maintenance::check_update_allowed(&windows, true, 2).unwrap_err();
    assert!(err.to_string().contains("override_requires_release_key"));
}

// ── Manifest parsing integration ─────────────────────────────────────

#[test]
fn manifest_parse_valid() {
    let raw = json!({
        "schema": "pmx-manifest-v1",
        "version": "1.2.3",
        "issuedAt": "2026-05-12T18:00:00Z",
        "agents": [{
            "name": "pmx-updater",
            "arch": "amd64",
            "url": "https://releases.example.com/v1.2.3/pmx-updater",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
            "min_compat": "1.4.0"
        }]
    });

    let m = manifest::Manifest::parse(&serde_json::to_vec(&raw).unwrap()).unwrap();
    assert_eq!(m.version, "1.2.3");
    assert_eq!(m.agents.len(), 1);

    let entry = m.find_entry("pmx-updater", "amd64").unwrap();
    assert_eq!(entry.name, "pmx-updater");
    assert_eq!(entry.arch, "amd64");
}

#[test]
fn manifest_parse_missing_version() {
    let raw = json!({
        "schema": "pmx-manifest-v1",
        "issuedAt": "2026-05-12T18:00:00Z",
        "agents": []
    });
    let err = manifest::Manifest::parse(&serde_json::to_vec(&raw).unwrap()).unwrap_err();
    assert!(err.to_string().contains("version"));
}

#[test]
fn manifest_find_entry_missing() {
    let raw = json!({
        "schema": "pmx-manifest-v1",
        "version": "1.0.0",
        "issuedAt": "2026-05-12T18:00:00Z",
        "agents": [{
            "name": "pmx-core",
            "arch": "amd64",
            "url": "https://example.com/pmx-core",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
            "min_compat": "1.4.0"
        }]
    });

    let m = manifest::Manifest::parse(&serde_json::to_vec(&raw).unwrap()).unwrap();
    assert!(m.find_entry("pmx-updater", "amd64").is_err());
}

// ── Swap handle integration ──────────────────────────────────────────

#[test]
fn swap_handle_fields() {
    let h = swap::SwapHandle {
        agent: "pmx-core".to_string(),
        new_version: "1.2.0".to_string(),
        old_version: Some("1.1.0".to_string()),
        agents_base: std::path::PathBuf::from("/opt/pmx-cloud/agents"),
    };
    assert_eq!(h.agent, "pmx-core");
    assert_eq!(h.new_version, "1.2.0");
    assert_eq!(h.old_version, Some("1.1.0".to_string()));
}

#[test]
fn swap_extract_version_from_target() {
    // Relative symlink target: versions/1.2.0/pmx-core
    let v = swap::extract_version_from_target(
        std::path::Path::new("versions/1.2.0/pmx-core"),
        "pmx-core",
    );
    assert_eq!(v, Some("1.2.0".to_string()));

    // Absolute symlink target
    let v = swap::extract_version_from_target(
        std::path::Path::new("/opt/pmx-cloud/agents/pmx-core/versions/0.9.0/pmx-core"),
        "pmx-core",
    );
    assert_eq!(v, Some("0.9.0".to_string()));

    // Non-matching agent name
    let v = swap::extract_version_from_target(
        std::path::Path::new("versions/1.2.0/pmx-other"),
        "pmx-core",
    );
    assert_eq!(v, None);
}

// ── Health check integration ─────────────────────────────────────────

#[test]
fn health_check_nonexistent_agent() {
    // Checking a non-existent agent should fail gracefully
    let result = health::check(
        "pmx-nonexistent-agent-xyz",
        health::AgentKind::Persistent,
        "/tmp/no-such-config.conf",
    );
    assert!(result.is_err());
}

// ── Config integration ───────────────────────────────────────────────

#[test]
fn config_load_missing_file() {
    let err = Config::load("/tmp/no-such-config-file-xyz.conf").unwrap_err();
    assert!(
        err.to_string().contains("config")
            || err.to_string().contains("no such file")
            || err.to_string().contains("not found")
    );
}

#[test]
fn config_validate_empty_manifest_url_ok() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("window.json");
    let cfg = test_config(cache_path.to_str().unwrap());
    // Empty manifest_url is allowed (dev mode)
    assert!(cfg.validate().is_ok());
}

// ── Window cache roundtrip ───────────────────────────────────────────

#[test]
fn window_cache_write_read_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");

    let ws = serde_json::from_value::<pmx_updater::maintenance::window::WindowSet>(json!({
        "windows": [
            { "days": ["Mon", "Wed"], "start": "01:00", "end": "03:00", "tz": "UTC" },
            { "days": ["Sat"], "start": "02:00", "end": "06:00", "tz": "Europe/Helsinki" }
        ]
    }))
    .unwrap();

    pmx_updater::maintenance::window::write_cache(path.to_str().unwrap(), &ws).unwrap();
    let loaded = pmx_updater::maintenance::window::read_cache(path.to_str().unwrap()).unwrap();

    assert_eq!(loaded.windows.len(), 2);
    assert_eq!(loaded.windows[0].days, vec!["Mon", "Wed"]);
    assert_eq!(loaded.windows[1].tz, "Europe/Helsinki");
}

#[test]
fn window_cache_read_missing_file() {
    let result = pmx_updater::maintenance::window::read_cache("/tmp/no-such-window-cache.json");
    assert!(result.is_err());
}

// ── Envelope integration ─────────────────────────────────────────────

#[test]
fn envelope_read_and_verify_missing_keyset() {
    let dir = tempfile::tempdir().unwrap();
    let fingerprint = dir.path().join("fingerprint");
    fs::write(&fingerprint, "test-fp").unwrap();
    let keyset_path = dir.path().join("nonexistent-keyset.pub");

    // Empty envelope bytes should fail
    let result = pmx_updater::envelope::read_and_verify_envelope(
        b"",
        keyset_path.to_str().unwrap(),
        fingerprint.to_str().unwrap(),
    );
    assert!(result.is_err());
}

// ── Wiremock-based check/apply integration ───────────────────────────

fn config_with_manifest_url(manifest_url: &str) -> Config {
    Config {
        identity: IdentityConfig {
            host_fingerprint_file: "/tmp/host-fingerprint".to_string(),
            agent_name: "pmx-updater".to_string(),
            agent_arch: "amd64".to_string(),
        },
        keyset: KeysetConfig {
            path: "/tmp/keyset.pub".to_string(),
            release_pubkey: String::new(),
        },
        files: FilesConfig {
            maintenance_window_cache_path: String::new(),
            manifest_url: manifest_url.to_string(),
            agents_base: "/opt/pmx-cloud/agents".to_string(),
            staging_dir: "/var/lib/pmx-cloud/updater/staging".to_string(),
        },
    }
}

fn signed_manifest_json(version: &str) -> (Vec<u8>, Vec<u8>) {
    let manifest_bytes = serde_json::json!({
        "schema": "pmx-manifest-v1",
        "version": version,
        "issuedAt": "2026-05-20T00:00:00Z",
        "agents": [{
            "name": "pmx-updater",
            "arch": "amd64",
            "url": "https://releases.example.com/binary",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
            "min_compat": "0.1.0"
        }]
    })
    .to_string()
    .into_bytes();

    // Produce a valid Ed25519 signature over the manifest bytes
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let sig = signing_key.sign(&manifest_bytes);
    let sig_bytes = sig.to_bytes().to_vec();

    (manifest_bytes, sig_bytes)
}

#[tokio::test]
async fn check_with_mock_server_reports_available() {
    let server = MockServer::start().await;

    let (manifest_bytes, sig_bytes) = signed_manifest_json("99.0.0");

    // Mock manifest endpoint (path-specific)
    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(manifest_bytes.clone()))
        .mount(&server)
        .await;

    // Mock signature endpoint (path-specific)
    Mock::given(method("GET"))
        .and(path("/manifest.sig"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(sig_bytes.clone()))
        .mount(&server)
        .await;

    let url = server.uri();
    let cfg = config_with_manifest_url(&url);

    let result = agent_update::check_async(&cfg)
        .await
        .expect("check should succeed");
    assert_eq!(result["available"], json!(true));
    assert_eq!(result["latest"], json!("99.0.0"));
}

#[tokio::test]
async fn check_with_mock_server_same_version_not_available() {
    let server = MockServer::start().await;

    // Use current CARGO_PKG_VERSION so available=false
    let current = env!("CARGO_PKG_VERSION");
    let (manifest_bytes, sig_bytes) = signed_manifest_json(current);

    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(manifest_bytes.clone()))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/manifest.sig"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(sig_bytes.clone()))
        .mount(&server)
        .await;

    let url = server.uri();
    let cfg = config_with_manifest_url(&url);

    let result = agent_update::check_async(&cfg)
        .await
        .expect("check should succeed");
    assert_eq!(result["available"], json!(false));
}

#[tokio::test]
async fn check_with_mock_server_bad_manifest_json_errors() {
    let server = MockServer::start().await;

    let bad_bytes = b"not json at all".to_vec();
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let sig = signing_key.sign(&bad_bytes);
    let sig_bytes = sig.to_bytes().to_vec();

    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bad_bytes))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/manifest.sig"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(sig_bytes))
        .mount(&server)
        .await;

    let url = server.uri();
    let cfg = config_with_manifest_url(&url);

    let result = agent_update::check_async(&cfg).await;
    assert!(result.is_err(), "bad manifest JSON should error");
}

#[tokio::test]
async fn check_with_mock_server_missing_schema_errors() {
    let server = MockServer::start().await;

    let manifest_bytes = serde_json::json!({
        "version": "2.0.0",
        "issuedAt": "2026-05-20T00:00:00Z",
        "agents": []
    })
    .to_string()
    .into_bytes();

    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let sig = signing_key.sign(&manifest_bytes);
    let sig_bytes = sig.to_bytes().to_vec();

    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(manifest_bytes))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/manifest.sig"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(sig_bytes))
        .mount(&server)
        .await;

    let url = server.uri();
    let cfg = config_with_manifest_url(&url);

    let result = agent_update::check_async(&cfg).await;
    assert!(result.is_err(), "manifest without schema should error");
}

#[tokio::test]
async fn apply_with_mock_server_no_matching_entry_errors() {
    let server = MockServer::start().await;

    // Manifest has pmx-network, not pmx-updater
    let manifest_bytes = serde_json::json!({
        "schema": "pmx-manifest-v1",
        "version": "99.0.0",
        "issuedAt": "2026-05-20T00:00:00Z",
        "agents": [{
            "name": "pmx-network",
            "arch": "amd64",
            "url": "https://releases.example.com/binary",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
            "min_compat": "0.1.0"
        }]
    })
    .to_string()
    .into_bytes();

    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let sig = signing_key.sign(&manifest_bytes);
    let sig_bytes = sig.to_bytes().to_vec();

    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(manifest_bytes))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/manifest.sig"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(sig_bytes))
        .mount(&server)
        .await;

    let url = server.uri();
    let cfg = config_with_manifest_url(&url);

    let result = agent_update::apply_async(&cfg).await;
    assert!(result.is_err(), "apply with no matching entry should error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("find agent entry") || err_msg.contains("entry"),
        "error should mention missing entry: {err_msg}"
    );
}

#[tokio::test]
async fn apply_with_mock_server_binary_fetch_succeeds_but_health_fails() {
    let server = MockServer::start().await;

    // Create a real binary file with correct sha256
    let binary_content = b"#!/bin/sh\necho hello\n";
    let binary_sha256 = hex::encode(Sha256::digest(binary_content));

    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let sig = signing_key.sign(Sha256::digest(binary_content).as_slice());
    let sig_hex = hex::encode(sig.to_bytes());

    let manifest_bytes = serde_json::json!({
        "schema": "pmx-manifest-v1",
        "version": "99.0.0",
        "issuedAt": "2026-05-20T00:00:00Z",
        "agents": [{
            "name": "pmx-core",
            "arch": "amd64",
            "url": format!("{}/binary", server.uri()),
            "sha256": binary_sha256,
            "sig": sig_hex,
            "min_compat": "0.1.0"
        }]
    })
    .to_string()
    .into_bytes();

    let manifest_sig = signing_key.sign(&manifest_bytes);
    let manifest_sig_bytes = manifest_sig.to_bytes().to_vec();

    // Mock manifest endpoint (path-specific)
    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(manifest_bytes))
        .mount(&server)
        .await;

    // Mock signature endpoint (path-specific)
    Mock::given(method("GET"))
        .and(path("/manifest.sig"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(manifest_sig_bytes))
        .mount(&server)
        .await;

    // Mock binary endpoint (path-specific)
    Mock::given(method("GET"))
        .and(path("/binary"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(binary_content.to_vec()))
        .mount(&server)
        .await;

    // Use pmx-core (not pmx-updater) to avoid self-update fork path
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("staging");
    let agents_base = dir.path().join("agents");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::create_dir_all(agents_base.join("pmx-core").join("versions")).unwrap();

    let cfg = Config {
        identity: IdentityConfig {
            host_fingerprint_file: "/tmp/host-fingerprint".to_string(),
            agent_name: "pmx-core".to_string(),
            agent_arch: "amd64".to_string(),
        },
        keyset: KeysetConfig {
            path: "/tmp/keyset.pub".to_string(),
            // Leave release_pubkey empty — no baked-in key in dev builds,
            // so manifest signature verification is skipped and we reach
            // the health-check path we actually want to test.
            release_pubkey: String::new(),
        },
        files: FilesConfig {
            maintenance_window_cache_path: String::new(),
            manifest_url: server.uri(),
            agents_base: agents_base.to_str().unwrap().to_string(),
            staging_dir: staging.to_str().unwrap().to_string(),
        },
    };

    let result = agent_update::apply_async(&cfg).await;
    // Health check will fail since pmx-core isn't really installed,
    // and rollback should also fail since there's no old version.
    assert!(result.is_err(), "apply should fail when health check fails");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("health check") || err_msg.contains("rollback"),
        "error should mention health check or rollback: {err_msg}"
    );
}
