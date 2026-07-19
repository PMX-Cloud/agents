//! Integration tests for the pmx-updater health module.
//!
//! Covers: sentinel-based health check, service health check,
//! and health status reporting.

use std::fs;

/// Helper: create a minimal config directory structure for testing.
fn setup_test_env() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn sentinel_create_and_read_roundtrip() {
    let dir = setup_test_env();
    let sentinel_path = dir.path().join("sentinel");
    let version = "1.4.2";

    // Create sentinel
    pmx_updater::agent_update::health::create_sentinel(version, &sentinel_path)
        .expect("create_sentinel must succeed");

    // Verify file exists
    assert!(
        sentinel_path.exists(),
        "sentinel file must exist after create"
    );

    // Read it back
    let sentinel = pmx_updater::agent_update::health::read_sentinel(&sentinel_path)
        .expect("read_sentinel must succeed")
        .expect("sentinel must be Some after create");
    assert_eq!(
        sentinel.version, version,
        "sentinel version must round-trip"
    );
}

#[test]
fn sentinel_clear_deletes_file() {
    let dir = setup_test_env();
    let sentinel_path = dir.path().join("sentinel");

    pmx_updater::agent_update::health::create_sentinel("1.0.0", &sentinel_path).unwrap();
    assert!(sentinel_path.exists());

    pmx_updater::agent_update::health::clear_sentinel(&sentinel_path).unwrap();
    assert!(
        !sentinel_path.exists(),
        "sentinel must be deleted after clear"
    );
}

#[test]
fn sentinel_read_missing_file_returns_none() {
    let dir = setup_test_env();
    let sentinel_path = dir.path().join("nonexistent");

    let result = pmx_updater::agent_update::health::read_sentinel(&sentinel_path)
        .expect("read_sentinel of missing file should not error");
    assert!(
        result.is_none(),
        "reading nonexistent sentinel must return None"
    );
}

#[test]
fn sentinel_clear_missing_file_ok() {
    let dir = setup_test_env();
    let sentinel_path = dir.path().join("nonexistent");

    // Clearing a nonexistent sentinel should be OK (idempotent)
    let result = pmx_updater::agent_update::health::clear_sentinel(&sentinel_path);
    assert!(
        result.is_ok(),
        "clearing missing sentinel should be ok: {:?}",
        result
    );
}

#[test]
fn sentinel_create_overwrites_existing() {
    let dir = setup_test_env();
    let sentinel_path = dir.path().join("sentinel");

    pmx_updater::agent_update::health::create_sentinel("1.0.0", &sentinel_path).unwrap();
    pmx_updater::agent_update::health::create_sentinel("2.0.0", &sentinel_path).unwrap();

    let sentinel = pmx_updater::agent_update::health::read_sentinel(&sentinel_path)
        .unwrap()
        .unwrap();
    assert_eq!(
        sentinel.version, "2.0.0",
        "sentinel must reflect latest write"
    );
}

#[test]
fn check_file_readable_with_existing_file() {
    let dir = setup_test_env();
    let file_path = dir.path().join("test-file");
    fs::write(&file_path, "test content").unwrap();

    let result =
        pmx_updater::agent_update::health::check_file_readable(file_path.to_str().unwrap());
    assert!(result.is_ok(), "existing readable file must pass check");
}

#[test]
fn check_file_readable_with_missing_file() {
    let result =
        pmx_updater::agent_update::health::check_file_readable("/tmp/nonexistent-pmx-test-12345");
    assert!(result.is_err(), "missing file must fail check");
}

#[test]
fn check_directory_writable_with_writable_dir() {
    let dir = setup_test_env();
    let result =
        pmx_updater::agent_update::health::check_directory_writable(dir.path().to_str().unwrap());
    assert!(result.is_ok(), "writable directory must pass check");
}

#[test]
fn check_directory_writable_with_readonly_dir() {
    // /proc is typically read-only on Linux
    if std::path::Path::new("/proc").exists() {
        let result = pmx_updater::agent_update::health::check_directory_writable("/proc");
        assert!(result.is_err(), "read-only directory must fail check");
    }
}

#[test]
fn check_disk_space_has_reasonable_amount() {
    let dir = setup_test_env();
    // Request a small amount (1KB) — should always pass
    let result =
        pmx_updater::agent_update::health::check_disk_space(dir.path().to_str().unwrap(), 1024);
    assert!(result.is_ok(), "1KB disk space request must pass");
}

#[test]
fn check_disk_space_excessive_amount_fails() {
    let dir = setup_test_env();
    // Request an absurd amount (1 Exabyte) — should fail
    let result = pmx_updater::agent_update::health::check_disk_space(
        dir.path().to_str().unwrap(),
        1_152_921_504_606_846_976,
    );
    assert!(result.is_err(), "1EB disk space request must fail");
}

#[test]
fn check_binary_on_path_with_known_binary() {
    // `ls` or `echo` should always be on PATH
    let result = pmx_updater::agent_update::health::check_binary_on_path("ls");
    assert!(result.is_ok(), "'ls' must be on PATH");
}

#[test]
fn check_binary_on_path_with_unknown_binary() {
    let result =
        pmx_updater::agent_update::health::check_binary_on_path("pmx-nonexistent-binary-xyz-12345");
    assert!(result.is_err(), "nonexistent binary must fail check");
}
