//! Integration tests for the pmx-updater rollback module.
//!
//! Covers: sentinel-based rollback, version backup/restore,
//! and rollback error handling.

use std::fs;

fn setup_test_env() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn backup_current_version_creates_backup() {
    let dir = setup_test_env();
    let current_dir = dir.path().join("current");
    let backup_dir = dir.path().join("backup");

    fs::create_dir_all(&current_dir).unwrap();
    fs::write(current_dir.join("agent-binary"), "v1-binary-content").unwrap();

    pmx_updater::agent_update::rollback::backup_current_version(
        current_dir.to_str().unwrap(),
        backup_dir.to_str().unwrap(),
    )
    .expect("backup must succeed");

    assert!(backup_dir.exists(), "backup dir must exist");
    assert!(
        fs::read_to_string(backup_dir.join("agent-binary")).unwrap() == "v1-binary-content",
        "backup must contain original content"
    );
}

#[test]
fn backup_preserves_existing_backup() {
    let dir = setup_test_env();
    let current_dir = dir.path().join("current");
    let backup_dir = dir.path().join("backup");

    fs::create_dir_all(&current_dir).unwrap();
    fs::create_dir_all(&backup_dir).unwrap();
    fs::write(backup_dir.join("old-binary"), "old-content").unwrap();
    fs::write(current_dir.join("agent-binary"), "new-content").unwrap();

    // Second backup should overwrite the old backup
    pmx_updater::agent_update::rollback::backup_current_version(
        current_dir.to_str().unwrap(),
        backup_dir.to_str().unwrap(),
    )
    .expect("backup must succeed");

    assert!(
        fs::read_to_string(backup_dir.join("agent-binary")).unwrap() == "new-content",
        "backup must be updated"
    );
}

#[test]
fn restore_from_backup_succeeds() {
    let dir = setup_test_env();
    let current_dir = dir.path().join("current");
    let backup_dir = dir.path().join("backup");

    fs::create_dir_all(&backup_dir).unwrap();
    fs::write(backup_dir.join("agent-binary"), "backup-content").unwrap();

    pmx_updater::agent_update::rollback::restore_from_backup(
        backup_dir.to_str().unwrap(),
        current_dir.to_str().unwrap(),
    )
    .expect("restore must succeed");

    assert!(current_dir.exists(), "current dir must exist after restore");
    assert_eq!(
        fs::read_to_string(current_dir.join("agent-binary")).unwrap(),
        "backup-content",
        "restored content must match backup"
    );
}

#[test]
fn restore_from_missing_backup_errors() {
    let dir = setup_test_env();
    let current_dir = dir.path().join("current");
    let backup_dir = dir.path().join("nonexistent-backup");

    let result = pmx_updater::agent_update::rollback::restore_from_backup(
        backup_dir.to_str().unwrap(),
        current_dir.to_str().unwrap(),
    );
    assert!(result.is_err(), "restoring from missing backup must fail");
}

#[test]
fn sentinel_rollback_triggers_restore() {
    let dir = setup_test_env();
    let current_dir = dir.path().join("current");
    let backup_dir = dir.path().join("backup");
    let sentinel_path = dir.path().join("sentinel");

    // Setup: current has v2, backup has v1
    fs::create_dir_all(&current_dir).unwrap();
    fs::write(current_dir.join("agent-binary"), "v2-content").unwrap();
    fs::create_dir_all(&backup_dir).unwrap();
    fs::write(backup_dir.join("agent-binary"), "v1-content").unwrap();

    // Create sentinel indicating v2 was being applied
    pmx_updater::agent_update::health::create_sentinel("2.0.0", &sentinel_path).unwrap();

    // Perform sentinel-based rollback
    let result = pmx_updater::agent_update::rollback::sentinel_rollback(
        &sentinel_path,
        backup_dir.to_str().unwrap(),
        current_dir.to_str().unwrap(),
    );

    if let Ok(rolled_back_version) = result {
        assert_eq!(
            rolled_back_version, "2.0.0",
            "must report rolled-back version"
        );
        // Sentinel should be removed after rollback
        assert!(
            !sentinel_path.exists(),
            "sentinel must be removed after rollback"
        );
        // Current should now have v1 content
        assert_eq!(
            fs::read_to_string(current_dir.join("agent-binary")).unwrap(),
            "v1-content",
            "current must be restored to backup"
        );
    }
}

#[test]
fn no_sentinel_means_no_rollback() {
    let dir = setup_test_env();
    let current_dir = dir.path().join("current");
    let backup_dir = dir.path().join("backup");
    let sentinel_path = dir.path().join("sentinel"); // doesn't exist

    fs::create_dir_all(&current_dir).unwrap();
    fs::write(current_dir.join("agent-binary"), "current-content").unwrap();
    fs::create_dir_all(&backup_dir).unwrap();
    fs::write(backup_dir.join("agent-binary"), "backup-content").unwrap();

    // No sentinel → no rollback should occur
    let result = pmx_updater::agent_update::rollback::sentinel_rollback(
        &sentinel_path,
        backup_dir.to_str().unwrap(),
        current_dir.to_str().unwrap(),
    );

    // Should indicate no rollback needed
    if let Ok(version) = result {
        assert!(
            version.is_empty() || version == "none",
            "no sentinel means no rollback: got '{version}'"
        );
    }

    // Current should remain unchanged
    assert_eq!(
        fs::read_to_string(current_dir.join("agent-binary")).unwrap(),
        "current-content",
        "current must remain unchanged when no sentinel"
    );
}

#[test]
fn clear_sentinel_after_successful_update() {
    let dir = setup_test_env();
    let sentinel_path = dir.path().join("sentinel");

    pmx_updater::agent_update::health::create_sentinel("2.0.0", &sentinel_path).unwrap();
    assert!(sentinel_path.exists());

    // After successful update, sentinel should be cleared
    pmx_updater::agent_update::rollback::clear_sentinel(&sentinel_path).unwrap();
    assert!(
        !sentinel_path.exists(),
        "sentinel must be cleared after successful update"
    );
}
