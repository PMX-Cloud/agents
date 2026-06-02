use super::{health, swap};
use std::path::Path;
use std::process::Command;
use thiserror::Error;
use tracing::{error, info};

#[derive(Debug, Error)]
pub enum RollbackError {
    #[error("swap rollback failed: {0}")]
    SwapFailed(#[from] swap::SwapError),
    #[allow(dead_code)]
    #[error("post-rollback health check failed: {0}")]
    HealthFailed(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("health error: {0}")]
    Health(#[from] health::HealthError),
    #[error("no sentinel found")]
    NoSentinel,
}

/// Execute a rollback: revert the symlink, restart the service, then health-check.
///
/// If the post-rollback health check fails we log it but do **not** return an error —
/// the swap has already been reverted and further escalation is out of scope here.
pub fn execute(
    handle: &swap::SwapHandle,
    agent_kind: health::AgentKind,
    config_path: &str,
) -> Result<(), RollbackError> {
    info!(
        agent = %handle.agent,
        new_version = %handle.new_version,
        old_version = ?handle.old_version,
        "executing rollback"
    );

    // 1. Revert the symlink.
    swap::rollback(handle)?;

    // 2. Restart the service so the old binary takes over.
    let unit = format!("pmx-{}", handle.agent);
    let restart_result = Command::new("systemctl")
        .args(["try-restart", &unit])
        .status();

    match restart_result {
        Ok(s) if s.success() => {
            info!(unit = %unit, "service restarted after rollback");
        }
        Ok(s) => {
            error!(unit = %unit, code = ?s.code(), "systemctl try-restart returned non-zero after rollback");
        }
        Err(e) => {
            error!(unit = %unit, error = %e, "could not invoke systemctl try-restart after rollback");
        }
    }

    // 3. Health check — best-effort; log failure but don't propagate.
    if let Err(e) = health::check(&handle.agent, agent_kind, config_path) {
        error!(
            agent = %handle.agent,
            error = %e,
            "post-rollback health check failed — host may need manual intervention"
        );
        // Do not return Err here; we've done our best.
    }

    Ok(())
}

/// Back up the current version directory to a backup location.
/// Used before applying an update so we can restore if the new version fails.
pub fn backup_current_version(current_dir: &str, backup_dir: &str) -> Result<(), RollbackError> {
    let src = Path::new(current_dir);
    let dst = Path::new(backup_dir);

    if !src.exists() {
        return Err(RollbackError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("current directory does not exist: {}", current_dir),
        )));
    }

    // Remove old backup if it exists
    if dst.exists() {
        std::fs::remove_dir_all(dst)?;
    }
    std::fs::create_dir_all(dst)?;

    // Copy all files from current to backup
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

/// Restore from a backup directory to the current directory.
/// Used when a sentinel-based rollback is triggered.
pub fn restore_from_backup(backup_dir: &str, current_dir: &str) -> Result<(), RollbackError> {
    let src = Path::new(backup_dir);
    let dst = Path::new(current_dir);

    if !src.exists() {
        return Err(RollbackError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("backup directory does not exist: {}", backup_dir),
        )));
    }

    // Remove current if it exists
    if dst.exists() {
        std::fs::remove_dir_all(dst)?;
    }
    std::fs::create_dir_all(dst)?;

    // Copy all files from backup to current
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

/// Perform a sentinel-based rollback: if a sentinel file exists,
/// restore from backup and clear the sentinel.
/// Returns the version string from the sentinel if rollback was performed,
/// or an empty string if no sentinel was found.
pub fn sentinel_rollback(
    sentinel_path: &Path,
    backup_dir: &str,
    current_dir: &str,
) -> Result<String, RollbackError> {
    match health::read_sentinel(sentinel_path)? {
        Some(sentinel) => {
            let version = sentinel.version.clone();
            info!(version = %version, "sentinel found, performing rollback");

            restore_from_backup(backup_dir, current_dir)?;
            health::clear_sentinel(sentinel_path)?;

            Ok(version)
        }
        None => Ok(String::new()),
    }
}

/// Clear the sentinel file after a successful update.
pub fn clear_sentinel(sentinel_path: &Path) -> Result<(), RollbackError> {
    health::clear_sentinel(sentinel_path)?;
    Ok(())
}

/// Recursively copy a directory and all its contents.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), RollbackError> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(path, content).expect("write file");
    }

    // ── backup_current_version ──────────────────────────────────────────────

    #[test]
    fn backup_current_version_copies_files() {
        let dir = tempdir().expect("tempdir");
        let current = dir.path().join("current");
        let backup = dir.path().join("backup");

        // Populate current dir.
        write_file(&current.join("bin/agent"), "binary content");
        write_file(&current.join("VERSION"), "1.4.1");

        backup_current_version(current.to_str().unwrap(), backup.to_str().unwrap())
            .expect("backup");

        assert!(backup.join("bin/agent").exists());
        assert!(backup.join("VERSION").exists());
        assert_eq!(
            std::fs::read_to_string(backup.join("VERSION")).expect("read"),
            "1.4.1"
        );
    }

    #[test]
    fn backup_current_version_replaces_existing_backup() {
        let dir = tempdir().expect("tempdir");
        let current = dir.path().join("current");
        let backup = dir.path().join("backup");

        write_file(&current.join("agent"), "v2");
        // Old backup with different content.
        write_file(&backup.join("old_file"), "old");

        backup_current_version(current.to_str().unwrap(), backup.to_str().unwrap())
            .expect("backup");

        assert!(backup.join("agent").exists());
        assert!(
            !backup.join("old_file").exists(),
            "old backup should be replaced"
        );
    }

    #[test]
    fn backup_current_version_nonexistent_source_errors() {
        let dir = tempdir().expect("tempdir");
        let current = dir.path().join("does_not_exist");
        let backup = dir.path().join("backup");

        let result = backup_current_version(current.to_str().unwrap(), backup.to_str().unwrap());
        assert!(result.is_err());
    }

    // ── restore_from_backup ─────────────────────────────────────────────────

    #[test]
    fn restore_from_backup_copies_files() {
        let dir = tempdir().expect("tempdir");
        let backup = dir.path().join("backup");
        let current = dir.path().join("current");

        write_file(&backup.join("bin/agent"), "old binary");
        write_file(&backup.join("VERSION"), "1.4.0");

        restore_from_backup(backup.to_str().unwrap(), current.to_str().unwrap())
            .expect("restore");

        assert!(current.join("bin/agent").exists());
        assert_eq!(
            std::fs::read_to_string(current.join("VERSION")).expect("read"),
            "1.4.0"
        );
    }

    #[test]
    fn restore_from_backup_replaces_current() {
        let dir = tempdir().expect("tempdir");
        let backup = dir.path().join("backup");
        let current = dir.path().join("current");

        write_file(&backup.join("agent"), "old");
        write_file(&current.join("agent"), "new");
        write_file(&current.join("extra"), "extra");

        restore_from_backup(backup.to_str().unwrap(), current.to_str().unwrap())
            .expect("restore");

        assert_eq!(
            std::fs::read_to_string(current.join("agent")).expect("read"),
            "old"
        );
        assert!(
            !current.join("extra").exists(),
            "current should be fully replaced"
        );
    }

    #[test]
    fn restore_from_backup_nonexistent_source_errors() {
        let dir = tempdir().expect("tempdir");
        let backup = dir.path().join("does_not_exist");
        let current = dir.path().join("current");

        let result = restore_from_backup(backup.to_str().unwrap(), current.to_str().unwrap());
        assert!(result.is_err());
    }

    // ── sentinel_rollback ───────────────────────────────────────────────────

    #[test]
    fn sentinel_rollback_performs_rollback_when_sentinel_present() {
        let dir = tempdir().expect("tempdir");
        let sentinel_path = dir.path().join("update.sentinel");
        let backup = dir.path().join("backup");
        let current = dir.path().join("current");

        // Set up backup with old version.
        write_file(&backup.join("agent"), "old binary");
        write_file(&backup.join("VERSION"), "1.4.0");

        // Set up current with new (bad) version.
        write_file(&current.join("agent"), "new binary");
        write_file(&current.join("VERSION"), "1.4.2");

        // Create sentinel.
        health::create_sentinel("1.4.2", &sentinel_path).expect("create sentinel");

        let version = sentinel_rollback(&sentinel_path, backup.to_str().unwrap(), current.to_str().unwrap())
            .expect("sentinel rollback");

        assert_eq!(version, "1.4.2");
        // Current should now have old content.
        assert_eq!(
            std::fs::read_to_string(current.join("VERSION")).expect("read"),
            "1.4.0"
        );
        // Sentinel should be cleared.
        assert!(!sentinel_path.exists());
    }

    #[test]
    fn sentinel_rollback_returns_empty_when_no_sentinel() {
        let dir = tempdir().expect("tempdir");
        let sentinel_path = dir.path().join("update.sentinel");
        let backup = dir.path().join("backup");
        let current = dir.path().join("current");

        let version = sentinel_rollback(&sentinel_path, backup.to_str().unwrap(), current.to_str().unwrap())
            .expect("no sentinel");

        assert!(version.is_empty());
    }

    // ── clear_sentinel ──────────────────────────────────────────────────────

    #[test]
    fn clear_sentinel_removes_file() {
        let dir = tempdir().expect("tempdir");
        let sentinel_path = dir.path().join("update.sentinel");
        health::create_sentinel("1.0.0", &sentinel_path).expect("create");
        assert!(sentinel_path.exists());

        super::clear_sentinel(&sentinel_path).expect("clear");
        assert!(!sentinel_path.exists());
    }

    #[test]
    fn clear_sentinel_nonexistent_ok() {
        let dir = tempdir().expect("tempdir");
        let sentinel_path = dir.path().join("nope.sentinel");
        super::clear_sentinel(&sentinel_path).expect("clear nonexistent");
    }

    // ── RollbackError variants ──────────────────────────────────────────────

    #[test]
    fn rollback_error_display() {
        let err = RollbackError::NoSentinel;
        assert!(err.to_string().contains("no sentinel"));

        let err = RollbackError::HealthFailed("bad".into());
        assert!(err.to_string().contains("bad"));
    }
}
