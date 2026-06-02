use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HealthError {
    #[error("agent not active after {timeout:?}: {details}")]
    NotActive { timeout: Duration, details: String },
    #[error("preflight failed with exit {code}: {stderr}")]
    PreflightFailed { code: i32, stderr: String },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sentinel: {0}")]
    Sentinel(String),
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum AgentKind {
    Persistent,
    Ephemeral,
}

/// Sentinel file content: just the version string being applied.
#[derive(Debug, Clone)]
pub struct Sentinel {
    pub version: String,
}

/// Poll `systemctl is-active --quiet pmx-<agent>` every 2 s until active or timeout.
pub fn check_persistent(agent: &str, timeout: Duration) -> Result<(), HealthError> {
    let unit = format!("pmx-{}", agent);
    let deadline = Instant::now() + timeout;
    let poll_interval = Duration::from_secs(2);

    loop {
        let status = Command::new("systemctl")
            .args(["is-active", "--quiet", &unit])
            .status()?;

        if status.success() {
            return Ok(());
        }

        if Instant::now() >= deadline {
            return Err(HealthError::NotActive {
                timeout,
                details: format!("systemctl is-active {} returned non-zero", unit),
            });
        }

        std::thread::sleep(poll_interval.min(deadline - Instant::now()));
    }
}

/// Run `pmx-<agent> --preflight --config <config_path>` and check exit code 0.
pub fn check_ephemeral(agent: &str, config_path: &str) -> Result<(), HealthError> {
    let binary = format!("pmx-{}", agent);
    let output = Command::new(&binary)
        .args(["--preflight", "--config", config_path])
        .output()?;

    if output.status.success() {
        return Ok(());
    }

    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Err(HealthError::PreflightFailed { code, stderr })
}

/// Dispatch to the correct health check based on agent kind.
pub fn check(agent: &str, kind: AgentKind, config_path: &str) -> Result<(), HealthError> {
    match kind {
        AgentKind::Persistent => check_persistent(agent, Duration::from_secs(30)),
        AgentKind::Ephemeral => check_ephemeral(agent, config_path),
    }
}

/// Create a sentinel file at `path` containing `version`.
/// The sentinel signals that an update is in progress; if it remains
/// after the updater exits, the ExecStartPre script triggers rollback.
pub fn create_sentinel(version: &str, path: &Path) -> Result<(), HealthError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, version.as_bytes())?;
    Ok(())
}

/// Read the sentinel file, returning the version string it contains.
/// Returns `Ok(None)` if the sentinel does not exist.
pub fn read_sentinel(path: &Path) -> Result<Option<Sentinel>, HealthError> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)?;
    let version = content.trim().to_string();
    if version.is_empty() {
        return Err(HealthError::Sentinel("sentinel file is empty".into()));
    }
    Ok(Some(Sentinel { version }))
}

/// Remove the sentinel file (called after a successful update).
pub fn clear_sentinel(path: &Path) -> Result<(), HealthError> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Check that a file at the given path is readable.
pub fn check_file_readable(path: &str) -> Result<(), HealthError> {
    std::fs::read_to_string(path)
        .map(|_| ())
        .map_err(HealthError::Io)
}

/// Check that a directory at the given path is writable by creating a temp file.
pub fn check_directory_writable(path: &str) -> Result<(), HealthError> {
    let dir = Path::new(path);
    let test_file = dir.join(".pmx-write-test");
    std::fs::write(&test_file, b"test")?;
    std::fs::remove_file(&test_file)?;
    Ok(())
}

/// Check that at least `required_bytes` of disk space is available at the given path.
#[allow(clippy::io_other_error)]
pub fn check_disk_space(path: &str, required_bytes: u64) -> Result<(), HealthError> {
    let available = fs4::free_space(path)?;
    if available >= required_bytes {
        Ok(())
    } else {
        Err(HealthError::Io(std::io::Error::other(
            format!(
                "insufficient disk space: {} bytes available, {} required",
                available, required_bytes
            ),
        )))
    }
}

/// Check that a binary is on PATH by checking `which <name>`.
pub fn check_binary_on_path(name: &str) -> Result<(), HealthError> {
    let status = Command::new("which")
        .arg(name)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(HealthError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("binary '{}' not found on PATH", name),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ── Sentinel tests ──────────────────────────────────────────────────────

    #[test]
    fn sentinel_create_read_clear_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let sentinel_path = dir.path().join("update.sentinel");

        // No sentinel initially.
        assert!(read_sentinel(&sentinel_path).expect("read").is_none());

        // Create sentinel.
        create_sentinel("1.4.2", &sentinel_path).expect("create");
        let s = read_sentinel(&sentinel_path).expect("read").expect("some");
        assert_eq!(s.version, "1.4.2");

        // Clear sentinel.
        clear_sentinel(&sentinel_path).expect("clear");
        assert!(read_sentinel(&sentinel_path).expect("read").is_none());
    }

    #[test]
    fn sentinel_create_creates_parent_dirs() {
        let dir = tempdir().expect("tempdir");
        let sentinel_path = dir.path().join("nested/deep/dir/sentinel");
        create_sentinel("2.0.0", &sentinel_path).expect("create with parents");
        let s = read_sentinel(&sentinel_path).expect("read").expect("some");
        assert_eq!(s.version, "2.0.0");
    }

    #[test]
    fn sentinel_empty_file_is_error() {
        let dir = tempdir().expect("tempdir");
        let sentinel_path = dir.path().join("empty.sentinel");
        std::fs::write(&sentinel_path, "").expect("write empty");
        let result = read_sentinel(&sentinel_path);
        assert!(result.is_err(), "empty sentinel should error");
        match result.unwrap_err() {
            HealthError::Sentinel(msg) => assert!(msg.contains("empty")),
            other => panic!("expected Sentinel error, got {:?}", other),
        }
    }

    #[test]
    fn sentinel_whitespace_only_file_is_error() {
        let dir = tempdir().expect("tempdir");
        let sentinel_path = dir.path().join("ws.sentinel");
        std::fs::write(&sentinel_path, "  \n ").expect("write ws");
        let result = read_sentinel(&sentinel_path);
        assert!(result.is_err(), "whitespace-only sentinel should error");
    }

    #[test]
    fn sentinel_clear_nonexistent_is_ok() {
        let dir = tempdir().expect("tempdir");
        let sentinel_path = dir.path().join("nope.sentinel");
        clear_sentinel(&sentinel_path).expect("clear nonexistent should be ok");
    }

    #[test]
    fn sentinel_trim_version() {
        let dir = tempdir().expect("tempdir");
        let sentinel_path = dir.path().join("trim.sentinel");
        std::fs::write(&sentinel_path, "  3.1.0\n").expect("write padded");
        let s = read_sentinel(&sentinel_path).expect("read").expect("some");
        assert_eq!(s.version, "3.1.0");
    }

    // ── File / directory checks ─────────────────────────────────────────────

    #[test]
    fn check_file_readable_ok() {
        let dir = tempdir().expect("tempdir");
        let f = dir.path().join("readable.txt");
        std::fs::write(&f, "hello").expect("write");
        check_file_readable(f.to_str().unwrap()).expect("should be readable");
    }

    #[test]
    fn check_file_readable_not_found() {
        let result = check_file_readable("/tmp/definitely_does_not_exist_12345");
        assert!(result.is_err());
    }

    #[test]
    fn check_directory_writable_ok() {
        let dir = tempdir().expect("tempdir");
        check_directory_writable(dir.path().to_str().unwrap()).expect("writable");
    }

    #[test]
    fn check_directory_writable_nonexistent() {
        let result = check_directory_writable("/tmp/definitely_does_not_exist_12345");
        assert!(result.is_err());
    }

    #[test]
    fn check_disk_space_sufficient() {
        let dir = tempdir().expect("tempdir");
        // Require 1 byte — always available on tempdir.
        check_disk_space(dir.path().to_str().unwrap(), 1).expect("should have 1 byte free");
    }

    #[test]
    fn check_disk_space_insufficient() {
        let dir = tempdir().expect("tempdir");
        // Require an absurd amount — should fail.
        let result = check_disk_space(dir.path().to_str().unwrap(), u64::MAX / 2);
        assert!(result.is_err(), "should report insufficient space");
    }

    // ── AgentKind dispatch ──────────────────────────────────────────────────

    #[test]
    fn check_ephemeral_nonexistent_binary_errors() {
        // Running check with a nonexistent binary should return an error.
        let result = check("nonexistent-agent-xyz", AgentKind::Ephemeral, "/dev/null");
        assert!(result.is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn check_persistent_nonexistent_unit_errors() {
        // A nonexistent systemd unit should time out quickly.
        // We use a very short timeout by calling check_persistent directly.
        // Gated to Linux — requires systemctl which is absent on macOS.
        let result = check_persistent("nonexistent-unit-xyz", Duration::from_millis(1));
        assert!(result.is_err(), "nonexistent unit should fail");
        match result.unwrap_err() {
            HealthError::NotActive { timeout, .. } => {
                assert_eq!(timeout, Duration::from_millis(1));
            }
            other => panic!("expected NotActive, got {:?}", other),
        }
    }

    #[test]
    fn check_binary_on_path_existing() {
        // `ls` should exist on any Unix system.
        check_binary_on_path("ls").expect("ls should be on PATH");
    }

    #[test]
    fn check_binary_on_path_missing() {
        let result = check_binary_on_path("definitely_not_a_real_binary_12345");
        assert!(result.is_err());
    }
}
