use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<Mutex<std::fs::File>>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    // Kept in the serialized audit schema for warning events emitted by future handlers.
    #[allow(dead_code)]
    Warn,
    Error,
    Critical,
}

#[derive(Debug, Serialize)]
pub struct Event<'a> {
    pub ts: DateTime<Utc>,
    pub severity: Severity,
    pub job_id: &'a str,
    pub command: &'a str,
    pub message: &'a str,
}

impl AuditLog {
    pub fn open(path: &str) -> Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            create_dir_all(parent)
                .with_context(|| format!("create audit dir {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open audit log {}", path))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(file)),
        })
    }

    pub fn append(&self, event: Event<'_>) {
        if let Ok(line) = serde_json::to_string(&event) {
            if let Ok(mut file) = self.inner.lock() {
                let _ = writeln!(file, "{}", line);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ── open creates the file and parent directories ──────────────────────────

    #[test]
    fn open_creates_file_in_nested_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/audit.log");
        let log = AuditLog::open(path.to_str().unwrap()).unwrap();
        drop(log);
        assert!(path.exists(), "audit file should exist after open");
    }

    // ── append writes a JSON line ─────────────────────────────────────────────

    #[test]
    fn append_writes_json_line_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let log = AuditLog::open(path.to_str().unwrap()).unwrap();

        log.append(Event {
            ts: chrono::Utc::now(),
            severity: Severity::Info,
            job_id: "job-001",
            command: "bridge.create",
            message: "ok",
        });

        drop(log);

        let content = fs::read_to_string(&path).unwrap();
        assert!(!content.is_empty(), "log should not be empty after append");
        let first_line = content.lines().next().unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(first_line).expect("must be valid JSON");
        assert_eq!(parsed["job_id"], "job-001");
        assert_eq!(parsed["command"], "bridge.create");
        assert_eq!(parsed["severity"], "info");
        assert_eq!(parsed["message"], "ok");
    }

    #[test]
    fn append_multiple_events_each_on_own_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let log = AuditLog::open(path.to_str().unwrap()).unwrap();

        for i in 0..3u32 {
            log.append(Event {
                ts: chrono::Utc::now(),
                severity: Severity::Warn,
                job_id: "job-multi",
                command: "vlan.create",
                message: &format!("event {}", i),
            });
        }

        drop(log);

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 3, "should have 3 lines");
        for line in content.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["command"], "vlan.create");
        }
    }

    // ── append after re-open continues the file ───────────────────────────────

    #[test]
    fn reopen_appends_without_truncating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");

        {
            let log = AuditLog::open(path.to_str().unwrap()).unwrap();
            log.append(Event {
                ts: chrono::Utc::now(),
                severity: Severity::Error,
                job_id: "j1",
                command: "cmd1",
                message: "first",
            });
        }
        {
            let log = AuditLog::open(path.to_str().unwrap()).unwrap();
            log.append(Event {
                ts: chrono::Utc::now(),
                severity: Severity::Critical,
                job_id: "j2",
                command: "cmd2",
                message: "second",
            });
        }

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(
            content.lines().count(),
            2,
            "should have 2 lines after two opens"
        );
    }

    // ── severity serialisation ────────────────────────────────────────────────

    #[test]
    fn severity_serialises_as_lowercase() {
        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"info\"");
        assert_eq!(serde_json::to_string(&Severity::Warn).unwrap(), "\"warn\"");
        assert_eq!(
            serde_json::to_string(&Severity::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
    }
}
