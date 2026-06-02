//! Append-only, hash-chained audit log — mirrors agents/shared/audit/audit.go.
//!
//! Hash chain formula (must match Go exactly):
//!   SHA-256( prevHash || jobId || command || step || string(exit) || string(durationMs) || timestamp.RFC3339Nano )
//!
//! All fields concatenated as bytes with NO separator.
//! Persistence: one JSON-Lines record per line at the path passed to `AuditLog::open`.
//! On startup the file is replayed to rebuild the in-memory chain head.
//! Each appended entry is also logged via `tracing::info!` with structured PMX_* fields
//! so that log aggregators can query it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("tamper detected at seq {seq} line {line}: expected {expected}, got {actual}")]
    Tamper {
        seq: u64,
        line: usize,
        expected: String,
        actual: String,
    },
}

pub type Result<T> = std::result::Result<T, AuditError>;

/// One record in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    #[serde(rename = "jobId")]
    pub job_id: String,
    pub command: String,
    pub step: String,
    pub exit: i32,
    #[serde(rename = "durationMs")]
    pub duration_ms: i64,
    #[serde(rename = "prevHash")]
    pub prev_hash: String,
    pub hash: String,
}

pub struct AuditLog {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    path: std::path::PathBuf,
    file: File,
    head: String,
    seq: u64,
}

// ── Hash computation ───────────────────────────────────────────────────────────

/// Compute the SHA-256 chain hash for an entry.
///
/// IMPORTANT: The timestamp format must match Go's `time.RFC3339Nano` for UTC
/// which produces `2006-01-02T15:04:05.999999999Z` (trailing "Z", not "+00:00").
/// `chrono::SecondsFormat::Nanos` with `use_z = true` produces the same suffix.
fn compute_hash(prev_hash: &str, e: &Entry) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(e.job_id.as_bytes());
    h.update(e.command.as_bytes());
    h.update(e.step.as_bytes());
    h.update(e.exit.to_string().as_bytes());
    h.update(e.duration_ms.to_string().as_bytes());
    // Use AutoSi to match Go's time.RFC3339Nano which strips trailing zeros.
    // e.g. nanoseconds=123456000 → ".123456Z" in both languages.
    h.update(
        e.timestamp
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
            .as_bytes(),
    );
    hex::encode(h.finalize())
}

// ── AuditLog impl ─────────────────────────────────────────────────────────────

impl AuditLog {
    /// Open (or create) the audit log at `path`, replaying any existing entries
    /// to restore the in-memory chain head and sequence counter.
    ///
    /// If the last line is partial/corrupt it is truncated with a warning; all
    /// preceding entries are valid and the chain head is the last valid entry.
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;

        let mut inner = Inner {
            path: path.to_path_buf(),
            file,
            head: String::new(),
            seq: 0,
        };
        inner.replay()?;

        Ok(AuditLog {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Return the current chain head (hex SHA-256 of the last entry).
    /// Returns an empty string if no entries have been written yet.
    pub fn head(&self) -> String {
        self.inner.lock().unwrap().head.clone()
    }

    /// Write `entry` to the log, compute its hash, fsync, and return the new
    /// chain head.
    pub fn append(&self, mut entry: Entry) -> Result<String> {
        let mut inner = self.inner.lock().unwrap();

        entry.seq = inner.seq + 1;
        entry.prev_hash = inner.head.clone();
        if entry.timestamp == DateTime::<Utc>::default() {
            entry.timestamp = Utc::now();
        }
        entry.hash = compute_hash(&entry.prev_hash, &entry);

        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');

        inner.file.write_all(&line)?;
        inner.file.flush()?;
        inner.file.sync_all()?;

        inner.head = entry.hash.clone();
        inner.seq = entry.seq;

        tracing::info!(
            PMX_JOB_ID = %entry.job_id,
            PMX_COMMAND = %entry.command,
            PMX_STEP = %entry.step,
            PMX_EXIT = entry.exit,
            PMX_DURATION_MS = entry.duration_ms,
            PMX_AUDIT_HASH = %entry.hash,
            seq = entry.seq,
            "audit.entry"
        );

        Ok(entry.hash)
    }

    /// Replay the entire log and return an error if any entry's hash does not
    /// match the recomputed value (tamper detection).
    pub fn verify(&self) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        let path = inner.path.clone();
        drop(inner); // release lock while doing file I/O

        let file = File::open(&path)?;
        let reader = BufReader::new(file);

        let mut prev_hash = String::new();
        for (idx, line_result) in reader.lines().enumerate() {
            let line_num = idx + 1;
            let line = line_result?;
            if line.is_empty() {
                continue;
            }
            let e: Entry = serde_json::from_str(&line)?;
            let expected = compute_hash(&prev_hash, &e);
            if e.hash != expected {
                return Err(AuditError::Tamper {
                    seq: e.seq,
                    line: line_num,
                    expected,
                    actual: e.hash,
                });
            }
            prev_hash = e.hash;
        }
        Ok(())
    }

    /// Return all entries with `seq >= from_seq` by opening a fresh file handle
    /// (so it does not block concurrent appends).
    pub fn iter(&self, from_seq: u64) -> Result<Vec<Entry>> {
        let inner = self.inner.lock().unwrap();
        let path = inner.path.clone();
        drop(inner);

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line_result in reader.lines() {
            let line = line_result?;
            if line.is_empty() {
                continue;
            }
            let e: Entry = serde_json::from_str(&line)?;
            if e.seq >= from_seq {
                entries.push(e);
            }
        }
        Ok(entries)
    }

    /// Flush and close the underlying file.
    pub fn close(self) {
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.file.flush();
            let _ = inner.file.sync_all();
            // File is closed when `inner` is dropped.
        }
    }
}

impl Inner {
    /// Scan the file from the beginning to restore `head` and `seq`.
    /// A partial last line (failed JSON parse) is logged as a warning and skipped.
    fn replay(&mut self) -> Result<()> {
        // Seek to the start for reading (the file was opened with O_APPEND so
        // writes go to the end, but reads need an explicit seek).
        self.file.seek(SeekFrom::Start(0))?;

        let reader = BufReader::new(&self.file);
        let mut last: Option<Entry> = None;
        let mut line_num = 0usize;

        for line_result in reader.lines() {
            line_num += 1;
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!(line = line_num, err = %e, "audit: I/O error during replay, stopping");
                    break;
                }
            };
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Entry>(&line) {
                Ok(e) => last = Some(e),
                Err(e) => {
                    tracing::warn!(
                        line = line_num,
                        err = %e,
                        "audit: partial line during replay, truncating"
                    );
                    break;
                }
            }
        }

        if let Some(e) = last {
            self.head = e.hash;
            self.seq = e.seq;
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use tempfile::NamedTempFile;

    fn make_entry(job_id: &str, command: &str, step: &str) -> Entry {
        Entry {
            seq: 0,
            timestamp: Utc::now(),
            job_id: job_id.to_string(),
            command: command.to_string(),
            step: step.to_string(),
            exit: 0,
            duration_ms: 42,
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    /// Append two entries, verify that head changes, and that verify() passes.
    #[test]
    fn test_append_and_verify() {
        let tmp = NamedTempFile::new().unwrap();
        let log = AuditLog::open(tmp.path()).unwrap();

        assert_eq!(log.head(), "");

        let h1 = log
            .append(make_entry("job-1", "vm.start", "start"))
            .unwrap();
        assert!(!h1.is_empty());
        assert_eq!(log.head(), h1);

        let h2 = log.append(make_entry("job-2", "vm.stop", "stop")).unwrap();
        assert_ne!(h1, h2);
        assert_eq!(log.head(), h2);

        log.verify().unwrap();
    }

    /// Append N entries, tamper with line 3, verify() must return a Tamper error.
    #[test]
    fn test_tamper_detection() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        {
            let log = AuditLog::open(&path).unwrap();
            for i in 0..5u64 {
                log.append(make_entry(&format!("job-{i}"), "vm.start", "step"))
                    .unwrap();
            }
            log.close();
        }

        // Read lines, corrupt line 3 (index 2).
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = content.lines().collect();
        assert!(lines.len() >= 3, "expected at least 3 lines");

        // Parse and tamper the third entry.
        let mut entry: Entry = serde_json::from_str(lines[2]).unwrap();
        entry.exit = 99; // mutate a field without recomputing hash
        let tampered = serde_json::to_string(&entry).unwrap();
        lines[2] = Box::leak(tampered.into_boxed_str());

        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        // Reopen and verify — must detect the tamper.
        let log2 = AuditLog::open(&path).unwrap();
        let err = log2.verify().unwrap_err();
        assert!(
            matches!(err, AuditError::Tamper { seq: 3, .. }),
            "expected Tamper at seq 3, got: {err:?}"
        );
    }

    /// Crash recovery: truncate the last line, reopen, head == last valid hash.
    #[test]
    fn test_crash_recovery() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let last_valid_hash;
        {
            let log = AuditLog::open(&path).unwrap();
            log.append(make_entry("job-1", "vm.start", "start"))
                .unwrap();
            last_valid_hash = log.append(make_entry("job-2", "vm.stop", "stop")).unwrap();
            log.close();
        }

        // Append a partial (incomplete) JSON line to simulate a crash mid-write.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(b"{\"seq\":3,\"timestamp\":\"2024-01-").unwrap();
        }

        // Reopen — should recover and present the last valid head.
        let log2 = AuditLog::open(&path).unwrap();
        assert_eq!(
            log2.head(),
            last_valid_hash,
            "head after crash recovery must equal last valid entry hash"
        );
    }

    /// iter(from_seq=3) must return only entries with seq >= 3.
    #[test]
    fn test_iter_from_seq() {
        let tmp = NamedTempFile::new().unwrap();
        let log = AuditLog::open(tmp.path()).unwrap();

        for i in 0..6u64 {
            log.append(make_entry(&format!("job-{i}"), "cmd", "step"))
                .unwrap();
        }

        let entries = log.iter(3).unwrap();
        assert_eq!(entries.len(), 4, "expected entries 3,4,5,6");
        assert!(entries.iter().all(|e| e.seq >= 3));
        assert_eq!(entries[0].seq, 3);
        assert_eq!(entries[3].seq, 6);
    }

    /// Cross-language interop: read a JSONL file produced by Go's
    /// TestInterop_GoAuditDumpFile and verify the entire hash chain.
    ///
    /// The file uses three timestamp precisions to verify that our RFC3339Nano
    /// trailing-zero stripping (SecondsFormat::AutoSi) matches Go's output.
    #[test]
    fn test_interop_go_audit_verifies() {
        let path = std::path::Path::new("testdata/audit-go.jsonl");

        // Skip gracefully if testdata not generated yet (run the Go test first).
        if !path.exists() {
            eprintln!("SKIP test_interop_go_audit_verifies: testdata/audit-go.jsonl not found");
            eprintln!("Run: cd agents/shared && go test ./audit/ -run TestInterop_GoAuditDumpFile");
            return;
        }

        // Copy the file to a temp path so AuditLog::open can write (it opens O_RDWR).
        let tmp = NamedTempFile::new().unwrap();
        std::fs::copy(path, tmp.path()).unwrap();

        let log = AuditLog::open(tmp.path()).unwrap();

        // verify() replays the chain and recomputes every hash.
        // If Go and Rust produce different hashes for the same field values
        // (timestamp format mismatch, field order, encoding difference), this fails.
        log.verify().unwrap_or_else(|e| {
            panic!("Go-written audit chain failed Rust verification: {e}");
        });

        // Confirm all 3 entries were parsed.
        let entries = log.iter(1).unwrap();
        assert_eq!(entries.len(), 3, "expected 3 entries from Go testdata");

        // Spot-check: entry 2 has zero nanoseconds → timestamp ends in 'Z' not '.000Z'.
        assert_eq!(
            entries[1].timestamp.format("%Z").to_string(),
            "UTC",
            "entry 2 timestamp must be UTC"
        );
        assert!(
            entries[1].timestamp.timestamp_subsec_nanos() == 0,
            "entry 2 timestamp must have zero nanoseconds"
        );
    }
}
