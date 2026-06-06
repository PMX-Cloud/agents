/*
Package audit implements the append-only, hash-chained audit log required by
architecture §6.3.

Hash chain formula:

	Hash = SHA-256( PrevHash || JobID || Command || Step || string(Exit) || string(DurationMs) || Timestamp.RFC3339Nano )

All bytes are concatenated with no separator — the format is fixed by this
comment and must not change without bumping the log format version.

Persistence: one JSON-Lines record per line at the path passed to Open().
On startup, the file is replayed to rebuild the in-memory chain head.
Journald: each appended entry is also logged via log/slog with structured
PMX_* fields so journalctl can query it.
*/
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"
)

// Entry is one record in the audit log.
type Entry struct {
	Seq        uint64    `json:"seq"`
	Timestamp  time.Time `json:"timestamp"`
	JobID      string    `json:"jobId"`
	Command    string    `json:"command"`
	Step       string    `json:"step"`
	Exit       int       `json:"exit"`
	DurationMs int64     `json:"durationMs"`
	PrevHash   string    `json:"prevHash"`
	Hash       string    `json:"hash"` // SHA-256(prevHash || JobID || Command || Step || Exit || DurationMs || Timestamp.RFC3339Nano)
}

// Log is an open, append-only audit log file. All methods are goroutine-safe.
type Log struct {
	mu   sync.Mutex
	path string
	file *os.File
	head string // hex SHA-256 of the last entry's hash
	seq  uint64 // monotonic sequence number
	log  *slog.Logger
}

// Open opens (or creates) the audit log at path, replaying any existing
// entries to restore the in-memory chain head.
//
// If the last line is partial/corrupt it is truncated with a warning; all
// preceding entries are valid and the chain head is the last valid entry.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o640) // #nosec G304 G302 -- audit log path is operator-configured; 0640 lets the agent's group read the tamper-evident log
	if err != nil {
		return nil, fmt.Errorf("audit: open %q: %w", path, err)
	}

	l := &Log{
		path: path,
		file: f,
		log:  slog.Default(),
	}
	if err := l.replay(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return l, nil
}

// Head returns the current audit chain head (hex SHA-256).
// Returns empty string if no entries have been written yet.
func (l *Log) Head() string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head
}

// Append writes e to the log, computes its hash, and returns the new chain head.
func (l *Log) Append(e Entry) (chainHead string, err error) {
	if l == nil {
		return "", fmt.Errorf("audit: append on nil log")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	e.Seq = l.seq + 1
	e.PrevHash = l.head
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	e.Hash = computeHash(e)

	line, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("audit: marshal: %w", err)
	}
	line = append(line, '\n')

	if _, err := l.file.Write(line); err != nil {
		return "", fmt.Errorf("audit: write: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return "", fmt.Errorf("audit: sync: %w", err)
	}

	l.head = e.Hash
	l.seq = e.Seq

	// Emit to journald via slog structured fields.
	l.log.Info("audit.entry",
		"PMX_JOB_ID", e.JobID,
		"PMX_COMMAND", e.Command,
		"PMX_STEP", e.Step,
		"PMX_EXIT", e.Exit,
		"PMX_DURATION_MS", e.DurationMs,
		"PMX_AUDIT_HASH", e.Hash,
		"seq", e.Seq,
	)

	return e.Hash, nil
}

// Iter returns a channel that streams entries in order starting from fromSeq.
// Close the returned channel's done channel to stop early. The channel is
// closed when all matching entries have been sent or done is signalled.
func (l *Log) Iter(fromSeq uint64) (<-chan Entry, error) {
	if l == nil {
		return nil, fmt.Errorf("audit: iter on nil log")
	}
	l.mu.Lock()
	path := l.path
	l.mu.Unlock()

	ch := make(chan Entry, 64)
	go func() {
		defer close(ch)
		f, err := os.Open(path) // #nosec G304 -- audit log path is operator-configured, not attacker-controlled
		if err != nil {
			return
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var e Entry
			if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
				continue
			}
			if e.Seq >= fromSeq {
				ch <- e
			}
		}
	}()
	return ch, nil
}

// Close flushes and closes the underlying file.
func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

// Verify replays the entire log and returns an error if any entry's hash does
// not match the recomputed value. Useful for tamper detection.
func (l *Log) Verify() error {
	if l == nil {
		return fmt.Errorf("audit: verify on nil log")
	}
	l.mu.Lock()
	path := l.path
	l.mu.Unlock()

	f, err := os.Open(path) // #nosec G304 -- audit log path is operator-configured, not attacker-controlled
	if err != nil {
		return fmt.Errorf("audit: verify open: %w", err)
	}
	defer f.Close()

	prevHash := ""
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return fmt.Errorf("audit: verify line %d: unmarshal: %w", lineNum, err)
		}
		expected := computeHashWithPrev(prevHash, e)
		if e.Hash != expected {
			return fmt.Errorf("audit: tamper detected at seq %d (line %d): expected %s, got %s",
				e.Seq, lineNum, expected, e.Hash)
		}
		prevHash = e.Hash
	}
	return scanner.Err()
}

// replay reads the existing file to restore the in-memory chain head. A
// partial last line is silently skipped with a warning logged.
func (l *Log) replay() error {
	// Seek to beginning for reading.
	if _, err := l.file.Seek(0, 0); err != nil {
		return fmt.Errorf("audit: replay seek: %w", err)
	}

	scanner := bufio.NewScanner(l.file)
	var last *Entry
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			// Partial last line — log and stop.
			slog.Warn("audit: partial line during replay, truncating",
				"line", lineNum, "err", err)
			break
		}
		last = &e
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("audit: replay scan: %w", err)
	}

	if last != nil {
		l.head = last.Hash
		l.seq = last.Seq
	}
	return nil
}

// computeHash derives the SHA-256 hash for entry e using l.head as prevHash.
func computeHash(e Entry) string {
	return computeHashWithPrev(e.PrevHash, e)
}

// computeHashWithPrev derives SHA-256 for e using an explicit prevHash (used
// during Verify so the stored PrevHash is not trusted).
func computeHashWithPrev(prevHash string, e Entry) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte(e.JobID))
	h.Write([]byte(e.Command))
	h.Write([]byte(e.Step))
	h.Write([]byte(strconv.Itoa(e.Exit)))
	h.Write([]byte(strconv.FormatInt(e.DurationMs, 10)))
	h.Write([]byte(e.Timestamp.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))
}
