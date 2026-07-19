package audit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/shared/audit"
)

func tmpLog(t *testing.T) (*audit.Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.audit.log")
	l, err := audit.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

func appendEntry(t *testing.T, l *audit.Log, jobID, cmd, step string, exit int) string {
	t.Helper()
	head, err := l.Append(audit.Entry{
		Timestamp:  time.Now(),
		JobID:      jobID,
		Command:    cmd,
		Step:       step,
		Exit:       exit,
		DurationMs: 42,
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	return head
}

// TestAudit_AppendAndHead -----------------------------------------------

func TestAudit_AppendAndHead(t *testing.T) {
	l, _ := tmpLog(t)

	if l.Head() != "" {
		t.Fatalf("expected empty head for fresh log, got %q", l.Head())
	}

	h1 := appendEntry(t, l, "job-1", "network.tunnel.up", "connect", 0)
	h2 := appendEntry(t, l, "job-2", "network.tunnel.down", "disconnect", 0)

	if h1 == h2 {
		t.Fatal("consecutive hashes must differ")
	}
	if l.Head() != h2 {
		t.Fatalf("Head() = %q, want %q", l.Head(), h2)
	}
}

// TestAudit_TamperDetection --------------------------------------------

func TestAudit_TamperDetection(t *testing.T) {
	l, path := tmpLog(t)

	for i := range 5 {
		appendEntry(t, l, "job-"+string(rune('A'+i)), "cmd", "step", 0)
	}
	_ = l.Close()

	// Tamper with line 3.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := splitLines(data)
	if len(lines) < 3 {
		t.Fatalf("expected >= 3 lines, got %d", len(lines))
	}

	// Mutate the Command field in line 3.
	var e audit.Entry
	if err := json.Unmarshal(lines[2], &e); err != nil {
		t.Fatalf("unmarshal line 3: %v", err)
	}
	e.Command = "tampered.command"
	lines[2], _ = json.Marshal(e)

	var rebuilt []byte
	for _, ln := range lines {
		rebuilt = append(rebuilt, ln...)
		rebuilt = append(rebuilt, '\n')
	}
	if err := os.WriteFile(path, rebuilt, 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Reopen and verify — must detect tampering.
	l2, err := audit.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = l2.Close() }()

	if err := l2.Verify(); err == nil {
		t.Fatal("expected tamper detection error, got nil")
	}
}

// TestAudit_CrashRecovery ----------------------------------------------

func TestAudit_CrashRecovery(t *testing.T) {
	l, path := tmpLog(t)

	for i := range 10 {
		appendEntry(t, l, "job-"+string(rune('0'+i)), "cmd", "step", 0)
	}
	validHead := l.Head()
	_ = l.Close()

	// Append a partial (corrupt) last line simulating a mid-write crash.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o640)
	_, _ = f.WriteString(`{"seq":11,"partial":true`)
	_ = f.Close()

	// Reopen — should succeed, with head equal to last valid entry.
	l2, err := audit.Open(path)
	if err != nil {
		t.Fatalf("reopen after crash: %v", err)
	}
	defer func() { _ = l2.Close() }()

	if l2.Head() != validHead {
		t.Fatalf("head after crash recovery: got %q, want %q", l2.Head(), validHead)
	}
}

// TestAudit_Iter --------------------------------------------------------

func TestAudit_Iter(t *testing.T) {
	l, _ := tmpLog(t)
	for i := range 5 {
		appendEntry(t, l, "job-iter-"+string(rune('0'+i)), "cmd", "step", 0)
	}

	ch, err := l.Iter(3)
	if err != nil {
		t.Fatalf("Iter: %v", err)
	}

	var entries []audit.Entry
	for e := range ch {
		entries = append(entries, e)
	}
	if len(entries) != 3 { // seq 3, 4, 5
		t.Fatalf("expected 3 entries from seq 3, got %d", len(entries))
	}
}

// TestInterop_GoAuditDumpFile writes a known audit log to
// testdata/audit-go.jsonl for use by the Rust cross-language interop test.
// Uses fixed timestamps to make the hash chain deterministic.
func TestInterop_GoAuditDumpFile(t *testing.T) {
	td := filepath.Join("testdata")
	if err := os.MkdirAll(td, 0o755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}

	path := filepath.Join(td, "audit-go.jsonl")
	// Remove old file so we start fresh.
	_ = os.Remove(path)

	l, err := audit.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Use fixed UTC timestamps with different sub-second precisions to exercise
	// the trailing-zero stripping in RFC3339Nano.
	entries := []struct {
		jobID string
		cmd   string
		step  string
		exit  int
		dMs   int64
		// RFC3339Nano strips trailing zeros, so test both microsecond and
		// nanosecond precision timestamps.
		timestamp time.Time
	}{
		{"job-interop-001", "network.tunnel.up", "connect", 0, 100, time.Date(2026, 1, 1, 10, 0, 0, 123456000, time.UTC)},
		{"job-interop-002", "vm.start", "start", 0, 250, time.Date(2026, 1, 1, 10, 0, 1, 0, time.UTC)},
		{"job-interop-003", "backup.create", "compress", 1, 500, time.Date(2026, 1, 1, 10, 0, 2, 987654321, time.UTC)},
	}

	for _, e := range entries {
		_, err := l.Append(audit.Entry{
			Timestamp:  e.timestamp,
			JobID:      e.jobID,
			Command:    e.cmd,
			Step:       e.step,
			Exit:       e.exit,
			DurationMs: e.dMs,
		})
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	// Verify the chain is intact before persisting.
	if err := l.Verify(); err != nil {
		t.Fatalf("Verify after write: %v", err)
	}

	t.Logf("audit testdata written to %s", path)
}

func TestAudit_NilLogSafeMethods(t *testing.T) {
	var l *audit.Log

	if got := l.Head(); got != "" {
		t.Fatalf("Head() on nil log = %q, want empty", got)
	}
	if _, err := l.Append(audit.Entry{JobID: "job-nil"}); err == nil {
		t.Fatal("Append() on nil log should fail")
	}
	if _, err := l.Iter(1); err == nil {
		t.Fatal("Iter() on nil log should fail")
	}
	if err := l.Verify(); err == nil {
		t.Fatal("Verify() on nil log should fail")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close() on nil log should be no-op, got %v", err)
	}
}

// helpers ---------------------------------------------------------------

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, data[start:i])
			}
			start = i + 1
		}
	}
	return lines
}
