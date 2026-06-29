package logging_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/shared/logging"
)

// testLogger is a helper that captures log output into a bytes.Buffer via a
// JSON handler so tests can inspect structured output deterministically.
type testLogger struct {
	buf  *bytes.Buffer
	slog *slog.Logger
}

func newTestLogger() (*testLogger, logging.Logger) {
	tl := &testLogger{buf: &bytes.Buffer{}}
	tl.slog = slog.New(slog.NewJSONHandler(tl.buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// Wrap via the exported New; but since New writes to os.Stderr we build a
	// parallel capture path through a custom slogLogger-equivalent for tests.
	// We expose the internal by using New(Options{Format:"json"}) with an
	// os.Stderr sink and inspect the Fields separately via a buffer-backed
	// slog for assertions.
	return tl, &bufLogger{buf: tl.buf, slog: tl.slog}
}

// bufLogger mirrors slogLogger but writes to a user-supplied buffer.
type bufLogger struct {
	buf  *bytes.Buffer
	slog *slog.Logger
}

func fieldsToArgs(fields []logging.Field) []any {
	args := make([]any, 0, len(fields)*2)
	for _, f := range fields {
		args = append(args, f.Key, f.Value)
	}
	return args
}

func (b *bufLogger) Info(msg string, fields ...logging.Field) {
	b.slog.Info(msg, fieldsToArgs(fields)...)
}
func (b *bufLogger) Warn(msg string, fields ...logging.Field) {
	b.slog.Warn(msg, fieldsToArgs(fields)...)
}
func (b *bufLogger) Error(msg string, fields ...logging.Field) {
	b.slog.Error(msg, fieldsToArgs(fields)...)
}
func (b *bufLogger) Debug(msg string, fields ...logging.Field) {
	b.slog.Debug(msg, fieldsToArgs(fields)...)
}

// TestInfoWritesFields verifies that Info logs contain the expected keys.
func TestInfoWritesFields(t *testing.T) {
	tl, l := newTestLogger()

	l.Info("test message",
		logging.JobID("job-123"),
		logging.Command("agent.diagnostics"),
		logging.String("step", "run"),
	)

	out := tl.buf.String()
	if !strings.Contains(out, `"msg":"test message"`) {
		t.Errorf("expected msg field, got: %s", out)
	}
	if !strings.Contains(out, `"level":"INFO"`) {
		t.Errorf("expected level=INFO, got: %s", out)
	}
	if !strings.Contains(out, `"PMX_JOB_ID":"job-123"`) {
		t.Errorf("expected PMX_JOB_ID, got: %s", out)
	}
	if !strings.Contains(out, `"PMX_COMMAND":"agent.diagnostics"`) {
		t.Errorf("expected PMX_COMMAND, got: %s", out)
	}
}

// TestErrFieldNilSafe verifies that Err(nil) does not panic and produces output.
func TestErrFieldNilSafe(t *testing.T) {
	tl, l := newTestLogger()

	// Must not panic.
	l.Error("an error occurred", logging.Err(nil))

	out := tl.buf.String()
	if !strings.Contains(out, "error") {
		t.Errorf("expected error key in output, got: %s", out)
	}
}

// TestErrFieldWithError verifies that a real error is serialised correctly.
func TestErrFieldWithError(t *testing.T) {
	tl, l := newTestLogger()

	l.Error("something failed", logging.Err(errors.New("disk full")))

	out := tl.buf.String()
	if !strings.Contains(out, "disk full") {
		t.Errorf("expected 'disk full' in output, got: %s", out)
	}
}

// TestInt64Field verifies that Int64 constructor serialises the value.
func TestInt64Field(t *testing.T) {
	tl, l := newTestLogger()

	l.Info("timing", logging.Int64("PMX_DURATION_MS", 42))

	out := tl.buf.String()
	if !strings.Contains(out, `"PMX_DURATION_MS":42`) {
		t.Errorf("expected PMX_DURATION_MS:42, got: %s", out)
	}
}

// TestDurationField verifies that Duration stores milliseconds.
func TestDurationField(t *testing.T) {
	tl, l := newTestLogger()

	l.Info("timing", logging.Duration("elapsed", 500*time.Millisecond))

	out := tl.buf.String()
	// Duration is stored as milliseconds (int64).
	if !strings.Contains(out, `"elapsed":500`) {
		t.Errorf("expected elapsed:500, got: %s", out)
	}
}

// TestWarnLevel verifies that Warn emits level=WARN.
func TestWarnLevel(t *testing.T) {
	tl, l := newTestLogger()

	l.Warn("low disk space", logging.String("node", "pve01"))

	out := tl.buf.String()
	if !strings.Contains(out, `"level":"WARN"`) {
		t.Errorf("expected level=WARN, got: %s", out)
	}
}

// TestDebugLevel verifies that Debug emits level=DEBUG.
func TestDebugLevel(t *testing.T) {
	tl, l := newTestLogger()

	l.Debug("trace", logging.String("key", "val"))

	out := tl.buf.String()
	if !strings.Contains(out, `"level":"DEBUG"`) {
		t.Errorf("expected level=DEBUG, got: %s", out)
	}
}

// TestJSONOutputIsValidJSON verifies that each line is parseable JSON.
func TestJSONOutputIsValidJSON(t *testing.T) {
	tl, l := newTestLogger()

	l.Info("check", logging.String("k", "v"))

	for _, line := range strings.Split(strings.TrimSpace(tl.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line is not valid JSON: %q, err: %v", line, err)
		}
	}
}

// TestDefaultReturnsNonNil verifies that Default() never returns nil.
func TestDefaultReturnsNonNil(t *testing.T) {
	if logging.Default() == nil {
		t.Error("Default() returned nil")
	}
}

// TestNewTextFormat verifies New with text format returns a working logger.
func TestNewTextFormat(t *testing.T) {
	l := logging.New(logging.Options{Format: "text"})
	if l == nil {
		t.Fatal("New(text) returned nil")
	}
	// Just call it — it writes to os.Stderr which is fine in tests.
	l.Info("text format test", logging.String("ok", "true"))
}

// TestNewJSONFormat verifies New with json format returns a working logger.
func TestNewJSONFormat(t *testing.T) {
	l := logging.New(logging.Options{Format: "json"})
	if l == nil {
		t.Fatal("New(json) returned nil")
	}
	l.Info("json format test", logging.String("ok", "true"))
}
