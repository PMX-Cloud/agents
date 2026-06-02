// Package logging provides a structured journald-compatible logger.
// All PMX agents use this logger so that every log line includes the
// mandatory PMX_* structured fields (PMX_JOB_ID, PMX_COMMAND, PMX_STEP,
// PMX_EXIT, PMX_DURATION_MS) used by monitoring and alerting.
package logging

import (
	"log/slog"
	"os"
	"time"
)

// Field is a typed key-value pair for structured log output.
type Field struct {
	Key   string
	Value any
}

// String returns a Field with a string value.
func String(key, val string) Field {
	return Field{Key: key, Value: val}
}

// Int64 returns a Field with an int64 value.
func Int64(key string, val int64) Field {
	return Field{Key: key, Value: val}
}

// Duration returns a Field with a time.Duration value (stored as milliseconds).
func Duration(key string, val time.Duration) Field {
	return Field{Key: key, Value: val.Milliseconds()}
}

// Err returns a Field for an error. If err is nil the value is the string "<nil>".
func Err(err error) Field {
	if err == nil {
		return Field{Key: "error", Value: "<nil>"}
	}
	return Field{Key: "error", Value: err.Error()}
}

// JobID returns a Field for the mandatory PMX_JOB_ID structured field.
func JobID(id string) Field {
	return Field{Key: "PMX_JOB_ID", Value: id}
}

// Command returns a Field for the mandatory PMX_COMMAND structured field.
func Command(cmd string) Field {
	return Field{Key: "PMX_COMMAND", Value: cmd}
}

// Logger is the interface satisfied by all PMX structured loggers.
type Logger interface {
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Debug(msg string, fields ...Field)
}

// Options controls how the logger is constructed.
// Format: "journald" (default), "json", or "text".
type Options struct {
	Format string
	Level  slog.Level
}

// slogLogger wraps a *slog.Logger and satisfies the Logger interface.
type slogLogger struct {
	l *slog.Logger
}

// fieldsToArgs converts []Field into the variadic []any expected by slog.
func fieldsToArgs(fields []Field) []any {
	args := make([]any, 0, len(fields)*2)
	for _, f := range fields {
		args = append(args, f.Key, f.Value)
	}
	return args
}

func (s *slogLogger) Info(msg string, fields ...Field) {
	s.l.Info(msg, fieldsToArgs(fields)...)
}

func (s *slogLogger) Warn(msg string, fields ...Field) {
	s.l.Warn(msg, fieldsToArgs(fields)...)
}

func (s *slogLogger) Error(msg string, fields ...Field) {
	s.l.Error(msg, fieldsToArgs(fields)...)
}

func (s *slogLogger) Debug(msg string, fields ...Field) {
	s.l.Debug(msg, fieldsToArgs(fields)...)
}

// New constructs a Logger according to opts.
//
// Format selection order:
//  1. If JOURNAL_STREAM env var is set → text handler (journald picks up key=value).
//  2. If PMX_LOG_FORMAT=json or opts.Format=="json" → JSON handler.
//  3. Otherwise → text handler.
func New(opts Options) Logger {
	ho := &slog.HandlerOptions{Level: opts.Level}

	var handler slog.Handler
	switch {
	case os.Getenv("JOURNAL_STREAM") != "":
		// Running under systemd — use text handler; journald captures stderr.
		handler = slog.NewTextHandler(os.Stderr, ho)
	case opts.Format == "json" || os.Getenv("PMX_LOG_FORMAT") == "json":
		handler = slog.NewJSONHandler(os.Stderr, ho)
	default:
		handler = slog.NewTextHandler(os.Stderr, ho)
	}

	return &slogLogger{l: slog.New(handler)}
}

// defaultLogger is the package-level singleton, initialised once at program start.
var defaultLogger Logger

func init() {
	format := os.Getenv("PMX_LOG_FORMAT")
	defaultLogger = New(Options{Format: format})
}

// Default returns the package-level default Logger.
// The format is determined by the PMX_LOG_FORMAT environment variable at
// process start (or overridden by JOURNAL_STREAM).
func Default() Logger {
	return defaultLogger
}
