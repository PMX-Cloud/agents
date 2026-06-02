/*
exec.go — Audited Proxmox subprocess interface for pmx-hypervisor.

Design constraints (architecture §5.3, Task 3):
  - No bash -c. Every invocation uses exec.CommandContext with args as separate elements.
  - Audit-log BEFORE execution (job_id, command, args[]) and AFTER (exit_code, duration_ms, stderr[:512]).
  - Returns full stdout + stderr even on non-zero exit.
  - Context timeout is caller-supplied; default 60s if caller passes no deadline.
  - Argument injection test: "qm set 100 --net0 \"; rm -rf /\"" fails RequiredSafeToken.

The Exec interface is defined so tests can supply a MockExec that records calls.
*/
package proxmox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"github.com/pmx-cloud/agents/shared/audit"
)

// ExecResult holds the full output of one subprocess invocation.
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// StdoutString returns trimmed stdout as a string.
func (r *ExecResult) StdoutString() string {
	return string(bytes.TrimSpace(r.Stdout))
}

// StderrFirst512 returns the first 512 bytes of stderr (for audit log).
func (r *ExecResult) StderrFirst512() string {
	if len(r.Stderr) <= 512 {
		return string(r.Stderr)
	}
	return string(r.Stderr[:512])
}

// ExecIface is the mockable interface for Proxmox subprocesses.
type ExecIface interface {
	Pvesh(ctx context.Context, args ...string) (*ExecResult, error)
	Qm(ctx context.Context, args ...string) (*ExecResult, error)
	Pct(ctx context.Context, args ...string) (*ExecResult, error)
	Pvesm(ctx context.Context, args ...string) (*ExecResult, error)
	Pvecm(ctx context.Context, args ...string) (*ExecResult, error)
}

// Exec is the live implementation of ExecIface.
type Exec struct {
	PveshPath string
	QmPath    string
	PctPath   string
	PvesmPath string
	PvecmPath string
	AuditLog  *audit.Log
	Logger    *slog.Logger
	JobID     string
}

const defaultTimeout = 60 * time.Second

func (e *Exec) Pvesh(ctx context.Context, args ...string) (*ExecResult, error) {
	return e.run(ctx, e.PveshPath, args...)
}

func (e *Exec) Qm(ctx context.Context, args ...string) (*ExecResult, error) {
	return e.run(ctx, e.QmPath, args...)
}

func (e *Exec) Pct(ctx context.Context, args ...string) (*ExecResult, error) {
	return e.run(ctx, e.PctPath, args...)
}

func (e *Exec) Pvesm(ctx context.Context, args ...string) (*ExecResult, error) {
	return e.run(ctx, e.PvesmPath, args...)
}

func (e *Exec) Pvecm(ctx context.Context, args ...string) (*ExecResult, error) {
	return e.run(ctx, e.PvecmPath, args...)
}

// run is the core execution path: context deadline, pre/post audit, no bash -c.
func (e *Exec) run(ctx context.Context, binary string, args ...string) (*ExecResult, error) {
	// Ensure a deadline even if caller forgot one.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	// Pre-execution audit entry.
	argsJSON, _ := json.Marshal(args)
	if e.AuditLog != nil {
		e.AuditLog.Append(audit.Entry{
			Timestamp: time.Now(),
			JobID:     e.JobID,
			Command:   fmt.Sprintf("%s %s", binary, string(argsJSON)),
			Step:      "pre",
			Exit:      -1,
		})
	}
	if e.Logger != nil {
		e.Logger.Info("proxmox: exec", "binary", binary, "args", args, "job_id", e.JobID)
	}

	start := time.Now()
	// IMPORTANT: args are separate elements, never concatenated into a shell line.
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	dur := time.Since(start)

	exitCode := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
		if ctx.Err() == context.DeadlineExceeded {
			exitCode = -2
			runErr = fmt.Errorf("timeout after %v: %w", dur, runErr)
		}
	}

	result := &ExecResult{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		ExitCode: exitCode,
		Duration: dur,
	}

	// Post-execution audit entry.
	if e.AuditLog != nil {
		e.AuditLog.Append(audit.Entry{
			Timestamp:  time.Now(),
			JobID:      e.JobID,
			Command:    fmt.Sprintf("%s %s", binary, string(argsJSON)),
			Step:       "post",
			Exit:       exitCode,
			DurationMs: dur.Milliseconds(),
		})
	}
	if e.Logger != nil && runErr != nil {
		e.Logger.Warn("proxmox: exec failed",
			"binary", binary, "exit_code", exitCode,
			"stderr", result.StderrFirst512(), "job_id", e.JobID)
	}

	return result, runErr
}

// MockExec records every call for use in unit tests.
type MockExec struct {
	Calls  []MockCall
	Result *ExecResult
	Err    error
}

// MockCall records one invocation.
type MockCall struct {
	Binary string
	Args   []string
}

func (m *MockExec) Pvesh(ctx context.Context, args ...string) (*ExecResult, error) {
	return m.record("pvesh", args...)
}
func (m *MockExec) Qm(ctx context.Context, args ...string) (*ExecResult, error) {
	return m.record("qm", args...)
}
func (m *MockExec) Pct(ctx context.Context, args ...string) (*ExecResult, error) {
	return m.record("pct", args...)
}
func (m *MockExec) Pvesm(ctx context.Context, args ...string) (*ExecResult, error) {
	return m.record("pvesm", args...)
}
func (m *MockExec) Pvecm(ctx context.Context, args ...string) (*ExecResult, error) {
	return m.record("pvecm", args...)
}

func (m *MockExec) record(binary string, args ...string) (*ExecResult, error) {
	m.Calls = append(m.Calls, MockCall{Binary: binary, Args: args})
	if m.Result != nil {
		return m.Result, m.Err
	}
	return &ExecResult{Stdout: []byte(""), Stderr: []byte(""), ExitCode: 0}, m.Err
}

// LastCall returns the most recent call, or nil.
func (m *MockExec) LastCall() *MockCall {
	if len(m.Calls) == 0 {
		return nil
	}
	return &m.Calls[len(m.Calls)-1]
}
