// Package runner provides command execution helpers with bounded output.
package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Command struct {
	Path        string
	Args        []string
	Env         map[string]string
	Timeout     time.Duration
	OutputLimit int64
}

type Result struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	Combined   string `json:"combined,omitempty"`
	Truncated  bool   `json:"truncated"`
	DurationMs int64  `json:"duration_ms"`
}

func Run(ctx context.Context, cmd Command, stepFn func(string)) (*Result, error) {
	if strings.TrimSpace(cmd.Path) == "" {
		return nil, fmt.Errorf("runner: command path is required")
	}
	limit := cmd.OutputLimit
	if limit <= 0 {
		limit = 4 * 1024 * 1024
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if cmd.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, cmd.Timeout)
		defer cancel()
	}

	proc := exec.CommandContext(runCtx, cmd.Path, cmd.Args...)
	if len(cmd.Env) > 0 {
		env := make([]string, 0, len(cmd.Env))
		for k, v := range cmd.Env {
			env = append(env, k+"="+v)
		}
		proc.Env = append(proc.Environ(), env...)
	}

	stdoutPipe, err := proc.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("runner: stdout pipe: %w", err)
	}
	stderrPipe, err := proc.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("runner: stderr pipe: %w", err)
	}

	start := time.Now()
	if err := proc.Start(); err != nil {
		return nil, fmt.Errorf("runner: start %s: %w", cmd.Path, err)
	}

	stdoutBuf := newCappedBuffer(limit)
	stderrBuf := newCappedBuffer(limit)
	combined := newCappedBuffer(limit)

	var wg sync.WaitGroup
	copyStream := func(prefix string, r io.Reader, dst *cappedBuffer) {
		defer wg.Done()
		scanner := bufio.NewScanner(r)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			dst.WriteString(line)
			dst.WriteString("\n")
			combined.WriteString(line)
			combined.WriteString("\n")
			if stepFn != nil {
				stepFn(prefix + strings.TrimSpace(line))
			}
		}
	}

	wg.Add(2)
	go copyStream("", stdoutPipe, stdoutBuf)
	go copyStream("ERR: ", stderrPipe, stderrBuf)

	// Drain stdout/stderr to EOF before Wait. Cmd.Wait closes the pipes once the
	// process exits, so calling it before the copy goroutines finish reading can
	// truncate captured output (an intermittently empty Stdout under load). See
	// the Cmd.StdoutPipe contract.
	wg.Wait()
	waitErr := proc.Wait()
	durationMs := time.Since(start).Milliseconds()

	result := &Result{
		ExitCode:   0,
		Stdout:     strings.TrimSpace(stdoutBuf.String()),
		Stderr:     strings.TrimSpace(stderrBuf.String()),
		Combined:   strings.TrimSpace(combined.String()),
		Truncated:  stdoutBuf.truncated || stderrBuf.truncated || combined.truncated,
		DurationMs: durationMs,
	}

	if waitErr == nil {
		return result, nil
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		result.ExitCode = -1
		return result, fmt.Errorf("runner: command timed out after %dms", durationMs)
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
	} else {
		result.ExitCode = 1
		var sErr *os.SyscallError
		if errors.As(waitErr, &sErr) {
			if errno, ok := sErr.Err.(syscall.Errno); ok {
				result.ExitCode = int(errno)
			}
		}
	}
	return result, fmt.Errorf("runner: %s %s failed: %w", cmd.Path, strings.Join(cmd.Args, " "), waitErr)
}

type cappedBuffer struct {
	limit     int64
	size      int64
	builder   strings.Builder
	truncated bool
}

func newCappedBuffer(limit int64) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

func (b *cappedBuffer) WriteString(value string) {
	if b.truncated || value == "" {
		return
	}
	remaining := b.limit - b.size
	if remaining <= 0 {
		b.truncated = true
		return
	}
	if int64(len(value)) > remaining {
		b.builder.WriteString(value[:remaining])
		b.size += remaining
		b.truncated = true
		return
	}
	b.builder.WriteString(value)
	b.size += int64(len(value))
}

func (b *cappedBuffer) String() string {
	return b.builder.String()
}
