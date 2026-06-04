// Package storageexec provides an audited, shell-free subprocess wrapper.
package storageexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pmx-cloud/agents/shared/audit"
)

var (
	// ErrExit marks a non-zero subprocess exit.
	ErrExit = errors.New("command exited non-zero")
	// ErrUnsafeArgument marks a rejected argument before execution.
	ErrUnsafeArgument = errors.New("unsafe argument")
)

const defaultTimeout = 60 * time.Second

// Result captures full subprocess output.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// StdoutString returns trimmed stdout.
func (r *Result) StdoutString() string {
	return string(bytes.TrimSpace(r.Stdout))
}

// Call records a command invocation.
type Call struct {
	Binary string
	Args   []string
}

// Interface is the command surface used by storage handlers.
type Interface interface {
	Lsblk(ctx context.Context, args ...string) (*Result, error)
	Parted(ctx context.Context, args ...string) (*Result, error)
	Wipefs(ctx context.Context, args ...string) (*Result, error)
	Mkfs(ctx context.Context, fsType string, args ...string) (*Result, error)
	Zpool(ctx context.Context, args ...string) (*Result, error)
	Zfs(ctx context.Context, args ...string) (*Result, error)
	Smartctl(ctx context.Context, args ...string) (*Result, error)
	Exportfs(ctx context.Context, args ...string) (*Result, error)
	Net(ctx context.Context, args ...string) (*Result, error)
	Nvme(ctx context.Context, args ...string) (*Result, error)
	QemuImg(ctx context.Context, args ...string) (*Result, error)
	Qm(ctx context.Context, args ...string) (*Result, error)
}

// Exec is the live implementation.
type Exec struct {
	Paths           map[string]string
	AllowedBinaries map[string]bool
	AuditLog        *audit.Log
	Logger          *slog.Logger
	JobID           string
}

// DefaultBinaryPaths returns command key to binary path mapping.
func DefaultBinaryPaths() map[string]string {
	return map[string]string{
		"lsblk":      "/sbin/lsblk",
		"parted":     "/sbin/parted",
		"wipefs":     "/sbin/wipefs",
		"mkfs.ext4":  "/sbin/mkfs.ext4",
		"mkfs.xfs":   "/sbin/mkfs.xfs",
		"mkfs.btrfs": "/sbin/mkfs.btrfs",
		"zpool":      "/sbin/zpool",
		"zfs":        "/sbin/zfs",
		"smartctl":   "/usr/sbin/smartctl",
		"exportfs":   "/usr/sbin/exportfs",
		"net":        "/usr/bin/net",
		"nvme":       "/usr/sbin/nvme",
		"qemu-img":   "/usr/bin/qemu-img",
	}
}

// DefaultAllowedBinaries is the hard allowlist.
func DefaultAllowedBinaries() map[string]bool {
	return map[string]bool{
		"/sbin/lsblk":        true,
		"/sbin/parted":       true,
		"/sbin/wipefs":       true,
		"/sbin/mkfs.ext4":    true,
		"/sbin/mkfs.xfs":     true,
		"/sbin/mkfs.btrfs":   true,
		"/sbin/zpool":        true,
		"/sbin/zfs":          true,
		"/usr/sbin/smartctl": true,
		"/usr/sbin/exportfs": true,
		"/usr/bin/net":       true,
		"/usr/sbin/nvme":     true,
		"/usr/bin/qemu-img":  true,
	}
}

// trustedBinDirs are the only directories a binary may be resolved from. This
// keeps the allowlist meaningful on usr-merged hosts (where /sbin/lsblk may not
// exist as a real file) without allowing execution of arbitrary PATH entries.
var trustedBinDirs = []string{
	"/usr/sbin",
	"/sbin",
	"/usr/bin",
	"/bin",
	"/usr/local/sbin",
	"/usr/local/bin",
}

// resolveBinary returns the real path for a command. It prefers the configured
// default path; if that file is absent (common on usr-merged systems where the
// canonical location moved), it searches the trusted bin dirs for the same
// basename. The returned path is guaranteed to be in a trusted directory, so
// callers can safely add it to the allowlist. When nothing is found the default
// is returned unchanged so the eventual exec fails with a clear error.
func resolveBinary(defaultPath string) string {
	if isExecutableFile(defaultPath) {
		return defaultPath
	}
	base := filepath.Base(defaultPath)
	for _, dir := range trustedBinDirs {
		candidate := filepath.Join(dir, base)
		if isExecutableFile(candidate) {
			return candidate
		}
	}
	return defaultPath
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}

// resolvedPathsAndAllowlist resolves every default command to a real on-host
// path and builds an allowlist that matches the resolved set. This is what makes
// the agent work on Debian/Ubuntu/Proxmox regardless of /sbin vs /usr/bin
// layout, removing the need for host-side symlinks.
func resolvedPathsAndAllowlist() (map[string]string, map[string]bool) {
	return ResolvePaths(DefaultBinaryPaths())
}

// ResolvePaths takes a command->path map (typically the configured command
// paths) and returns the same map with every path resolved against the host,
// plus an allowlist built from the resolved set. An empty path for a known
// command falls back to its built-in default before resolution. Callers that
// override Exec.Paths from config MUST use this so Exec.AllowedBinaries stays in
// sync with the resolved paths — otherwise a resolved binary is rejected by the
// allowlist check.
func ResolvePaths(paths map[string]string) (map[string]string, map[string]bool) {
	defaults := DefaultBinaryPaths()
	resolvedPaths := make(map[string]string, len(paths))
	allow := make(map[string]bool, len(paths))
	for name, p := range paths {
		if strings.TrimSpace(p) == "" {
			p = defaults[name]
		}
		if strings.TrimSpace(p) == "" {
			continue
		}
		resolved := resolveBinary(p)
		resolvedPaths[name] = resolved
		allow[resolved] = true
	}
	return resolvedPaths, allow
}

// New returns an Exec with paths resolved against the host and an allowlist that
// matches them.
func New() *Exec {
	paths, allow := resolvedPathsAndAllowlist()
	return &Exec{
		Paths:           paths,
		AllowedBinaries: allow,
	}
}

func (e *Exec) Lsblk(ctx context.Context, args ...string) (*Result, error) {
	return e.runNamed(ctx, "lsblk", args...)
}
func (e *Exec) Parted(ctx context.Context, args ...string) (*Result, error) {
	return e.runNamed(ctx, "parted", args...)
}
func (e *Exec) Wipefs(ctx context.Context, args ...string) (*Result, error) {
	return e.runNamed(ctx, "wipefs", args...)
}
func (e *Exec) Zpool(ctx context.Context, args ...string) (*Result, error) {
	return e.runNamed(ctx, "zpool", args...)
}
func (e *Exec) Zfs(ctx context.Context, args ...string) (*Result, error) {
	return e.runNamed(ctx, "zfs", args...)
}
func (e *Exec) Smartctl(ctx context.Context, args ...string) (*Result, error) {
	return e.runNamed(ctx, "smartctl", args...)
}
func (e *Exec) Exportfs(ctx context.Context, args ...string) (*Result, error) {
	return e.runNamed(ctx, "exportfs", args...)
}
func (e *Exec) Net(ctx context.Context, args ...string) (*Result, error) {
	return e.runNamed(ctx, "net", args...)
}
func (e *Exec) Nvme(ctx context.Context, args ...string) (*Result, error) {
	return e.runNamed(ctx, "nvme", args...)
}
func (e *Exec) QemuImg(ctx context.Context, args ...string) (*Result, error) {
	return e.runNamed(ctx, "qemu-img", args...)
}

// Qm exists only for test parity with other agents.
func (e *Exec) Qm(ctx context.Context, args ...string) (*Result, error) {
	if err := validateArgs(args); err != nil {
		return nil, err
	}
	return &Result{}, nil
}

func (e *Exec) Mkfs(ctx context.Context, fsType string, args ...string) (*Result, error) {
	name := "mkfs." + strings.TrimSpace(fsType)
	return e.runNamed(ctx, name, args...)
}

func (e *Exec) runNamed(ctx context.Context, name string, args ...string) (*Result, error) {
	if e.Paths == nil || e.AllowedBinaries == nil {
		paths, allow := resolvedPathsAndAllowlist()
		if e.Paths == nil {
			e.Paths = paths
		}
		if e.AllowedBinaries == nil {
			e.AllowedBinaries = allow
		}
	}
	path, ok := e.Paths[name]
	if !ok || strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("storageexec: path not configured for %s", name)
	}
	if !e.AllowedBinaries[path] {
		return nil, fmt.Errorf("storageexec: binary %s not in allowlist", path)
	}
	if err := validateArgs(args); err != nil {
		return nil, err
	}

	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	if e.AuditLog != nil {
		e.AuditLog.Append(audit.Entry{
			Timestamp: time.Now(),
			JobID:     e.JobID,
			Command:   name,
			Step:      "pre",
			Exit:      -1,
		})
	}
	if e.Logger != nil {
		e.Logger.Info("storageexec: exec", "binary", path, "args", args, "job_id", e.JobID)
	}

	start := time.Now()
	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	dur := time.Since(start)

	exit := 0
	if runErr != nil {
		exit = -1
		if ee, ok := runErr.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
		runErr = fmt.Errorf("%w: %s", ErrExit, runErr)
	}

	res := &Result{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		ExitCode: exit,
		Duration: dur,
	}

	if e.AuditLog != nil {
		e.AuditLog.Append(audit.Entry{
			Timestamp:  time.Now(),
			JobID:      e.JobID,
			Command:    name,
			Step:       "post",
			Exit:       exit,
			DurationMs: dur.Milliseconds(),
		})
	}
	return res, runErr
}

func validateArgs(args []string) error {
	for _, arg := range args {
		if !IsSafeArg(arg) {
			return fmt.Errorf("%w: %q", ErrUnsafeArgument, arg)
		}
	}
	return nil
}

// IsSafeArg rejects shell-metachar payloads. Commands are still executed argv-style.
func IsSafeArg(arg string) bool {
	if strings.ContainsAny(arg, ";|&`$<>()\n\r\x00") {
		return false
	}
	return true
}

// MockExec is a deterministic mock used by storage unit tests.
type MockExec struct {
	Calls   []Call
	Results map[string]*Result
	Errs    map[string]error
}

func (m *MockExec) Lsblk(ctx context.Context, args ...string) (*Result, error) {
	return m.call("lsblk", args...)
}
func (m *MockExec) Parted(ctx context.Context, args ...string) (*Result, error) {
	return m.call("parted", args...)
}
func (m *MockExec) Wipefs(ctx context.Context, args ...string) (*Result, error) {
	return m.call("wipefs", args...)
}
func (m *MockExec) Zpool(ctx context.Context, args ...string) (*Result, error) {
	return m.call("zpool", args...)
}
func (m *MockExec) Zfs(ctx context.Context, args ...string) (*Result, error) {
	return m.call("zfs", args...)
}
func (m *MockExec) Smartctl(ctx context.Context, args ...string) (*Result, error) {
	return m.call("smartctl", args...)
}
func (m *MockExec) Exportfs(ctx context.Context, args ...string) (*Result, error) {
	return m.call("exportfs", args...)
}
func (m *MockExec) Net(ctx context.Context, args ...string) (*Result, error) {
	return m.call("net", args...)
}
func (m *MockExec) Nvme(ctx context.Context, args ...string) (*Result, error) {
	return m.call("nvme", args...)
}
func (m *MockExec) QemuImg(ctx context.Context, args ...string) (*Result, error) {
	return m.call("qemu-img", args...)
}
func (m *MockExec) Qm(ctx context.Context, args ...string) (*Result, error) {
	return m.call("qm", args...)
}

func (m *MockExec) Mkfs(ctx context.Context, fsType string, args ...string) (*Result, error) {
	return m.call("mkfs."+strings.TrimSpace(fsType), args...)
}

func (m *MockExec) call(binary string, args ...string) (*Result, error) {
	if err := validateArgs(args); err != nil {
		return nil, err
	}
	m.Calls = append(m.Calls, Call{Binary: binary, Args: append([]string(nil), args...)})

	res := &Result{}
	if m.Results != nil {
		if candidate, ok := m.Results[binary]; ok && candidate != nil {
			res = candidate
		}
	}
	if m.Errs != nil {
		if err, ok := m.Errs[binary]; ok && err != nil {
			return res, err
		}
	}
	if res.ExitCode != 0 {
		return res, ErrExit
	}
	return res, nil
}
