// Package communityscript executes signed community scripts in a strict one-shot sandbox.
package communityscript

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Params struct {
	SystemdRunPath      string
	ReleaseKeyPath      string
	AllowedInterpreters []string
	AllowedWriteRoots   []string
	OutputLimitBytes    int64
	MaxTimeoutSec       int
}

type RunRequest struct {
	Script          string   `json:"script"`
	ScriptSignature string   `json:"scriptSignature"`
	Interpreter     string   `json:"interpreter"`
	WritePaths      []string `json:"writePaths"`
	EnvAllowlist    []string `json:"envAllowlist"`
	TimeoutSeconds  int      `json:"timeoutSeconds"`
	AllowNetwork    bool     `json:"allowNetwork"`
	IPAddressAllow  []string `json:"ipAddressAllow"`
}

type Result struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	Truncated  bool   `json:"truncated"`
	DurationMs int64  `json:"duration_ms"`
}

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func Run(ctx context.Context, p Params, req RunRequest, stepFn func(string)) (*Result, error) {
	scriptBytes, err := decodeScript(req.Script)
	if err != nil {
		return nil, err
	}
	publicKey, err := loadReleasePublicKey(p.ReleaseKeyPath)
	if err != nil {
		return nil, err
	}
	sig, err := decodeSignature(req.ScriptSignature)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(publicKey, scriptBytes, sig) {
		return nil, fmt.Errorf("community-script: script signature verification failed")
	}

	interpreter := strings.TrimSpace(req.Interpreter)
	if interpreter == "" {
		interpreter = "/bin/bash"
	}
	if !slicesContains(p.AllowedInterpreters, interpreter) {
		return nil, fmt.Errorf("community-script: interpreter %q is not allowlisted", interpreter)
	}

	writePaths, err := normalizeWritePaths(req.WritePaths, p.AllowedWriteRoots)
	if err != nil {
		return nil, err
	}
	for _, path := range writePaths {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, fmt.Errorf("community-script: create write path %q: %w", path, err)
		}
	}

	timeoutSec := req.TimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = p.MaxTimeoutSec
	}
	if timeoutSec <= 0 {
		timeoutSec = 600
	}
	if timeoutSec > p.MaxTimeoutSec && p.MaxTimeoutSec > 0 {
		return nil, fmt.Errorf("community-script: timeoutSeconds exceeds max %d", p.MaxTimeoutSec)
	}
	limit := p.OutputLimitBytes
	if limit <= 0 {
		limit = 10 * 1024 * 1024
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	scriptFD, scriptFile, err := createSealedScriptMemfd(scriptBytes)
	if err != nil {
		return nil, err
	}
	defer closeMemfd(scriptFD, scriptFile)

	args, err := buildSystemdRunArgs(interpreter, scriptFD, writePaths, req.AllowNetwork, req.IPAddressAllow)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, p.SystemdRunPath, args...)
	cmd.ExtraFiles = []*os.File{scriptFile}
	if env, err := buildAllowedEnv(req.EnvAllowlist); err != nil {
		return nil, err
	} else if len(env) > 0 {
		cmd.Env = env
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("community-script: stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("community-script: stderr pipe: %w", err)
	}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("community-script: start systemd-run: %w", err)
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

	// Drain stdout/stderr to EOF before Wait: Cmd.Wait closes the pipes on exit,
	// so waiting first can truncate captured output. See Cmd.StdoutPipe.
	wg.Wait()
	waitErr := cmd.Wait()
	durationMs := time.Since(start).Milliseconds()

	result := &Result{
		ExitCode:   0,
		Stdout:     strings.TrimSpace(stdoutBuf.String()),
		Stderr:     strings.TrimSpace(stderrBuf.String()),
		Truncated:  stdoutBuf.truncated || stderrBuf.truncated || combined.truncated,
		DurationMs: durationMs,
	}

	if waitErr == nil {
		return result, nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.ExitCode = -1
		return result, fmt.Errorf("community-script: timed out after %dms", durationMs)
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
	} else {
		result.ExitCode = 1
		var sysErr *os.SyscallError
		if errors.As(waitErr, &sysErr) {
			if errno, ok := sysErr.Err.(syscall.Errno); ok {
				result.ExitCode = int(errno)
			}
		}
	}
	return result, fmt.Errorf("community-script: systemd-run failed: %w", waitErr)
}

func decodeScript(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("community-script: script is required")
	}
	data, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil {
		return data, nil
	}
	data, err = base64.RawStdEncoding.DecodeString(trimmed)
	if err == nil {
		return data, nil
	}
	return nil, fmt.Errorf("community-script: script must be base64 encoded")
}

func decodeSignature(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("community-script: scriptSignature is required")
	}
	if sig, err := hex.DecodeString(trimmed); err == nil {
		return sig, nil
	}
	if sig, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return sig, nil
	}
	if sig, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil {
		return sig, nil
	}
	return nil, fmt.Errorf("community-script: scriptSignature must be hex or base64")
}

func loadReleasePublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("community-script: read release key %q: %w", path, err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, fmt.Errorf("community-script: release key file is empty")
	}

	if block, _ := pem.Decode(raw); block != nil {
		if pub, err := parsePEMPublicKey(block.Bytes); err == nil {
			return pub, nil
		}
	}
	if key, err := hex.DecodeString(trimmed); err == nil && len(key) == ed25519.PublicKeySize {
		return ed25519.PublicKey(key), nil
	}
	if key, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(key) == ed25519.PublicKeySize {
		return ed25519.PublicKey(key), nil
	}
	if key, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil && len(key) == ed25519.PublicKeySize {
		return ed25519.PublicKey(key), nil
	}
	return nil, fmt.Errorf("community-script: unsupported release key encoding in %q", path)
}

func parsePEMPublicKey(der []byte) (ed25519.PublicKey, error) {
	if cert, err := x509.ParseCertificate(der); err == nil {
		if key, ok := cert.PublicKey.(ed25519.PublicKey); ok {
			return key, nil
		}
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ed25519 public key")
	}
	return pub, nil
}

func normalizeWritePaths(paths []string, roots []string) ([]string, error) {
	if len(roots) == 0 {
		roots = []string{"/tmp", "/var/tmp"}
	}
	out := make([]string, 0, len(paths))
	seen := map[string]struct{}{}
	if len(paths) == 0 {
		paths = []string{roots[0]}
	}
	for _, raw := range paths {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}
		if strings.Contains(path, " ") {
			return nil, fmt.Errorf("community-script: write path %q contains spaces", raw)
		}
		if !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("community-script: write path %q must be absolute", raw)
		}
		clean := strings.TrimSuffix(path, "/")
		if clean == "" {
			clean = "/"
		}
		allowed := false
		for _, root := range roots {
			rootClean := strings.TrimSuffix(strings.TrimSpace(root), "/")
			if rootClean == "" {
				continue
			}
			if clean == rootClean || strings.HasPrefix(clean, rootClean+"/") {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("community-script: write path %q is outside allowed roots", raw)
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("community-script: writePaths resolved to empty set")
	}
	return out, nil
}

func buildSystemdRunArgs(interpreter string, scriptFD int, writePaths []string, allowNetwork bool, ipAddressAllow []string) ([]string, error) {
	execPath, execArgs, err := buildExecTarget(interpreter, scriptFD)
	if err != nil {
		return nil, err
	}
	args := []string{
		"--pipe",
		"--wait",
		"--collect",
		"--property=NoNewPrivileges=yes",
		"--property=ProtectSystem=strict",
		"--property=ProtectHome=true",
		"--property=PrivateTmp=true",
		"--property=ReadOnlyPaths=/",
		"--property=ReadWritePaths=" + strings.Join(writePaths, " "),
		"--property=AppArmorProfile=pmx-hardware-installer-community-script",
	}
	if !allowNetwork {
		args = append(args, "--property=PrivateNetwork=true")
	} else {
		if len(ipAddressAllow) == 0 {
			return nil, fmt.Errorf("community-script: ipAddressAllow is required when allowNetwork=true")
		}
		validated := 0
		for _, raw := range ipAddressAllow {
			v := strings.TrimSpace(raw)
			if v == "" {
				continue
			}
			if _, err := netip.ParsePrefix(v); err != nil {
				if _, err := netip.ParseAddr(v); err != nil {
					return nil, fmt.Errorf("community-script: invalid ipAddressAllow entry %q", raw)
				}
			}
			args = append(args, "--property=IPAddressAllow="+v)
			validated++
		}
		if validated == 0 {
			return nil, fmt.Errorf("community-script: ipAddressAllow resolved to empty set")
		}
	}
	args = append(args, execPath)
	args = append(args, execArgs...)
	return args, nil
}

func buildExecTarget(interpreter string, scriptFD int) (string, []string, error) {
	if scriptFD < 0 {
		return "", nil, fmt.Errorf("community-script: invalid memfd")
	}
	fdNumber := scriptFD + 3
	scriptPath := "/proc/self/fd/" + strconv.Itoa(fdNumber)
	switch interpreter {
	case "/bin/bash", "/bin/sh":
		return interpreter, []string{scriptPath}, nil
	case "/usr/bin/python3":
		return interpreter, []string{scriptPath}, nil
	default:
		return "", nil, fmt.Errorf("community-script: interpreter %q is not allowlisted", interpreter)
	}
}

func buildAllowedEnv(allowlist []string) ([]string, error) {
	if len(allowlist) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(allowlist)+1)
	seen := map[string]struct{}{}
	for _, raw := range allowlist {
		name := strings.TrimSpace(raw)
		if !envNameRE.MatchString(name) {
			return nil, fmt.Errorf("community-script: invalid env var name %q", raw)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		if value, ok := os.LookupEnv(name); ok {
			out = append(out, name+"="+value)
		}
	}
	if _, ok := seen["PATH"]; !ok {
		out = append(out, "PATH=/usr/sbin:/usr/bin:/sbin:/bin")
	}
	return out, nil
}

func slicesContains(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
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
