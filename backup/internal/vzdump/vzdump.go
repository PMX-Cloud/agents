// Package vzdump wraps Proxmox vzdump/qm/qmrestore orchestration for pmx-backup.
package vzdump

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Binaries struct {
	VZDump    string
	QM        string
	QMRestore string
}

type CreateParams struct {
	VMID          int
	DumpDir       string
	Mode          string
	Compress      string
	NotesTemplate string
}

type CreateResult struct {
	ArchivePath string `json:"archive_path"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
}

type RestoreParams struct {
	ArchivePath string
	VMID        int
	Storage     string
	Overwrite   bool
}

var (
	archiveQuotedPattern = regexp.MustCompile(`(?i)archive(?: file)? ['"]([^'"]+)['"]`)
	archivePathPattern   = regexp.MustCompile(`(/[A-Za-z0-9._/\-]*vzdump[^\s'"\\]+)`)
)

func Create(ctx context.Context, bins Binaries, params CreateParams, stepFn func(string)) (*CreateResult, error) {
	if params.VMID <= 0 {
		return nil, fmt.Errorf("vzdump: vmid must be > 0")
	}
	if strings.TrimSpace(params.DumpDir) == "" {
		return nil, fmt.Errorf("vzdump: dumpdir is required")
	}
	if !filepath.IsAbs(params.DumpDir) {
		return nil, fmt.Errorf("vzdump: dumpdir must be absolute")
	}
	mode := strings.TrimSpace(params.Mode)
	if mode == "" {
		mode = "snapshot"
	}
	compress := strings.TrimSpace(params.Compress)
	if compress == "" {
		compress = "zstd"
	}

	exists, err := VMExists(ctx, bins.QM, params.VMID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("vzdump: vmid %d does not exist", params.VMID)
	}

	start := time.Now()
	var (
		mu          sync.Mutex
		archivePath string
	)
	// NOTE: --notes-template is deliberately omitted. vzdump rejects it unless
	// --storage is also given ("storage: missing property required by
	// 'notes-template'"), and this path dumps to an explicit --dumpdir.
	args := []string{
		strconv.Itoa(params.VMID),
		"--dumpdir", params.DumpDir,
		"--mode", mode,
		"--compress", compress,
	}

	err = runStream(ctx, bins.VZDump, args,
		func(line string) {
			if stepFn != nil {
				stepFn(line)
			}
		},
		func(line string) {
			if stepFn != nil {
				stepFn(line)
			}
			if candidate, ok := parseArchivePath(line); ok {
				mu.Lock()
				if archivePath == "" {
					archivePath = candidate
				}
				mu.Unlock()
			}
		},
	)
	if err != nil {
		return nil, err
	}

	mu.Lock()
	resolvedArchive := archivePath
	mu.Unlock()
	if resolvedArchive == "" {
		resolvedArchive, err = findCreatedArchive(params.DumpDir, params.VMID, start)
		if err != nil {
			return nil, err
		}
	}
	sha, size, err := HashFileSHA256(resolvedArchive, stepFn)
	if err != nil {
		return nil, err
	}
	return &CreateResult{
		ArchivePath: resolvedArchive,
		SizeBytes:   size,
		SHA256:      sha,
	}, nil
}

func Restore(ctx context.Context, bins Binaries, params RestoreParams, stepFn func(string)) error {
	if params.VMID <= 0 {
		return fmt.Errorf("qmrestore: vmid must be > 0")
	}
	if strings.TrimSpace(params.ArchivePath) == "" {
		return fmt.Errorf("qmrestore: archive_path is required")
	}
	if !filepath.IsAbs(params.ArchivePath) {
		return fmt.Errorf("qmrestore: archive_path must be absolute")
	}

	exists, err := VMExists(ctx, bins.QM, params.VMID)
	if err != nil {
		return err
	}
	if exists && !params.Overwrite {
		return fmt.Errorf("qmrestore: vmid %d already exists; overwrite=true required", params.VMID)
	}

	args := []string{params.ArchivePath, strconv.Itoa(params.VMID)}
	if strings.TrimSpace(params.Storage) != "" {
		args = append(args, "--storage", strings.TrimSpace(params.Storage))
	}
	if params.Overwrite {
		args = append(args, "--force", "1")
	}
	return runStream(ctx, bins.QMRestore, args,
		func(line string) {
			if stepFn != nil {
				stepFn(line)
			}
		},
		func(line string) {
			if stepFn != nil {
				stepFn(line)
			}
		},
	)
}

func VMExists(ctx context.Context, qmBinary string, vmid int) (bool, error) {
	if strings.TrimSpace(qmBinary) == "" {
		return false, fmt.Errorf("qm binary path is required")
	}
	cmd := exec.CommandContext(ctx, qmBinary, "status", strconv.Itoa(vmid))
	if out, err := cmd.CombinedOutput(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			_ = out
			return false, nil
		}
		return false, fmt.Errorf("qm status %d: %w", vmid, err)
	}
	return true, nil
}

func HashFileSHA256(path string, stepFn func(string)) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("hash: open %q: %w", path, err)
	}
	defer file.Close()

	st, err := file.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("hash: stat %q: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return "", 0, fmt.Errorf("hash: %q is not a regular file", path)
	}

	h := sha256.New()
	buf := make([]byte, 8*1024*1024)
	var (
		totalRead int64
		lastEmit  int64
	)
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			totalRead += int64(n)
			if _, err := h.Write(buf[:n]); err != nil {
				return "", 0, fmt.Errorf("hash: write digest: %w", err)
			}
		}
		if stepFn != nil && (totalRead == st.Size() || totalRead-lastEmit >= 64*1024*1024) {
			stepFn(fmt.Sprintf("sha256 %d/%d", totalRead, st.Size()))
			lastEmit = totalRead
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", 0, fmt.Errorf("hash: read %q: %w", path, readErr)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), st.Size(), nil
}

func runStream(
	ctx context.Context,
	binary string,
	args []string,
	onStdoutLine func(string),
	onStderrLine func(string),
) error {
	if strings.TrimSpace(binary) == "" {
		return fmt.Errorf("command binary path is required")
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%s stdout pipe: %w", binary, err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("%s stderr pipe: %w", binary, err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", binary, err)
	}

	var wg sync.WaitGroup
	var scanErrMu sync.Mutex
	var scanErr error
	scan := func(r io.Reader, cb func(string)) {
		defer wg.Done()
		scanner := bufio.NewScanner(r)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		for scanner.Scan() {
			if cb != nil {
				cb(strings.TrimSpace(scanner.Text()))
			}
		}
		if err := scanner.Err(); err != nil {
			scanErrMu.Lock()
			if scanErr == nil {
				scanErr = err
			}
			scanErrMu.Unlock()
		}
	}

	wg.Add(2)
	go scan(stdoutPipe, onStdoutLine)
	go scan(stderrPipe, onStderrLine)

	// Drain stdout/stderr to EOF before Wait: Cmd.Wait closes the pipes on exit,
	// so waiting first can truncate captured output. See Cmd.StdoutPipe.
	wg.Wait()
	waitErr := cmd.Wait()

	scanErrMu.Lock()
	defer scanErrMu.Unlock()
	if scanErr != nil {
		return fmt.Errorf("%s output scan failed: %w", binary, scanErr)
	}
	if waitErr != nil {
		return fmt.Errorf("%s %s: %w", binary, strings.Join(args, " "), waitErr)
	}
	return nil
}

func parseArchivePath(line string) (string, bool) {
	if line == "" {
		return "", false
	}
	if match := archiveQuotedPattern.FindStringSubmatch(line); len(match) == 2 {
		candidate := strings.TrimSpace(match[1])
		if filepath.IsAbs(candidate) {
			return candidate, true
		}
	}
	if match := archivePathPattern.FindStringSubmatch(line); len(match) == 2 {
		candidate := strings.TrimSpace(match[1])
		if filepath.IsAbs(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func findCreatedArchive(dumpDir string, vmid int, startedAt time.Time) (string, error) {
	patterns := []string{
		filepath.Join(dumpDir, fmt.Sprintf("vzdump-qemu-%d-*", vmid)),
		filepath.Join(dumpDir, fmt.Sprintf("vzdump-lxc-%d-*", vmid)),
	}
	candidates := make([]string, 0)
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return "", fmt.Errorf("vzdump: invalid archive glob %q: %w", pattern, err)
		}
		candidates = append(candidates, matches...)
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("vzdump: archive path not found in %s", dumpDir)
	}

	type fileWithStat struct {
		path string
		st   os.FileInfo
	}
	entries := make([]fileWithStat, 0, len(candidates))
	for _, candidate := range candidates {
		st, err := os.Stat(candidate)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		entries = append(entries, fileWithStat{path: candidate, st: st})
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("vzdump: archive path not found in %s", dumpDir)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].st.ModTime().After(entries[j].st.ModTime())
	})
	for _, entry := range entries {
		if !entry.st.ModTime().Before(startedAt.Add(-2 * time.Minute)) {
			return entry.path, nil
		}
	}
	return entries[0].path, nil
}
