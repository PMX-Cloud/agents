// Package pbs wraps proxmox-backup-client push/pull commands.
package pbs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
)

type PushParams struct {
	Binary         string   `json:"binary"`
	Repository     string   `json:"repository"`
	ArchiveName    string   `json:"archive_name"`
	LocalPath      string   `json:"local_path"`
	Namespace      string   `json:"namespace"`
	Fingerprint    string   `json:"fingerprint"`
	AdditionalArgs []string `json:"additional_args"`
}

type PullParams struct {
	Binary         string   `json:"binary"`
	Repository     string   `json:"repository"`
	Snapshot       string   `json:"snapshot"`
	ArchiveName    string   `json:"archive_name"`
	LocalPath      string   `json:"local_path"`
	Namespace      string   `json:"namespace"`
	Fingerprint    string   `json:"fingerprint"`
	AdditionalArgs []string `json:"additional_args"`
}

func Push(ctx context.Context, p PushParams, stepFn func(string)) error {
	binary := strings.TrimSpace(p.Binary)
	if binary == "" {
		binary = "/usr/bin/proxmox-backup-client"
	}
	if strings.TrimSpace(p.Repository) == "" {
		return fmt.Errorf("pbs push: repository is required")
	}
	if strings.TrimSpace(p.ArchiveName) == "" || strings.TrimSpace(p.LocalPath) == "" {
		return fmt.Errorf("pbs push: archive_name and local_path are required")
	}
	args := []string{
		"backup",
		fmt.Sprintf("%s.pxar:%s", strings.TrimSpace(p.ArchiveName), strings.TrimSpace(p.LocalPath)),
		"--repository", strings.TrimSpace(p.Repository),
	}
	if ns := strings.TrimSpace(p.Namespace); ns != "" {
		args = append(args, "--ns", ns)
	}
	if fp := strings.TrimSpace(p.Fingerprint); fp != "" {
		args = append(args, "--fingerprint", fp)
	}
	args = append(args, p.AdditionalArgs...)
	return runStream(ctx, binary, args, stepFn)
}

func Pull(ctx context.Context, p PullParams, stepFn func(string)) error {
	binary := strings.TrimSpace(p.Binary)
	if binary == "" {
		binary = "/usr/bin/proxmox-backup-client"
	}
	if strings.TrimSpace(p.Repository) == "" {
		return fmt.Errorf("pbs pull: repository is required")
	}
	if strings.TrimSpace(p.Snapshot) == "" || strings.TrimSpace(p.ArchiveName) == "" || strings.TrimSpace(p.LocalPath) == "" {
		return fmt.Errorf("pbs pull: snapshot, archive_name, and local_path are required")
	}
	args := []string{
		"restore",
		strings.TrimSpace(p.Snapshot),
		strings.TrimSpace(p.ArchiveName),
		strings.TrimSpace(p.LocalPath),
		"--repository", strings.TrimSpace(p.Repository),
	}
	if ns := strings.TrimSpace(p.Namespace); ns != "" {
		args = append(args, "--ns", ns)
	}
	if fp := strings.TrimSpace(p.Fingerprint); fp != "" {
		args = append(args, "--fingerprint", fp)
	}
	args = append(args, p.AdditionalArgs...)
	return runStream(ctx, binary, args, stepFn)
}

func runStream(ctx context.Context, binary string, args []string, stepFn func(string)) error {
	cmd := exec.CommandContext(ctx, binary, args...)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("pbs: stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("pbs: stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("pbs: start %s: %w", binary, err)
	}

	scan := func(r io.Reader) {
		scanner := bufio.NewScanner(r)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		for scanner.Scan() {
			if stepFn != nil {
				stepFn(strings.TrimSpace(scanner.Text()))
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		scan(stdoutPipe)
	}()
	go func() {
		defer wg.Done()
		scan(stderrPipe)
	}()

	// Drain stdout/stderr to EOF before Wait: Cmd.Wait closes the pipes on exit,
	// so waiting first can truncate captured output. See Cmd.StdoutPipe.
	wg.Wait()
	waitErr := cmd.Wait()
	if waitErr != nil {
		return fmt.Errorf("pbs %s %s: %w", binary, strings.Join(args, " "), waitErr)
	}
	return nil
}
