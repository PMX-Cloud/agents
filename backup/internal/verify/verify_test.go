package verify_test

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pmx-cloud/agents/backup/internal/verify"
)

func TestRun_ShaMismatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "archive.bin")
	if err := writeTar(file, map[string]string{"qemu-server.conf": "boot: order=scsi0\n"}); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	_, err := verify.Run(context.Background(), verify.Params{
		ArchivePath:    file,
		ExpectedSHA256: "deadbeef",
	}, nil)
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
}

func TestRun_SucceedsWithoutExpectedHash(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "archive.bin")
	if err := writeTar(file, map[string]string{"qemu-server.conf": "boot: order=scsi0\n"}); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	res, err := verify.Run(context.Background(), verify.Params{ArchivePath: file}, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if res.SHA256 == "" {
		t.Fatal("sha256 must not be empty")
	}
	if res.SizeBytes == 0 {
		t.Fatal("size must be > 0")
	}
}

func TestRun_FailsWhenArchiveManifestCannotBeRead(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "archive.bin")
	if err := os.WriteFile(file, []byte("not-a-tar"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	_, err := verify.Run(context.Background(), verify.Params{ArchivePath: file}, nil)
	if err == nil {
		t.Fatal("expected manifest parsing failure")
	}
}

func writeTar(path string, files map[string]string) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		content := []byte(body)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			return err
		}
		if _, err := tw.Write(content); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}
