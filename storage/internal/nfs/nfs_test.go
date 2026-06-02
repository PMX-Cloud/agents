package nfs_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/storage/internal/nfs"
	"github.com/pmx-cloud/agents/storage/internal/storageexec"
)

func TestShareCreateWritesOwnExportsFileAndReloads(t *testing.T) {
	dir := t.TempDir()
	sharePath := filepath.Join(dir, "share")
	if err := os.Mkdir(sharePath, 0o755); err != nil {
		t.Fatal(err)
	}
	m := &storageexec.MockExec{}
	err := nfs.ShareCreate(context.Background(), m, nfs.ShareParams{ID: "abc123", Path: sharePath, Network: "10.0.0.0/24", Options: []string{"rw", "sync"}, ExportsDir: dir})
	if err != nil {
		t.Fatalf("share create: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "pmx-abc123.exports"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), sharePath+" 10.0.0.0/24(rw,sync)") {
		t.Fatalf("unexpected export content: %s", data)
	}
	if len(m.Calls) != 1 || m.Calls[0].Binary != "exportfs" {
		t.Fatalf("expected exportfs reload, got %v", m.Calls)
	}
}

func TestShareCreateRejectsUnsafeOption(t *testing.T) {
	m := &storageexec.MockExec{}
	err := nfs.ShareCreate(context.Background(), m, nfs.ShareParams{ID: "abc123", Path: t.TempDir(), Network: "*", Options: []string{"rw", "insecure"}, ExportsDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "option") {
		t.Fatalf("expected option error, got %v", err)
	}
}
