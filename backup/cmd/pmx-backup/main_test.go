package main

import (
	"os"
	"path/filepath"
	"testing"

	backupsync "github.com/pmx-cloud/agents/backup/internal/sync"
)

func TestNormalizeSyncPushParamsRejectsOutsideLocalPath(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.vma.zst")
	if err := os.WriteFile(outside, []byte("archive"), 0o644); err != nil {
		t.Fatalf("write outside archive: %v", err)
	}

	params := backupsync.PushParams{Provider: "s3", LocalPath: outside}
	if err := normalizeSyncPushParams(&params, []string{root}); err == nil {
		t.Fatal("expected outside push path to be rejected")
	}
}

func TestNormalizeSyncPullParamsRejectsOutsideDestination(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	destination := filepath.Join(t.TempDir(), "pulled.vma.zst")

	params := backupsync.PullParams{Provider: "s3", LocalPath: destination}
	if err := normalizeSyncPullParams(&params, []string{root}); err == nil {
		t.Fatal("expected outside pull destination to be rejected")
	}
}

func TestNormalizeSyncPullParamsAllowsMissingPathInsideRoot(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	destination := filepath.Join(root, "nested", "pulled.vma.zst")

	params := backupsync.PullParams{Provider: "s3", LocalPath: destination}
	if err := normalizeSyncPullParams(&params, []string{root}); err != nil {
		t.Fatalf("expected inside missing destination to be allowed, got %v", err)
	}
	if params.LocalPath != destination || params.S3.LocalPath != destination {
		t.Fatalf("expected normalized local paths to be set, got top=%q s3=%q", params.LocalPath, params.S3.LocalPath)
	}
}

func TestIntParamHandlesUint64FromCBOR(t *testing.T) {
	// CBOR decodes a non-negative vmid into uint64. requiredIntParam must accept
	// it; the missing uint64 case caused "vmid must be a positive integer".
	params := map[string]any{"vmid": uint64(955)}
	got, err := requiredIntParam(params, "vmid")
	if err != nil {
		t.Fatalf("requiredIntParam returned error for uint64 vmid: %v", err)
	}
	if got != 955 {
		t.Fatalf("requiredIntParam(uint64 955) = %d, want 955", got)
	}
}
