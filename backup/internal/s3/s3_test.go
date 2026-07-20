package s3

import (
	"path/filepath"
	"testing"
)

func TestUploadStatePathSanitizesJobID(t *testing.T) {
	t.Parallel()

	path := uploadStatePath(filepath.Join(t.TempDir(), "archive.vma.zst"), "job/../weird id")
	if filepath.Base(path) != ".pmx-s3-upload-job_.._weird_id.json" {
		t.Fatalf("unexpected state path %q", path)
	}
}

func TestUploadStateRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".pmx-s3-upload-job.json")
	want := uploadState{Bucket: "bucket", Key: "archive", UploadID: "upload-id"}
	if err := saveUploadState(path, want); err != nil {
		t.Fatalf("saveUploadState() error = %v", err)
	}
	got, err := loadUploadState(path)
	if err != nil {
		t.Fatalf("loadUploadState() error = %v", err)
	}
	if got != want {
		t.Fatalf("state = %+v, want %+v", got, want)
	}
}
