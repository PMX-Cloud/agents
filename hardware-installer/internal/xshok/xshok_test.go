package xshok

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetect(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	match := filepath.Join(dir, "motd")
	if err := os.WriteFile(match, []byte("Proxmox VE Post Install helper"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	res, err := Detect(Params{Paths: []string{dir}})
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if !res.Detected {
		t.Fatal("expected conflict to be detected")
	}
	if len(res.Matches) != 1 || res.Matches[0] != match {
		t.Fatalf("unexpected matches: %#v", res.Matches)
	}
}
