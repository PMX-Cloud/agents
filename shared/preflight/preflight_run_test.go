package preflight_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/shared/preflight"
)

// TestRun_WritesToStderr calls the public Run (which writes to os.Stderr).
func TestRun_WithPassingCheck(t *testing.T) {
	code := preflight.Run([]preflight.Check{
		{Name: "pass", Run: func(_ context.Context) error { return nil }},
	})
	if code != 0 {
		t.Fatalf("Run returned %d, want 0", code)
	}
}

// TestCheckCertValid_MalformedCert covers the "load cert failed" branch.
func TestCheckCertValid_MalformedCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.crt")
	keyPath := filepath.Join(dir, "bad.key")
	_ = os.WriteFile(certPath, []byte("not-a-cert"), 0o600)
	_ = os.WriteFile(keyPath, []byte("not-a-key"), 0o600)

	checks := preflight.StandardChecks("pmx-test", "/nonexistent/conf", certPath, keyPath, "/nonexistent/keyset", nil)
	var buf bytes.Buffer
	preflight.RunTo(&buf, checks)
	out := buf.String()
	if !strings.Contains(out, "[FAIL] cert-valid") {
		t.Errorf("cert-valid must FAIL for malformed cert, got:\n%s", out)
	}
}

// TestCheckKeysetReadable_EmptyFile covers the "keyset has no keys" branch.
func TestCheckKeysetReadable_EmptyKeyset(t *testing.T) {
	dir := t.TempDir()
	keysetPath := filepath.Join(dir, "empty.pub")
	_ = os.WriteFile(keysetPath, []byte(""), 0o444)

	checks := preflight.StandardChecks("pmx-test", "/nonexistent/conf", "", "", keysetPath, nil)
	var buf bytes.Buffer
	preflight.RunTo(&buf, checks)
	out := buf.String()
	if !strings.Contains(out, "[FAIL] keyset-readable") {
		t.Errorf("keyset-readable must FAIL for empty keyset, got:\n%s", out)
	}
}
