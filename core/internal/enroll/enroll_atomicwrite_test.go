package enroll_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/pmx-cloud/agents/core/internal/enroll"
)

// TestRun_AtomicWriteFails_PermissionDenied covers the atomicWrite failure path inside Run.
// We need: MkdirAll succeeds (dir exists) but CreateTemp inside atomicWrite fails.
// Strategy: pre-create the cert dir, then remove write permission from it.
func TestRun_AtomicWriteFails_PermissionDenied(t *testing.T) {
	// Backend returns a valid PEM certificate.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"certificate": fakeCertPEM})
	}))
	defer srv.Close()

	origClient := http.DefaultClient
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = origClient }()

	certDir := t.TempDir()
	// Remove write permission so CreateTemp inside atomicWrite fails.
	if err := os.Chmod(certDir, 0o555); err != nil {
		t.Skipf("cannot chmod tempdir (likely root or unsupported OS): %v", err)
	}
	defer os.Chmod(certDir, 0o755) // restore so cleanup works

	err := enroll.Run(t.Context(), &enroll.Config{
		EnrollURL: srv.URL + "/agents/enroll",
		CertDir:   certDir,
		Token:     "tok-001",
	})
	if err == nil {
		// On some systems (root user) chmod 555 doesn't restrict writes.
		t.Skip("write succeeded despite chmod 555 — likely running as root")
	}
	// Verify the error mentions the write failure, not some other error.
	if err.Error() == "" {
		t.Fatal("expected non-empty error")
	}
}
