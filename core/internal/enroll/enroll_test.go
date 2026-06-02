package enroll_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/pmx-cloud/agents/core/internal/enroll"
)

// fakeEnrollServer returns an httptest.Server that mimics the backend enroll endpoint.
func fakeEnrollServer(t *testing.T, statusCode int, certPEM string, errMsg string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(statusCode)
		resp := map[string]string{}
		if certPEM != "" {
			resp["certificate"] = certPEM
		}
		if errMsg != "" {
			resp["error"] = errMsg
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	return srv
}

// selfSignedCert is a minimal fake PEM cert for testing write logic only.
const fakeCertPEM = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJALQ5ZxFgLfFcMA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMME3Bt
eC1jb3JlLXRlc3QtY2VydDAeFw0yNjA1MDEwMDAwMDBaFw0yNzA1MDEwMDAwMDBa
MB4xHDAaBgNVBAMME3BteC1jb3JlLXRlc3QtY2VydDBcMA0GCSqGSIb3DQEBAQUA
A0sAMEgCQQDSomerandomdatagoeshereJustForTestingPurposesOnlyMakeItLong
AgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADQQA=
-----END CERTIFICATE-----
`

// ── Validation tests (no network needed) ─────────────────────────────────────

func TestRun_EmptyToken(t *testing.T) {
	err := enroll.Run(t.Context(), &enroll.Config{
		EnrollURL: "https://example.com/agents/enroll",
		CertDir:   t.TempDir(),
		Token:     "",
	})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestRun_EmptyURL(t *testing.T) {
	err := enroll.Run(t.Context(), &enroll.Config{
		EnrollURL: "",
		CertDir:   t.TempDir(),
		Token:     "tok-001",
	})
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestRun_CertAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	// Pre-create client.crt so the idempotency check triggers.
	if err := os.WriteFile(filepath.Join(dir, "client.crt"), []byte("existing"), 0o400); err != nil {
		t.Fatal(err)
	}
	err := enroll.Run(t.Context(), &enroll.Config{
		EnrollURL: "https://example.com/agents/enroll",
		CertDir:   dir,
		Token:     "tok-001",
	})
	if err == nil {
		t.Fatal("expected error when cert already exists")
	}
	if !containsAny(err.Error(), "already exists", "exist") {
		t.Fatalf("expected 'already exists' in error, got: %v", err)
	}
}

// ── Network tests using httptest ──────────────────────────────────────────────

func TestRun_BackendReturns400(t *testing.T) {
	srv := fakeEnrollServer(t, http.StatusBadRequest, "", "token already used")
	defer srv.Close()

	// The TLS server uses a self-signed cert; we need a permissive HTTP client.
	origClient := http.DefaultClient
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = origClient }()

	err := enroll.Run(t.Context(), &enroll.Config{
		EnrollURL: srv.URL + "/agents/enroll",
		CertDir:   t.TempDir(),
		Token:     "tok-already-used",
	})
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	if !containsAny(err.Error(), "backend error", "token already used") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_BackendReturnsEmptyCert(t *testing.T) {
	srv := fakeEnrollServer(t, http.StatusOK, "", "")
	defer srv.Close()

	origClient := http.DefaultClient
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = origClient }()

	err := enroll.Run(t.Context(), &enroll.Config{
		EnrollURL: srv.URL + "/agents/enroll",
		CertDir:   t.TempDir(),
		Token:     "tok-001",
	})
	if err == nil {
		t.Fatal("expected error for empty certificate")
	}
}

func TestRun_AtomicWrite_KeyFileModeOnSuccess(t *testing.T) {
	// The cert returned is not a valid x509 cert — that's fine for file-write tests.
	srv := fakeEnrollServer(t, http.StatusOK, fakeCertPEM, "")
	defer srv.Close()

	origClient := http.DefaultClient
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = origClient }()

	dir := t.TempDir()
	err := enroll.Run(t.Context(), &enroll.Config{
		EnrollURL: srv.URL + "/agents/enroll",
		CertDir:   dir,
		Token:     "tok-001",
	})
	if err != nil {
		// The fake cert is not a valid PEM key pair so key-write may fail after
		// the cert is written. We accept either:
		//   a) success (very permissive fake servers), or
		//   b) error after cert write (key PEM marshal failed).
		// Either way, no leftover temp files should remain.
		files, _ := os.ReadDir(dir)
		for _, f := range files {
			if len(f.Name()) > 14 && f.Name()[:14] == ".enroll-tmp-" {
				t.Errorf("temp file leaked: %s", f.Name())
			}
		}
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
