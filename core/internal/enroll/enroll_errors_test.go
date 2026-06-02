package enroll_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pmx-cloud/agents/core/internal/enroll"
)

func TestRun_BackendReturns400_EmptyError(t *testing.T) {
	// 400 with no error message should fall back to "HTTP 400".
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// Return a JSON body with empty "error" field.
		_ = json.NewEncoder(w).Encode(map[string]string{"error": ""})
	}))
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
		t.Fatal("expected error for 400 response")
	}
	if !containsAny(err.Error(), "HTTP 400", "backend error") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestRun_InvalidEnrollURL(t *testing.T) {
	err := enroll.Run(t.Context(), &enroll.Config{
		EnrollURL: "://bad-url",
		CertDir:   t.TempDir(),
		Token:     "tok-001",
	})
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestRun_WriteToReadOnlyDir(t *testing.T) {
	srv := fakeEnrollServer(t, http.StatusOK, fakeCertPEM, "")
	defer srv.Close()

	origClient := http.DefaultClient
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = origClient }()

	err := enroll.Run(t.Context(), &enroll.Config{
		EnrollURL: srv.URL + "/agents/enroll",
		CertDir:   "/nonexistent/readonly/dir",
		Token:     "tok-001",
	})
	if err == nil {
		t.Fatal("expected error writing to non-existent directory")
	}
}
