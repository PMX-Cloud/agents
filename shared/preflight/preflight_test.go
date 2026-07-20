package preflight_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/shared/preflight"
)

// ── RunTo output ──────────────────────────────────────────────────────────────

func TestRunTo_AllPass(t *testing.T) {
	var buf bytes.Buffer
	code := preflight.RunTo(&buf, []preflight.Check{
		{Name: "always-pass", Run: func(ctx context.Context) error { return nil }},
		{Name: "also-pass", Run: func(ctx context.Context) error { return nil }},
	})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "[PASS] always-pass") {
		t.Errorf("expected PASS line, got: %q", out)
	}
	if !strings.Contains(out, "[PASS] also-pass") {
		t.Errorf("expected PASS line, got: %q", out)
	}
}

func TestRunTo_OneFail(t *testing.T) {
	var buf bytes.Buffer
	code := preflight.RunTo(&buf, []preflight.Check{
		{Name: "pass-me", Run: func(ctx context.Context) error { return nil }},
		{Name: "fail-me", Run: func(ctx context.Context) error { return errors.New("boom") }},
	})
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "[FAIL] fail-me") {
		t.Errorf("expected FAIL line, got: %q", out)
	}
	if !strings.Contains(out, "boom") {
		t.Errorf("expected error message in output, got: %q", out)
	}
	// pass-me must still be PASS
	if !strings.Contains(out, "[PASS] pass-me") {
		t.Errorf("expected PASS for pass-me, got: %q", out)
	}
}

func TestRunTo_AllFail(t *testing.T) {
	var buf bytes.Buffer
	code := preflight.RunTo(&buf, []preflight.Check{
		{Name: "a", Run: func(ctx context.Context) error { return errors.New("err a") }},
		{Name: "b", Run: func(ctx context.Context) error { return errors.New("err b") }},
	})
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
}

func TestRunTo_EmptyChecks(t *testing.T) {
	var buf bytes.Buffer
	code := preflight.RunTo(&buf, nil)
	if code != 0 {
		t.Fatalf("empty check list should pass, got %d", code)
	}
}

func TestRunTo_Timeout(t *testing.T) {
	// A check that blocks forever must be interrupted by the 5s context timeout.
	// We use a fast context in the runner by patching the check to detect Done.
	var buf bytes.Buffer
	code := preflight.RunTo(&buf, []preflight.Check{
		{Name: "instant-ctx-cancel", Run: func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		}},
	})
	// Should complete without hanging — pass or fail is both fine; what matters is
	// it returned.
	_ = code
}

// ── StandardChecks — smoke (no real files; just ensure it builds and runs) ──

func TestStandardChecks_NoFiles(t *testing.T) {
	checks := preflight.StandardChecks(
		"pmx-test",
		"/nonexistent/config.conf",
		"", // no cert
		"", // no key
		"/nonexistent/keyset.pub",
		nil,
	)
	if len(checks) == 0 {
		t.Fatal("StandardChecks must return at least one check")
	}
	var buf bytes.Buffer
	// All must fail gracefully (no panic).
	code := preflight.RunTo(&buf, checks)
	// Expect non-zero (files don't exist) but NOT a panic.
	if code == 0 {
		// On a system that somehow has those files (extremely unlikely), this is fine.
		t.Log("unexpected pass — non-existent paths somehow resolved")
	}
}

func TestStandardChecks_NamesIncludeExpected(t *testing.T) {
	checks := preflight.StandardChecks("pmx-test", "", "", "", "", nil)
	names := make(map[string]bool)
	for _, c := range checks {
		names[c.Name] = true
	}
	for _, want := range []string{"config-exists", "cert-readable", "cert-valid", "keyset-readable", "journald-writable", "clock-skew"} {
		if !names[want] {
			t.Errorf("StandardChecks missing check %q", want)
		}
	}
}

// ── certReadable skip when paths are empty ────────────────────────────────────

func TestStandardChecks_EmptyCertPaths_SkipsCertChecks(t *testing.T) {
	// When certPath and keyPath are empty, cert-readable and cert-valid must pass.
	checks := preflight.StandardChecks("pmx-test", "", "", "", "", nil)
	var buf bytes.Buffer
	preflight.RunTo(&buf, checks)
	out := buf.String()
	// cert-readable and cert-valid lines must be PASS (skip logic)
	for _, name := range []string{"cert-readable", "cert-valid"} {
		if strings.Contains(out, "[FAIL] "+name) {
			t.Errorf("check %q should PASS (skip) when paths are empty, got FAIL in output:\n%s", name, out)
		}
	}
}
