package preflight_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/shared/preflight"
)

// TestJournaldWritable_MockBinary exercises the exec path of checkJournaldWritable
// by putting a fake "systemd-cat" binary in PATH that succeeds.
func TestJournaldWritable_MockBinary(t *testing.T) {
	// Create a fake systemd-cat that does nothing and exits 0.
	binDir := t.TempDir()
	fakePath := filepath.Join(binDir, "systemd-cat")
	// Write a minimal shell script (works on macOS + Linux).
	script := "#!/bin/sh\nexec \"$@\"\n"
	if err := os.WriteFile(fakePath, []byte(script), 0o755); err != nil {
		t.Skipf("cannot write fake binary: %v", err)
	}

	// Prepend binDir to PATH so exec.LookPath finds our fake binary first.
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+":"+origPath)

	checks := preflight.StandardChecks("pmx-test", "/nonexistent/conf", "", "", "/nonexistent/keyset", nil)
	var buf bytes.Buffer
	preflight.RunTo(&buf, checks)
	out := buf.String()
	// journald-writable must now run (and PASS since our script succeeds).
	if !strings.Contains(out, "journald-writable") {
		t.Errorf("journald-writable check must appear in output, got:\n%s", out)
	}
}

// TestClockSkew_MockTimedatectl exercises the timedatectl path.
func TestClockSkew_MockTimedatectl(t *testing.T) {
	binDir := t.TempDir()
	// Write a fake timedatectl that outputs "NTPSynchronized=yes".
	script := "#!/bin/sh\necho 'NTPSynchronized=yes'\n"
	fakePath := filepath.Join(binDir, "timedatectl")
	if err := os.WriteFile(fakePath, []byte(script), 0o755); err != nil {
		t.Skipf("cannot write fake timedatectl: %v", err)
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+":"+origPath)

	checks := preflight.StandardChecks("pmx-test", "/nonexistent/conf", "", "", "/nonexistent/keyset", nil)
	var buf bytes.Buffer
	preflight.RunTo(&buf, checks)
	out := buf.String()
	if !strings.Contains(out, "clock-skew") {
		t.Errorf("clock-skew check must appear in output, got:\n%s", out)
	}
	if strings.Contains(out, "[FAIL] clock-skew") {
		t.Errorf("clock-skew must PASS with NTPSynchronized=yes, got:\n%s", out)
	}
}

// TestClockSkew_MockTimedatectl_NotSynced exercises the NTP failure path.
func TestClockSkew_MockTimedatectl_NotSynced(t *testing.T) {
	binDir := t.TempDir()
	script := "#!/bin/sh\necho 'NTPSynchronized=no'\n"
	fakePath := filepath.Join(binDir, "timedatectl")
	if err := os.WriteFile(fakePath, []byte(script), 0o755); err != nil {
		t.Skipf("cannot write fake timedatectl: %v", err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	checks := preflight.StandardChecks("pmx-test", "/nonexistent/conf", "", "", "/nonexistent/keyset", nil)
	var buf bytes.Buffer
	preflight.RunTo(&buf, checks)
	out := buf.String()
	if !strings.Contains(out, "[FAIL] clock-skew") {
		t.Errorf("clock-skew must FAIL with NTPSynchronized=no, got:\n%s", out)
	}
}
