package lynis_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pmx-cloud/agents/security/internal/lynis"
)

type mockRunner struct{}

func (m *mockRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, []byte, error) {
	return []byte("ok"), nil, nil
}

func TestRunParsesReport(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "lynis-report.dat")
	if err := os.WriteFile(report, []byte("hardening_index=64\nwarning[]=Disable x\nsuggestion[]=Enable y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := lynis.Run(context.Background(), "/usr/sbin/lynis", "", report, nil, &mockRunner{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Findings["hardening_index"] != "64" {
		t.Fatalf("unexpected findings: %+v", res.Findings)
	}
}
