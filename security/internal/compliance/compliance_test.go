package compliance_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/security/internal/compliance"
)

type mockRunner struct{}

func (m *mockRunner) Run(ctx context.Context, binary string, args ...string) (string, string, int, error) {
	if len(args) > 0 && args[0] == "is-enabled" && len(args) > 1 && args[1] == "auditd.service" {
		return "enabled", "", 0, nil
	}
	return "disabled", "", 1, nil
}

func TestRunReportReturnsResults(t *testing.T) {
	rep, err := compliance.RunReport(context.Background(), "cis-debian-level1", &mockRunner{})
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if len(rep.Results) == 0 {
		t.Fatalf("expected controls, got none")
	}
}
