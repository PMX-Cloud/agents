package hardening_test

import (
	"context"
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/security/internal/hardening"
	"github.com/pmx-cloud/agents/security/internal/rootscope"
)

type mockRootRunner struct {
	calls []string
}

func (m *mockRootRunner) RunRoot(ctx context.Context, jobID, name, command string, args []string, h rootscope.Hardening) (*rootscope.Result, error) {
	m.calls = append(m.calls, name+":"+strings.Join(args, " "))
	if strings.Contains(name, "check") {
		return &rootscope.Result{ExitCode: 1}, nil // not yet applied
	}
	return &rootscope.Result{ExitCode: 0}, nil
}

func TestApplyCISLevel1RunsOperations(t *testing.T) {
	m := &mockRootRunner{}
	res, err := hardening.Apply(context.Background(), hardening.ApplyParams{JobID: "job1", Profile: "cis_level1", StateDir: t.TempDir()}, m)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(res.Applied) == 0 {
		t.Fatalf("expected applied operations, got %+v", res)
	}
}

func TestApplyCustomRejectsUnknownOperation(t *testing.T) {
	_, err := hardening.Apply(context.Background(), hardening.ApplyParams{Profile: "custom", Operations: []string{"bad-op"}, StateDir: t.TempDir()}, &mockRootRunner{})
	if err == nil || !strings.Contains(err.Error(), "unknown operation") {
		t.Fatalf("expected unknown operation error, got %v", err)
	}
}
