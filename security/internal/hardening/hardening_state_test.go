package hardening_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/security/internal/hardening"
)

func TestApplyPersistsSuccessState(t *testing.T) {
	stateDir := t.TempDir()
	m := &mockRootRunner{}

	_, err := hardening.Apply(context.Background(), hardening.ApplyParams{
		JobID:    "job-state-001",
		Profile:  "cis_level1",
		StateDir: stateDir,
	}, m)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	st, err := hardening.LoadApplyState(stateDir, "job-state-001")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st.Status != "success" {
		t.Fatalf("expected success status, got %q", st.Status)
	}
	if len(st.Operations) == 0 {
		t.Fatal("expected at least one operation in state")
	}
	for _, op := range st.Operations {
		if op.Status != "success" {
			t.Fatalf("operation %s should be success, got %q", op.Name, op.Status)
		}
	}
}

func TestReconcileApplyStatesMarksSuccess(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now().UTC()
	writeApplyStateFixture(t, stateDir, &hardening.ApplyState{
		JobID:     "job-reconcile-success",
		Profile:   "cis_level1",
		Status:    "running",
		CreatedAt: now,
		UpdatedAt: now,
		Operations: []hardening.OperationState{
			{
				Name:      "ssh_level1",
				Status:    "running",
				Unit:      "pmx-sec-apply-job-reconcile-success-ssh_level1.scope",
				StartedAt: &now,
			},
		},
	})

	err := hardening.ReconcileApplyStates(context.Background(), stateDir, mockInspector{
		out: hardening.ScopeState{
			ActiveState:    "inactive",
			SubState:       "dead",
			Result:         "success",
			ExecMainStatus: 0,
		},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	st, err := hardening.LoadApplyState(stateDir, "job-reconcile-success")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st.Status != "success" {
		t.Fatalf("expected job success after reconcile, got %q", st.Status)
	}
	if st.Operations[0].Status != "success" {
		t.Fatalf("expected op success after reconcile, got %q", st.Operations[0].Status)
	}
}

func TestReconcileApplyStatesMarksFailureWhenScopeMissing(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now().UTC()
	writeApplyStateFixture(t, stateDir, &hardening.ApplyState{
		JobID:     "job-reconcile-missing",
		Profile:   "cis_level1",
		Status:    "running",
		CreatedAt: now,
		UpdatedAt: now,
		Operations: []hardening.OperationState{
			{
				Name:      "ssh_level1",
				Status:    "running",
				Unit:      "pmx-sec-apply-job-reconcile-missing-ssh_level1.scope",
				StartedAt: &now,
			},
		},
	})

	err := hardening.ReconcileApplyStates(context.Background(), stateDir, mockInspector{
		err: hardening.ErrScopeNotFound,
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	st, err := hardening.LoadApplyState(stateDir, "job-reconcile-missing")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st.Status != "fail" {
		t.Fatalf("expected job fail after reconcile, got %q", st.Status)
	}
	if st.Operations[0].Status != "fail" {
		t.Fatalf("expected op fail after reconcile, got %q", st.Operations[0].Status)
	}
}

type mockInspector struct {
	out hardening.ScopeState
	err error
}

func (m mockInspector) Show(ctx context.Context, unit string) (hardening.ScopeState, error) {
	_ = ctx
	_ = unit
	if m.err != nil {
		return hardening.ScopeState{}, m.err
	}
	return m.out, nil
}

func writeApplyStateFixture(t *testing.T, stateDir string, st *hardening.ApplyState) {
	t.Helper()
	path := filepath.Join(stateDir, "hardening", "jobs", st.JobID+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestReconcileApplyStatesMissingDirectoryIsNoop(t *testing.T) {
	err := hardening.ReconcileApplyStates(context.Background(), t.TempDir(), mockInspector{err: errors.New("should not be called")})
	if err != nil {
		t.Fatalf("expected no error when state dir missing, got: %v", err)
	}
}
