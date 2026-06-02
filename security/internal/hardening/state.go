package hardening

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pmx-cloud/agents/security/internal/rootscope"
)

const (
	stateQueued  = "queued"
	stateRunning = "running"
	stateSuccess = "success"
	stateFail    = "fail"
)

// ApplyState tracks persisted hardening.apply execution state.
type ApplyState struct {
	JobID      string           `json:"job_id"`
	Profile    string           `json:"profile"`
	Status     string           `json:"status"`
	CreatedAt  time.Time        `json:"created_at"`
	UpdatedAt  time.Time        `json:"updated_at"`
	FinishedAt *time.Time       `json:"finished_at,omitempty"`
	Error      string           `json:"error,omitempty"`
	Operations []OperationState `json:"operations"`
}

// OperationState tracks one hardening operation within an apply job.
type OperationState struct {
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	Noop       bool       `json:"noop,omitempty"`
	Unit       string     `json:"unit,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Stderr     string     `json:"stderr,omitempty"`
}

type applyTracker struct {
	stateDir string
	state    *ApplyState
	index    map[string]int
}

func newApplyTracker(stateDir, jobID, profile string, ops []string) (*applyTracker, error) {
	path, err := applyStatePath(stateDir, jobID)
	if err != nil {
		return nil, err
	}
	_ = path

	now := nowUTC()
	st := &ApplyState{
		JobID:      jobID,
		Profile:    profile,
		Status:     stateRunning,
		CreatedAt:  now,
		UpdatedAt:  now,
		Operations: make([]OperationState, 0, len(ops)),
	}
	idx := make(map[string]int, len(ops))
	for _, op := range ops {
		idx[op] = len(st.Operations)
		st.Operations = append(st.Operations, OperationState{
			Name:   op,
			Status: stateQueued,
		})
	}
	t := &applyTracker{
		stateDir: stateDir,
		state:    st,
		index:    idx,
	}
	if err := t.persist(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *applyTracker) markOpRunning(name, unit string) error {
	op, err := t.lookup(name)
	if err != nil {
		return err
	}
	now := nowUTC()
	op.Status = stateRunning
	op.Unit = unit
	op.StartedAt = &now
	op.Stderr = ""
	return t.persist()
}

func (t *applyTracker) markOpSuccess(name string, noop bool) error {
	op, err := t.lookup(name)
	if err != nil {
		return err
	}
	now := nowUTC()
	op.Status = stateSuccess
	op.Noop = noop
	op.FinishedAt = &now
	op.Stderr = ""
	return t.persist()
}

func (t *applyTracker) markOpFail(name, stderr string) error {
	op, err := t.lookup(name)
	if err != nil {
		return err
	}
	now := nowUTC()
	op.Status = stateFail
	op.FinishedAt = &now
	op.Stderr = stderr
	return t.persist()
}

func (t *applyTracker) markJobSuccess() error {
	now := nowUTC()
	t.state.Status = stateSuccess
	t.state.Error = ""
	t.state.FinishedAt = &now
	return t.persist()
}

func (t *applyTracker) markJobFail(reason string) error {
	now := nowUTC()
	t.state.Status = stateFail
	t.state.Error = strings.TrimSpace(reason)
	t.state.FinishedAt = &now
	return t.persist()
}

func (t *applyTracker) lookup(name string) (*OperationState, error) {
	i, ok := t.index[name]
	if !ok {
		return nil, fmt.Errorf("hardening.apply: unknown operation state %q", name)
	}
	return &t.state.Operations[i], nil
}

func (t *applyTracker) persist() error {
	t.state.UpdatedAt = nowUTC()
	return saveApplyState(t.stateDir, t.state)
}

// LoadApplyState returns a persisted hardening.apply job state.
func LoadApplyState(stateDir, jobID string) (*ApplyState, error) {
	path, err := applyStatePath(stateDir, jobID)
	if err != nil {
		return nil, err
	}
	return loadApplyStateFile(path)
}

// ErrScopeNotFound indicates a systemd scope unit no longer exists.
var ErrScopeNotFound = errors.New("hardening: scope not found")

// ScopeState is a parsed subset of `systemctl show` properties.
type ScopeState struct {
	ActiveState    string
	SubState       string
	Result         string
	ExecMainStatus int
}

// ScopeInspector loads state for a given scope unit.
type ScopeInspector interface {
	Show(ctx context.Context, unit string) (ScopeState, error)
}

type systemctlInspector struct{}

func (i *systemctlInspector) Show(ctx context.Context, unit string) (ScopeState, error) {
	cmd := exec.CommandContext(ctx, "systemctl", "show", unit,
		"--no-page",
		"--property=ActiveState",
		"--property=SubState",
		"--property=Result",
		"--property=ExecMainStatus",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.ToLower(strings.TrimSpace(string(out)))
		if strings.Contains(msg, "could not be found") || strings.Contains(msg, "not found") {
			return ScopeState{}, ErrScopeNotFound
		}
		return ScopeState{}, fmt.Errorf("hardening.reconcile: systemctl show %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	props := parseSystemdKV(out)
	exit, _ := strconv.Atoi(strings.TrimSpace(props["ExecMainStatus"]))
	return ScopeState{
		ActiveState:    strings.TrimSpace(props["ActiveState"]),
		SubState:       strings.TrimSpace(props["SubState"]),
		Result:         strings.TrimSpace(props["Result"]),
		ExecMainStatus: exit,
	}, nil
}

// ReconcileApplyStates inspects persisted running hardening apply jobs and
// updates status using systemd scope unit state.
func ReconcileApplyStates(ctx context.Context, stateDir string, inspector ScopeInspector) error {
	if inspector == nil {
		inspector = &systemctlInspector{}
	}
	entries, err := os.ReadDir(applyStatesDir(stateDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("hardening.reconcile: readdir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(applyStatesDir(stateDir), entry.Name())
		st, err := loadApplyStateFile(path)
		if err != nil {
			return err
		}
		if st.Status != stateRunning {
			continue
		}

		changed, running, failed := reconcileOne(ctx, st, inspector)
		if !changed {
			continue
		}
		if failed {
			now := nowUTC()
			st.Status = stateFail
			if st.Error == "" {
				st.Error = "reconcile detected failed operation"
			}
			st.FinishedAt = &now
		} else if running {
			st.Status = stateRunning
			st.Error = ""
		} else if allSuccessful(st.Operations) {
			now := nowUTC()
			st.Status = stateSuccess
			st.Error = ""
			st.FinishedAt = &now
		} else {
			now := nowUTC()
			st.Status = stateFail
			st.Error = "reconcile found incomplete operation set"
			st.FinishedAt = &now
		}
		st.UpdatedAt = nowUTC()
		if err := writeApplyStateFile(path, st); err != nil {
			return err
		}
	}
	return nil
}

func reconcileOne(ctx context.Context, st *ApplyState, inspector ScopeInspector) (changed bool, running bool, failed bool) {
	for i := range st.Operations {
		op := &st.Operations[i]
		if op.Status != stateRunning {
			if op.Status == stateFail {
				failed = true
			}
			continue
		}
		if strings.TrimSpace(op.Unit) == "" {
			now := nowUTC()
			op.Status = stateFail
			op.FinishedAt = &now
			op.Stderr = "running operation missing scope unit"
			changed = true
			failed = true
			continue
		}
		scope, err := inspector.Show(ctx, op.Unit)
		if err != nil {
			if errors.Is(err, ErrScopeNotFound) {
				now := nowUTC()
				op.Status = stateFail
				op.FinishedAt = &now
				op.Stderr = "scope not found during reconcile"
				changed = true
				failed = true
				continue
			}
			now := nowUTC()
			op.Status = stateFail
			op.FinishedAt = &now
			op.Stderr = err.Error()
			changed = true
			failed = true
			continue
		}
		if strings.EqualFold(scope.ActiveState, "active") || strings.EqualFold(scope.SubState, "running") {
			running = true
			continue
		}
		now := nowUTC()
		if scope.ExecMainStatus == 0 || strings.EqualFold(scope.Result, "success") {
			op.Status = stateSuccess
			op.FinishedAt = &now
			op.Stderr = ""
			changed = true
			continue
		}
		op.Status = stateFail
		op.FinishedAt = &now
		op.Stderr = fmt.Sprintf("result=%s exit=%d", scope.Result, scope.ExecMainStatus)
		changed = true
		failed = true
	}
	return changed, running, failed
}

func allSuccessful(ops []OperationState) bool {
	if len(ops) == 0 {
		return false
	}
	for _, op := range ops {
		if op.Status != stateSuccess {
			return false
		}
	}
	return true
}

func saveApplyState(stateDir string, st *ApplyState) error {
	path, err := applyStatePath(stateDir, st.JobID)
	if err != nil {
		return err
	}
	return writeApplyStateFile(path, st)
}

func writeApplyStateFile(path string, st *ApplyState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("hardening.apply: mkdir state dir: %w", err)
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("hardening.apply: marshal state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("hardening.apply: write temp state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hardening.apply: install state: %w", err)
	}
	return nil
}

func loadApplyStateFile(path string) (*ApplyState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st ApplyState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("hardening.apply: decode state %s: %w", path, err)
	}
	return &st, nil
}

func applyStatePath(stateDir, jobID string) (string, error) {
	if _, err := rootscope.ScopeUnitName(jobID, "state"); err != nil {
		return "", fmt.Errorf("hardening.apply: invalid job id for state path: %w", err)
	}
	return filepath.Join(applyStatesDir(stateDir), jobID+".json"), nil
}

func applyStatesDir(stateDir string) string {
	return filepath.Join(stateDir, "hardening", "jobs")
}

func parseSystemdKV(raw []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func nowUTC() time.Time {
	return time.Now().UTC()
}
