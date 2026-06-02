// Package compliance implements compliance.report.
package compliance

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

//go:embed baselines/cis-debian-level1.json
var baselineCISDebianLevel1 []byte

type Baseline struct {
	Name     string    `json:"name"`
	Controls []Control `json:"controls"`
}

type Control struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	CheckType   string   `json:"check_type"`
	Path        string   `json:"path,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	Command     []string `json:"command,omitempty"`
}

type ControlResult struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Expected    string `json:"expected,omitempty"`
	Observed    string `json:"observed,omitempty"`
}

type Report struct {
	Baseline string          `json:"baseline"`
	Passed   int             `json:"passed"`
	Failed   int             `json:"failed"`
	Results  []ControlResult `json:"results"`
}

type Runner interface {
	Run(ctx context.Context, binary string, args ...string) (stdout string, stderr string, exitCode int, err error)
}

type ExecRunner struct{}

func (r *ExecRunner) Run(ctx context.Context, binary string, args ...string) (string, string, int, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	out, errOut := &strings.Builder{}, &strings.Builder{}
	cmd.Stdout = builderWriter{out}
	cmd.Stderr = builderWriter{errOut}
	err := cmd.Run()
	exit := 0
	if err != nil {
		exit = -1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
	}
	return strings.TrimSpace(out.String()), strings.TrimSpace(errOut.String()), exit, err
}

type builderWriter struct{ b *strings.Builder }

func (w builderWriter) Write(p []byte) (int, error) {
	return w.b.Write(p)
}

func RunReport(ctx context.Context, baselineName string, runner Runner) (*Report, error) {
	if runner == nil {
		runner = &ExecRunner{}
	}
	baseline, err := loadBaseline(baselineName)
	if err != nil {
		return nil, err
	}

	report := &Report{Baseline: baseline.Name, Results: make([]ControlResult, 0, len(baseline.Controls))}
	for _, c := range baseline.Controls {
		res := evaluateControl(ctx, c, runner)
		if res.Status == "pass" {
			report.Passed++
		} else {
			report.Failed++
		}
		report.Results = append(report.Results, res)
	}
	return report, nil
}

func loadBaseline(name string) (*Baseline, error) {
	if name == "" {
		name = "cis-debian-level1"
	}
	var raw []byte
	switch name {
	case "cis-debian-level1":
		raw = baselineCISDebianLevel1
	default:
		return nil, fmt.Errorf("unknown baseline %q", name)
	}
	var b Baseline
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %q: %w", name, err)
	}
	return &b, nil
}

func evaluateControl(ctx context.Context, c Control, runner Runner) ControlResult {
	result := ControlResult{ID: c.ID, Description: c.Description, Status: "fail"}
	switch c.CheckType {
	case "file_not_contains":
		data, err := os.ReadFile(c.Path)
		result.Expected = fmt.Sprintf("%s not present", c.Pattern)
		if err != nil {
			result.Observed = err.Error()
			return result
		}
		if !strings.Contains(string(data), c.Pattern) {
			result.Status = "pass"
			result.Observed = "pattern absent"
		} else {
			result.Observed = "pattern present"
		}
	case "file_contains":
		data, err := os.ReadFile(c.Path)
		result.Expected = fmt.Sprintf("%s present", c.Pattern)
		if err != nil {
			result.Observed = err.Error()
			return result
		}
		if strings.Contains(string(data), c.Pattern) {
			result.Status = "pass"
			result.Observed = "pattern present"
		} else {
			result.Observed = "pattern absent"
		}
	case "command_exit_zero", "command_exit_nonzero":
		if len(c.Command) == 0 {
			result.Observed = "missing command"
			return result
		}
		stdout, stderr, exit, _ := runner.Run(ctx, c.Command[0], c.Command[1:]...)
		result.Observed = strings.TrimSpace(strings.TrimSpace(stdout + " " + stderr))
		result.Expected = c.CheckType
		if c.CheckType == "command_exit_zero" && exit == 0 {
			result.Status = "pass"
		}
		if c.CheckType == "command_exit_nonzero" && exit != 0 {
			result.Status = "pass"
		}
	default:
		result.Observed = "unsupported check_type"
	}
	return result
}
