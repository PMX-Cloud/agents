package runner_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/hardware-installer/internal/runner"
)

func TestRunSuccess(t *testing.T) {
	t.Parallel()

	res, err := runner.Run(context.Background(), runner.Command{
		Path: "/bin/sh",
		Args: []string{"-c", "printf 'ok'"},
	}, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "ok") {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestRunTimeout(t *testing.T) {
	t.Parallel()

	_, err := runner.Run(context.Background(), runner.Command{
		Path:    "/bin/sh",
		Args:    []string{"-c", "sleep 1"},
		Timeout: 10 * time.Millisecond,
	}, nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
