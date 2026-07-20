// Package ksm configures ksmtuned in one-shot mode.
package ksm

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pmx-cloud/agents/hardware-installer/internal/runner"
)

type Params struct {
	ConfigPath  string
	Systemctl   string
	OutputLimit int64
}

type ConfigureRequest struct {
	Enabled          bool `json:"enabled"`
	SleepMsec        int  `json:"sleep_millisecs"`
	PagesToScan      int  `json:"pages_to_scan"`
	MergeAcrossNodes int  `json:"merge_across_nodes"`
}

type Result struct {
	Changed bool `json:"changed"`
	Enabled bool `json:"enabled"`
}

func Configure(ctx context.Context, p Params, req ConfigureRequest, stepFn func(string)) (*Result, error) {
	sleepMsec := req.SleepMsec
	if sleepMsec <= 0 {
		sleepMsec = 100
	}
	pagesToScan := req.PagesToScan
	if pagesToScan <= 0 {
		pagesToScan = 200
	}
	mergeAcross := req.MergeAcrossNodes
	if mergeAcross < 0 || mergeAcross > 1 {
		mergeAcross = 1
	}
	runVal := "0"
	if req.Enabled {
		runVal = "1"
	}

	content := strings.Join([]string{
		"# Managed by pmx-hardware-installer",
		"KSM_RUN=" + runVal,
		"KSM_SLEEP_MSEC=" + strconv.Itoa(sleepMsec),
		"KSM_NPAGES_BOOST=" + strconv.Itoa(pagesToScan),
		"KSM_MERGE_ACROSS_NODES=" + strconv.Itoa(mergeAcross),
		"",
	}, "\n")
	changed, err := writeIfChanged(p.ConfigPath, []byte(content), 0o644)
	if err != nil {
		return nil, err
	}

	args := []string{"enable", "--now", "ksmtuned"}
	if !req.Enabled {
		args = []string{"disable", "--now", "ksmtuned"}
	}
	if _, err := runner.Run(ctx, runner.Command{
		Path:        p.Systemctl,
		Args:        args,
		OutputLimit: p.OutputLimit,
	}, stepFn); err != nil {
		return nil, fmt.Errorf("ksm: systemctl %s failed: %w", strings.Join(args, " "), err)
	}

	return &Result{Changed: changed, Enabled: req.Enabled}, nil
}

func writeIfChanged(path string, data []byte, mode os.FileMode) (bool, error) {
	current, err := os.ReadFile(path)
	if err == nil && bytes.Equal(current, data) {
		return false, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("ksm: read %q: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("ksm: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-ksm-*")
	if err != nil {
		return false, fmt.Errorf("ksm: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("ksm: write temp file: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("ksm: chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("ksm: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("ksm: replace %q: %w", path, err)
	}
	return true, nil
}
