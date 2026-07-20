// Package apt manages one-shot apt tuning and optional source pin writes.
package apt

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pmx-cloud/agents/hardware-installer/internal/runner"
)

type Params struct {
	AptGetPath  string
	ConfigDir   string
	OutputLimit int64
}

type Request struct {
	Pins             []Pin `json:"pins"`
	InstallTransport *bool `json:"install_transport"`
}

type Pin struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type Result struct {
	Changed      bool     `json:"changed"`
	WrittenFiles []string `json:"written_files,omitempty"`
}

var safePinName = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func Tune(ctx context.Context, p Params, req Request, stepFn func(string)) (*Result, error) {
	installTransport := true
	if req.InstallTransport != nil {
		installTransport = *req.InstallTransport
	}

	if installTransport {
		env := map[string]string{"DEBIAN_FRONTEND": "noninteractive"}
		if _, err := runner.Run(ctx, runner.Command{
			Path:        p.AptGetPath,
			Args:        []string{"update"},
			Env:         env,
			OutputLimit: p.OutputLimit,
		}, stepFn); err != nil {
			return nil, fmt.Errorf("apt: update failed: %w", err)
		}
		if _, err := runner.Run(ctx, runner.Command{
			Path:        p.AptGetPath,
			Args:        []string{"install", "-y", "apt-transport-https", "ca-certificates"},
			Env:         env,
			OutputLimit: p.OutputLimit,
		}, stepFn); err != nil {
			return nil, fmt.Errorf("apt: install transport packages failed: %w", err)
		}
	}

	if err := os.MkdirAll(p.ConfigDir, 0o755); err != nil {
		return nil, fmt.Errorf("apt: create config dir %q: %w", p.ConfigDir, err)
	}

	result := &Result{}
	baseFiles := map[string]string{
		"99-pmx-cloud-performance": strings.Join([]string{
			"Acquire::Queue-Mode \"access\";",
			"Acquire::Retries \"3\";",
			"Acquire::http::Pipeline-Depth \"5\";",
			"APT::Get::Show-Upgraded \"true\";",
		}, "\n") + "\n",
		"99-pmx-cloud-no-languages": "Acquire::Languages \"none\";\n",
	}
	for name, body := range baseFiles {
		path := filepath.Join(p.ConfigDir, name)
		changed, err := writeFileIfChanged(path, []byte(body), 0o644)
		if err != nil {
			return nil, err
		}
		if changed {
			result.Changed = true
			result.WrittenFiles = append(result.WrittenFiles, path)
		}
	}

	for _, pin := range req.Pins {
		name := strings.TrimSpace(pin.Name)
		if !safePinName.MatchString(name) {
			return nil, fmt.Errorf("apt: invalid pin name %q", pin.Name)
		}
		content := strings.TrimSpace(pin.Content)
		if content == "" {
			return nil, fmt.Errorf("apt: pin %q content is required", pin.Name)
		}
		path := filepath.Join(p.ConfigDir, "99-pmx-cloud-pin-"+name)
		changed, err := writeFileIfChanged(path, []byte(content+"\n"), 0o644)
		if err != nil {
			return nil, err
		}
		if changed {
			result.Changed = true
			result.WrittenFiles = append(result.WrittenFiles, path)
		}
	}

	return result, nil
}

func writeFileIfChanged(path string, data []byte, mode os.FileMode) (bool, error) {
	current, err := os.ReadFile(path)
	if err == nil && bytes.Equal(current, data) {
		return false, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("apt: read %q: %w", path, err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-apt-*")
	if err != nil {
		return false, fmt.Errorf("apt: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("apt: write temp file: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("apt: chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("apt: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("apt: replace %q: %w", path, err)
	}
	return true, nil
}
