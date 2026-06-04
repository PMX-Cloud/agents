// Package smart implements SMART polling and schedule persistence.
package smart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pmx-cloud/agents/storage/internal/storageexec"
)

// PollResult is the stable smart.poll payload.
type PollResult struct {
	Disks []DiskResult `json:"disks"`
}

// DiskResult summarizes SMART status for one disk.
type DiskResult struct {
	Device      string             `json:"device"`
	Status      string             `json:"status"`
	Temperature float64            `json:"temperature_c,omitempty"`
	Attributes  map[string]float64 `json:"attributes,omitempty"`
	Error       string             `json:"error,omitempty"`
}

// ScheduleParams controls smart.schedule storage.
type ScheduleParams struct {
	Interval string `json:"interval"`
	StateDir string `json:"state_dir"`
}

type smartJSON struct {
	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature struct {
		Current float64 `json:"current"`
	} `json:"temperature"`
	ATA struct {
		Table []struct {
			Name string `json:"name"`
			Raw  struct {
				Value float64 `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMe struct {
		Temperature float64 `json:"temperature"`
	} `json:"nvme_smart_health_information_log"`
}

// Poll polls smartctl for each disk, downgrading unsupported disks to status=unsupported.
func Poll(ctx context.Context, ex storageexec.Interface, devices []string) (*PollResult, error) {
	if len(devices) == 0 {
		return &PollResult{}, nil
	}
	out := &PollResult{Disks: make([]DiskResult, 0, len(devices))}
	for _, dev := range devices {
		entry := DiskResult{Device: dev, Attributes: map[string]float64{}}
		// -H reports the overall SMART health (smart_status.passed); without it
		// smartctl -A omits smart_status entirely and every disk would parse as
		// "failed". -A adds the vendor attribute table.
		res, err := ex.Smartctl(ctx, "-j", "-H", "-A", dev)

		var stdout, stderrBytes []byte
		if res != nil {
			stdout = res.Stdout
			stderrBytes = res.Stderr
		}

		// smartctl encodes findings in the exit code as a bitmask: bits 3-7
		// (failing/threshold attributes, error-log or self-test-log entries) are
		// non-fatal and still emit a complete JSON document, so we must NOT treat
		// a non-zero exit as a data error. Parse stdout first; only when there is
		// no usable JSON do we classify the device as unsupported or errored.
		var parsed smartJSON
		if parseErr := json.Unmarshal(stdout, &parsed); parseErr != nil {
			stderr := strings.ToLower(string(stderrBytes))
			if isUnsupportedSmart(err, stderr) {
				entry.Status = "unsupported"
			} else {
				entry.Status = "error"
				if err != nil {
					entry.Error = err.Error()
				} else {
					entry.Error = fmt.Sprintf("parse smartctl json: %v", parseErr)
				}
			}
			out.Disks = append(out.Disks, entry)
			continue
		}

		switch {
		case parsed.SmartStatus == nil:
			// JSON present but health indeterminate (e.g. controller did not
			// report smart_status). Surface the data we have without claiming a
			// pass/fail verdict.
			entry.Status = "unknown"
		case parsed.SmartStatus.Passed:
			entry.Status = "passed"
		default:
			entry.Status = "failed"
		}
		if parsed.Temperature.Current > 0 {
			entry.Temperature = parsed.Temperature.Current
		} else if parsed.NVMe.Temperature > 0 {
			// NVMe often reports Kelvin.
			entry.Temperature = kelvinMaybeToC(parsed.NVMe.Temperature)
		}
		for _, row := range parsed.ATA.Table {
			if strings.TrimSpace(row.Name) == "" {
				continue
			}
			entry.Attributes[row.Name] = row.Raw.Value
		}
		out.Disks = append(out.Disks, entry)
	}
	return out, nil
}

// isUnsupportedSmart reports whether a failed smartctl invocation indicates the
// device simply lacks SMART support (vs a genuine error worth surfacing).
func isUnsupportedSmart(err error, stderr string) bool {
	if err == nil || !errors.Is(err, storageexec.ErrExit) {
		return false
	}
	return strings.Contains(stderr, "unavailable") ||
		strings.Contains(stderr, "unsupported") ||
		strings.Contains(stderr, "not support")
}

// Schedule persists a polling schedule file under agent state.
func Schedule(_ context.Context, p ScheduleParams) (string, error) {
	interval := strings.TrimSpace(p.Interval)
	if interval == "" {
		interval = "15m"
	}
	if _, err := strconv.Atoi(strings.TrimSuffix(interval, "m")); strings.HasSuffix(interval, "m") && err != nil {
		return "", fmt.Errorf("smart.schedule: invalid minute interval %q", p.Interval)
	}
	if p.StateDir == "" {
		p.StateDir = "/var/lib/pmx-cloud/storage"
	}
	if err := os.MkdirAll(p.StateDir, 0o700); err != nil {
		return "", fmt.Errorf("smart.schedule: mkdir state dir: %w", err)
	}
	path := filepath.Join(p.StateDir, "smart-schedule.json")
	body, _ := json.Marshal(map[string]string{"interval": interval})
	if err := os.WriteFile(path, body, 0o400); err != nil {
		return "", fmt.Errorf("smart.schedule: write state file: %w", err)
	}
	return path, nil
}

func kelvinMaybeToC(v float64) float64 {
	if v > 200 {
		return v - 273.15
	}
	return v
}
