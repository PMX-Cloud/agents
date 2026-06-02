// Package retention computes and applies backup retention policies.
package retention

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pmx-cloud/agents/backup/internal/archive"
)

type Policy struct {
	KeepDailies   int `json:"keep_dailies"`
	KeepWeeklies  int `json:"keep_weeklies"`
	KeepMonthlies int `json:"keep_monthlies"`
}

type Archive struct {
	Path      string    `json:"path"`
	FileName  string    `json:"file_name"`
	VMID      string    `json:"vmid"`
	Timestamp time.Time `json:"timestamp"`
}

type ApplyParams struct {
	ArchiveRoot  string
	ArchiveRoots []string
	VMID         string
	Policy       Policy
	DryRun       bool
}

type ApplyResult struct {
	ArchiveRoot string   `json:"archive_root"`
	DryRun      bool     `json:"dry_run"`
	Evaluated   int      `json:"evaluated"`
	Kept        []string `json:"kept"`
	WouldDelete []string `json:"would_delete"`
	Deleted     []string `json:"deleted"`
}

var archiveNamePattern = regexp.MustCompile(`^vzdump-(qemu|lxc)-([0-9]+)-([0-9]{4}_[0-9]{2}_[0-9]{2})-([0-9]{2}_[0-9]{2}_[0-9]{2})`) //nolint:lll

func Enumerate(root string, vmidFilter string) ([]Archive, error) {
	dirEntries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("retention: read dir %q: %w", root, err)
	}

	archives := make([]Archive, 0, len(dirEntries))
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		parsed, ok := ParseArchiveFileName(de.Name())
		if !ok {
			continue
		}
		if vmidFilter != "" && parsed.VMID != vmidFilter {
			continue
		}
		parsed.Path = filepath.Join(root, de.Name())
		archives = append(archives, parsed)
	}

	sort.Slice(archives, func(i, j int) bool {
		return archives[i].Timestamp.After(archives[j].Timestamp)
	})
	return archives, nil
}

func ParseArchiveFileName(name string) (Archive, bool) {
	matches := archiveNamePattern.FindStringSubmatch(name)
	if len(matches) != 5 {
		return Archive{}, false
	}
	stamp, err := time.ParseInLocation("2006_01_02-15_04_05", matches[3]+"-"+matches[4], time.UTC)
	if err != nil {
		return Archive{}, false
	}
	return Archive{
		FileName:  name,
		VMID:      matches[2],
		Timestamp: stamp.UTC(),
	}, true
}

func ComputeKeepSet(archives []Archive, policy Policy) map[string]struct{} {
	kept := make(map[string]struct{})
	if len(archives) == 0 {
		return kept
	}

	if policy.KeepDailies > 0 {
		seen := make(map[string]struct{})
		for _, candidate := range archives {
			dayKey := candidate.Timestamp.UTC().Format("2006-01-02")
			if _, ok := seen[dayKey]; ok {
				continue
			}
			seen[dayKey] = struct{}{}
			kept[candidate.Path] = struct{}{}
			if len(seen) >= policy.KeepDailies {
				break
			}
		}
	}

	if policy.KeepWeeklies > 0 {
		seen := make(map[string]struct{})
		for _, candidate := range archives {
			year, week := candidate.Timestamp.UTC().ISOWeek()
			weekKey := fmt.Sprintf("%04d-W%02d", year, week)
			if _, ok := seen[weekKey]; ok {
				continue
			}
			seen[weekKey] = struct{}{}
			kept[candidate.Path] = struct{}{}
			if len(seen) >= policy.KeepWeeklies {
				break
			}
		}
	}

	if policy.KeepMonthlies > 0 {
		seen := make(map[string]struct{})
		for _, candidate := range archives {
			monthKey := candidate.Timestamp.UTC().Format("2006-01")
			if _, ok := seen[monthKey]; ok {
				continue
			}
			seen[monthKey] = struct{}{}
			kept[candidate.Path] = struct{}{}
			if len(seen) >= policy.KeepMonthlies {
				break
			}
		}
	}

	return kept
}

func Apply(params ApplyParams) (*ApplyResult, error) {
	if params.Policy.KeepDailies < 0 || params.Policy.KeepWeeklies < 0 || params.Policy.KeepMonthlies < 0 {
		return nil, fmt.Errorf("retention: keep policy values must be >= 0")
	}

	root, err := archive.EnsureWritableDirectory(params.ArchiveRoot, params.ArchiveRoots)
	if err != nil {
		return nil, err
	}

	archives, err := Enumerate(root, strings.TrimSpace(params.VMID))
	if err != nil {
		return nil, err
	}
	keepSet := ComputeKeepSet(archives, params.Policy)

	res := &ApplyResult{
		ArchiveRoot: root,
		DryRun:      params.DryRun,
		Evaluated:   len(archives),
		Kept:        make([]string, 0, len(archives)),
		WouldDelete: make([]string, 0, len(archives)),
		Deleted:     []string{},
	}
	for _, candidate := range archives {
		if _, ok := keepSet[candidate.Path]; ok {
			res.Kept = append(res.Kept, candidate.Path)
			continue
		}
		res.WouldDelete = append(res.WouldDelete, candidate.Path)
	}

	if params.DryRun {
		return res, nil
	}

	for _, path := range res.WouldDelete {
		deleted, err := archive.DeleteArchiveWithSidecars(path, params.ArchiveRoots)
		if err != nil {
			return nil, err
		}
		res.Deleted = append(res.Deleted, deleted...)
	}

	return res, nil
}
