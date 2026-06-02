// Package xshok detects known xshok/post-install conflict markers.
package xshok

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Params struct {
	Paths    []string
	Patterns []string
}

type Result struct {
	Detected bool     `json:"detected"`
	Matches  []string `json:"matches,omitempty"`
}

func Detect(p Params) (*Result, error) {
	paths := p.Paths
	if len(paths) == 0 {
		paths = []string{
			"/etc/sysctl.d/99-proxmox.conf",
			"/etc/motd",
			"/etc/motd.d",
			"/root/.bashrc",
			"/root/.profile",
		}
	}
	patterns := p.Patterns
	if len(patterns) == 0 {
		patterns = []string{"xshok", "proxmox-ve-post-install", "pvesmart", "proxmox ve post install"}
	}
	for i := range patterns {
		patterns[i] = strings.ToLower(patterns[i])
	}

	seen := map[string]struct{}{}
	matches := make([]string, 0, 8)
	for _, root := range paths {
		if _, err := os.Stat(root); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("xshok: stat %q: %w", root, err)
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			contains, err := fileContainsAny(path, patterns)
			if err != nil || !contains {
				return nil
			}
			if _, ok := seen[path]; ok {
				return nil
			}
			seen[path] = struct{}{}
			matches = append(matches, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(matches)
	return &Result{Detected: len(matches) > 0, Matches: matches}, nil
}

func fileContainsAny(path string, patterns []string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	lower := strings.ToLower(string(data))
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true, nil
		}
	}
	return false, nil
}
