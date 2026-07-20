// Package nfs implements nfs.share.* commands.
package nfs

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pmx-cloud/agents/storage/internal/storageexec"
)

var allowedOptions = map[string]bool{
	"rw":               true,
	"ro":               true,
	"sync":             true,
	"async":            true,
	"no_subtree_check": true,
	"no_root_squash":   true,
}

// ShareParams configures NFS share lifecycle operations.
type ShareParams struct {
	ID         string   `json:"id"`
	Path       string   `json:"path"`
	Network    string   `json:"network"`
	Options    []string `json:"options"`
	ExportsDir string   `json:"exports_dir"`
}

// Share is the parsed nfs.share.list item.
type Share struct {
	ID      string   `json:"id"`
	Path    string   `json:"path"`
	Network string   `json:"network"`
	Options []string `json:"options"`
}

func ShareCreate(ctx context.Context, ex storageexec.Interface, p ShareParams) error {
	if !isSafeID(p.ID) {
		return fmt.Errorf("nfs.share.create: invalid id")
	}
	if !isValidPath(p.Path) {
		return fmt.Errorf("nfs.share.create: invalid path")
	}
	if _, err := os.Stat(p.Path); err != nil {
		return fmt.Errorf("nfs.share.create: path does not exist: %w", err)
	}
	if !isValidNetwork(p.Network) {
		return fmt.Errorf("nfs.share.create: invalid network spec")
	}
	options, err := validateOptions(p.Options)
	if err != nil {
		return err
	}

	exportsDir := p.ExportsDir
	if exportsDir == "" {
		exportsDir = "/etc/exports.d"
	}
	if err := os.MkdirAll(exportsDir, 0o755); err != nil {
		return fmt.Errorf("nfs.share.create: mkdir exports dir: %w", err)
	}
	content := fmt.Sprintf("%s %s(%s)\n", p.Path, p.Network, strings.Join(options, ","))
	file := filepath.Join(exportsDir, "pmx-"+p.ID+".exports")
	if err := os.WriteFile(file, []byte(content), 0o640); err != nil {
		return fmt.Errorf("nfs.share.create: write exports file: %w", err)
	}
	if _, err := ex.Exportfs(ctx, "-ra"); err != nil {
		return fmt.Errorf("nfs.share.create: exportfs -ra: %w", err)
	}
	return nil
}

func ShareDelete(ctx context.Context, ex storageexec.Interface, p ShareParams) error {
	if !isSafeID(p.ID) {
		return fmt.Errorf("nfs.share.delete: invalid id")
	}
	exportsDir := p.ExportsDir
	if exportsDir == "" {
		exportsDir = "/etc/exports.d"
	}
	file := filepath.Join(exportsDir, "pmx-"+p.ID+".exports")
	if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("nfs.share.delete: remove exports file: %w", err)
	}
	if _, err := ex.Exportfs(ctx, "-ra"); err != nil {
		return fmt.Errorf("nfs.share.delete: exportfs -ra: %w", err)
	}
	return nil
}

func ShareList(p ShareParams) ([]Share, error) {
	exportsDir := p.ExportsDir
	if exportsDir == "" {
		exportsDir = "/etc/exports.d"
	}
	glob := filepath.Join(exportsDir, "pmx-*.exports")
	files, err := filepath.Glob(glob)
	if err != nil {
		return nil, fmt.Errorf("nfs.share.list: glob exports files: %w", err)
	}
	sort.Strings(files)
	shares := make([]Share, 0, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("nfs.share.list: read %s: %w", file, err)
		}
		line := strings.TrimSpace(string(data))
		if line == "" {
			continue
		}
		path, network, options, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("nfs.share.list: parse %s: %w", file, err)
		}
		id := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(file), "pmx-"), ".exports")
		shares = append(shares, Share{ID: id, Path: path, Network: network, Options: options})
	}
	return shares, nil
}

func parseLine(line string) (path, network string, options []string, err error) {
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return "", "", nil, fmt.Errorf("invalid exports line")
	}
	path = fields[0]
	netAndOpts := fields[1]
	open := strings.IndexRune(netAndOpts, '(')
	close := strings.LastIndex(netAndOpts, ")")
	if open <= 0 || close <= open {
		return "", "", nil, fmt.Errorf("invalid options")
	}
	network = netAndOpts[:open]
	optCSV := netAndOpts[open+1 : close]
	if optCSV != "" {
		options = strings.Split(optCSV, ",")
	}
	return path, network, options, nil
}

func validateOptions(options []string) ([]string, error) {
	if len(options) == 0 {
		return []string{"rw", "sync"}, nil
	}
	out := make([]string, 0, len(options))
	seen := map[string]bool{}
	for _, opt := range options {
		norm := strings.TrimSpace(opt)
		if !allowedOptions[norm] {
			return nil, fmt.Errorf("nfs.share.create: option %q is not allowed", opt)
		}
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	sort.Strings(out)
	return out, nil
}

func isValidNetwork(v string) bool {
	if v == "*" {
		return true
	}
	_, _, err := net.ParseCIDR(v)
	return err == nil
}

func isValidPath(v string) bool {
	return strings.HasPrefix(v, "/") && !strings.Contains(v, "..")
}

func isSafeID(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	for _, c := range v {
		if !(c == '-' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
