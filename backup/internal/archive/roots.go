// Package archive enforces backup archive root allowlists.
package archive

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func EnsureWritableDirectory(target string, roots []string) (string, error) {
	resolved, err := ensureInsideAllowedRoots(target, roots)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("archive: stat %q: %w", resolved, err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("archive: %q is not a directory", resolved)
	}
	return resolved, nil
}

func EnsureExistingArchive(path string, roots []string) (string, error) {
	resolved, err := ensureInsideAllowedRoots(path, roots)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("archive: stat %q: %w", resolved, err)
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("archive: %q is not a regular file", resolved)
	}
	return resolved, nil
}

func EnsureInsideAllowedRoots(path string, roots []string) (string, error) {
	return ensureInsideAllowedRoots(path, roots)
}

func EnsurePathForCreate(path string, roots []string) (string, error) {
	return ensureInsideAllowedRootsForCreate(path, roots)
}

func DeleteArchiveWithSidecars(path string, roots []string) ([]string, error) {
	resolved, err := EnsureExistingArchive(path, roots)
	if err != nil {
		return nil, err
	}

	candidates := sidecarCandidates(resolved)
	deleted := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		inside, inErr := ensureInsideAllowedRootsForCreate(candidate, roots)
		if inErr != nil {
			return nil, inErr
		}
		err := os.Remove(inside)
		if err == nil {
			deleted = append(deleted, inside)
			continue
		}
		if os.IsNotExist(err) {
			continue
		}
		return nil, fmt.Errorf("archive: remove %q: %w", inside, err)
	}

	return deleted, nil
}

func sidecarCandidates(path string) []string {
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	return []string{
		path,
		path + ".notes",
		path + ".log",
		base + ".notes",
		base + ".log",
	}
}

func ensureInsideAllowedRoots(path string, roots []string) (string, error) {
	normalized := strings.TrimSpace(path)
	if normalized == "" {
		return "", fmt.Errorf("archive: path is required")
	}
	if !filepath.IsAbs(normalized) {
		return "", fmt.Errorf("archive: path must be absolute, got %q", path)
	}
	resolved := filepath.Clean(normalized)
	resolved, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", fmt.Errorf("archive: resolve %q: %w", path, err)
	}
	resolved = filepath.Clean(resolved)
	if _, ok := matchingAllowedRoot(resolved, roots); ok {
		return resolved, nil
	}
	return "", fmt.Errorf("archive: path %q is outside configured archive_roots", path)
}

func ensureInsideAllowedRootsForCreate(path string, roots []string) (string, error) {
	normalized := strings.TrimSpace(path)
	if normalized == "" {
		return "", fmt.Errorf("archive: path is required")
	}
	if !filepath.IsAbs(normalized) {
		return "", fmt.Errorf("archive: path must be absolute, got %q", path)
	}
	cleaned := filepath.Clean(normalized)
	resolved, err := resolveForCreate(cleaned)
	if err != nil {
		return "", err
	}
	if _, ok := matchingAllowedRoot(resolved, roots); ok {
		return cleaned, nil
	}
	return "", fmt.Errorf("archive: path %q is outside configured archive_roots", path)
}

func matchingAllowedRoot(resolved string, roots []string) (string, bool) {
	for _, root := range roots {
		r := filepath.Clean(strings.TrimSpace(root))
		if r == "" {
			continue
		}
		if evaluated, err := filepath.EvalSymlinks(r); err == nil {
			r = filepath.Clean(evaluated)
		}
		if isPathInsideRoot(r, resolved) {
			return r, true
		}
	}
	return "", false
}

func resolveForCreate(cleaned string) (string, error) {
	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		return filepath.Clean(resolved), nil
	}

	anchor := cleaned
	for {
		parent := filepath.Dir(anchor)
		if parent == anchor {
			break
		}
		anchor = parent
		if _, err := os.Stat(anchor); err == nil {
			break
		}
	}
	resolvedAnchor, err := filepath.EvalSymlinks(anchor)
	if err != nil {
		return "", fmt.Errorf("archive: resolve parent %q: %w", cleaned, err)
	}
	rel, err := filepath.Rel(anchor, cleaned)
	if err != nil {
		return "", fmt.Errorf("archive: resolve relative path %q: %w", cleaned, err)
	}
	return filepath.Clean(filepath.Join(resolvedAnchor, rel)), nil
}

func isPathInsideRoot(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == "" {
		return true
	}
	if strings.HasPrefix(rel, "..") {
		return false
	}
	return !filepath.IsAbs(rel)
}
