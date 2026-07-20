// Package verify validates backup archive checksums and manifest visibility.
package verify

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pmx-cloud/agents/backup/internal/vzdump"
)

type Params struct {
	ArchivePath    string
	ExpectedSHA256 string
	TarBinary      string
}

type Result struct {
	SHA256        string   `json:"sha256"`
	SizeBytes     int64    `json:"size_bytes"`
	ManifestFiles []string `json:"manifest_files,omitempty"`
	ManifestError string   `json:"manifest_error,omitempty"`
}

func Run(ctx context.Context, p Params, stepFn func(string)) (*Result, error) {
	sha, size, err := vzdump.HashFileSHA256(p.ArchivePath, stepFn)
	if err != nil {
		return nil, err
	}
	if expected := strings.ToLower(strings.TrimSpace(p.ExpectedSHA256)); expected != "" {
		if strings.ToLower(sha) != expected {
			return nil, fmt.Errorf("verify: sha256 mismatch (expected=%s got=%s)", expected, sha)
		}
	}

	manifest, manifestErr := listManifest(ctx, p.TarBinary, p.ArchivePath)
	if manifestErr != nil {
		return nil, manifestErr
	}
	if !containsQemuServerConfig(manifest) {
		return nil, fmt.Errorf("verify: archive manifest missing qemu-server.conf (%s)", formatManifestPreview(manifest))
	}
	result := &Result{
		SHA256:    sha,
		SizeBytes: size,
	}
	if len(manifest) > 0 {
		result.ManifestFiles = manifest
	}
	return result, nil
}

func listManifest(ctx context.Context, tarBinary, archivePath string) ([]string, error) {
	_ = tarBinary
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("manifest parse: open %q: %w", archivePath, err)
	}
	defer file.Close()

	reader := tar.NewReader(file)
	manifest := make([]string, 0, 128)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("manifest parse: %w", err)
		}
		trimmed := strings.TrimSpace(header.Name)
		if trimmed == "" {
			continue
		}
		manifest = append(manifest, trimmed)
		if len(manifest) >= 1024 {
			break
		}
	}
	return manifest, nil
}

func containsQemuServerConfig(manifest []string) bool {
	for _, entry := range manifest {
		if strings.Contains(entry, "qemu-server.conf") {
			return true
		}
	}
	return false
}

func formatManifestPreview(manifest []string) string {
	if len(manifest) == 0 {
		return ""
	}
	preview := manifest
	if len(preview) > 5 {
		preview = preview[:5]
	}
	return strings.TrimSpace(bytes.NewBufferString(strings.Join(preview, ", ")).String())
}
