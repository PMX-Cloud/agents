// Package cve implements CVE DB update and package scan.
package cve

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pmx-cloud/agents/shared/envelope"
	_ "modernc.org/sqlite"
)

type UpdateParams struct {
	DBBase64   string `json:"db_base64"`
	SHA256     string `json:"sha256"`
	Signature  string `json:"signature"`
	DBPath     string `json:"db_path"`
	KeysetPath string `json:"-"`
}

type Finding struct {
	Package          string `json:"package"`
	InstalledVersion string `json:"installed_version"`
	CVEID            string `json:"cve_id"`
	Severity         string `json:"severity"`
	FixedVersion     string `json:"fixed_version,omitempty"`
}

type ScanResult struct {
	Findings []Finding `json:"findings"`
}

type Package struct {
	Name          string
	Version       string
	SourceVersion string
}

type PackageProvider interface {
	ListInstalled(ctx context.Context) ([]Package, error)
}

type DpkgProvider struct{}

func (p *DpkgProvider) ListInstalled(ctx context.Context) ([]Package, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "-W", "-f=${binary:Package}|${Version}|${source:Version}\\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("cve.scan dpkg-query failed: %w", err)
	}
	return parseDpkgPackages(string(out)), nil
}

func UpdateDB(params UpdateParams) error {
	if params.DBPath == "" {
		params.DBPath = "/var/lib/pmx-cloud/security/cve.db"
	}
	if params.DBBase64 == "" || params.SHA256 == "" || strings.TrimSpace(params.Signature) == "" {
		return fmt.Errorf("security.cvedb.update: db_base64, sha256, and signature are required")
	}

	decoded, err := base64.StdEncoding.DecodeString(params.DBBase64)
	if err != nil {
		return fmt.Errorf("security.cvedb.update: invalid base64 payload: %w", err)
	}
	hash := sha256.Sum256(decoded)
	actual := hex.EncodeToString(hash[:])
	if !strings.EqualFold(actual, strings.TrimSpace(params.SHA256)) {
		return fmt.Errorf("security.cvedb.update: signature mismatch")
	}
	if err := verifyDetachedSignature(decoded, params.Signature, params.KeysetPath); err != nil {
		return fmt.Errorf("security.cvedb.update: detached signature verify failed: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(params.DBPath), 0o755); err != nil {
		return fmt.Errorf("security.cvedb.update: mkdir: %w", err)
	}
	tmp := params.DBPath + ".tmp"
	if err := os.WriteFile(tmp, decoded, 0o644); err != nil {
		return fmt.Errorf("security.cvedb.update: write temp db: %w", err)
	}
	if err := validateSQLite(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("security.cvedb.update: invalid sqlite db: %w", err)
	}
	if err := os.Rename(tmp, params.DBPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("security.cvedb.update: install db: %w", err)
	}
	if err := os.Chmod(params.DBPath, 0o644); err != nil {
		return fmt.Errorf("security.cvedb.update: chmod db: %w", err)
	}
	return nil
}

func Scan(ctx context.Context, dbPath string, provider PackageProvider) (*ScanResult, error) {
	if dbPath == "" {
		dbPath = "/var/lib/pmx-cloud/security/cve.db"
	}
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CVE_DB_MISSING")
		}
		return nil, fmt.Errorf("cve.scan: stat db: %w", err)
	}
	if provider == nil {
		provider = &DpkgProvider{}
	}
	pkgs, err := provider.ListInstalled(ctx)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("cve.scan: open db: %w", err)
	}
	defer db.Close()

	query, err := resolveQuery(db)
	if err != nil {
		return nil, err
	}

	findings := make([]Finding, 0)
	for _, pkg := range pkgs {
		rows, err := db.QueryContext(ctx, query, pkg.Name)
		if err != nil {
			return nil, fmt.Errorf("cve.scan query %s: %w", pkg.Name, err)
		}
		for rows.Next() {
			var cveID, severity, fixed string
			if err := rows.Scan(&cveID, &severity, &fixed); err != nil {
				rows.Close()
				return nil, fmt.Errorf("cve.scan scan row: %w", err)
			}
			if affected(ctx, pkg.Version, fixed) {
				findings = append(findings, Finding{
					Package:          pkg.Name,
					InstalledVersion: pkg.Version,
					CVEID:            cveID,
					Severity:         severity,
					FixedVersion:     fixed,
				})
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cve.scan rows %s: %w", pkg.Name, err)
		}
		rows.Close()
	}

	return &ScanResult{Findings: findings}, nil
}

func parseDpkgPackages(raw string) []Package {
	out := []Package{}
	s := bufio.NewScanner(strings.NewReader(raw))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		source := ""
		if len(parts) > 2 {
			source = parts[2]
		}
		out = append(out, Package{Name: parts[0], Version: parts[1], SourceVersion: source})
	}
	return out
}

// ParseDpkgPackagesForTest exposes package parsing to unit tests.
func ParseDpkgPackagesForTest(raw string) []Package {
	return parseDpkgPackages(raw)
}

func validateSQLite(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	var one int
	if err := db.QueryRow("SELECT 1").Scan(&one); err != nil {
		return err
	}
	if one != 1 {
		return fmt.Errorf("sqlite probe failed")
	}
	return nil
}

func resolveQuery(db *sql.DB) (string, error) {
	// Preferred schema.
	q1 := "SELECT cve_id, severity, fixed_version FROM cves WHERE package = ?"
	if rows, err := db.Query(q1, "__probe__"); err == nil {
		_ = rows.Close()
		return q1, nil
	}
	// Legacy schema.
	q2 := "SELECT cve_id, severity, fixed_version FROM vulnerabilities WHERE package = ?"
	if rows, err := db.Query(q2, "__probe__"); err == nil {
		_ = rows.Close()
		return q2, nil
	}
	return "", fmt.Errorf("cve.scan: unsupported CVE DB schema")
}

func affected(ctx context.Context, installed, fixed string) bool {
	fixed = strings.TrimSpace(fixed)
	if fixed == "" {
		return true
	}
	// dpkg --compare-versions returns exit 0 when relation is true.
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg", "--compare-versions", installed, "lt", fixed)
	if err := cmd.Run(); err == nil {
		return true
	}
	// Fallback lexical compare when dpkg compare is unavailable.
	return installed < fixed
}

func verifyDetachedSignature(payload []byte, signature, keysetPath string) error {
	if strings.TrimSpace(keysetPath) == "" {
		return fmt.Errorf("keyset path is required")
	}
	ks, err := envelope.LoadKeySet(keysetPath)
	if err != nil {
		return fmt.Errorf("load keyset: %w", err)
	}
	sig, err := decodeDetachedSignature(signature)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length %d", len(sig))
	}
	if !ks.Verify(payload, sig) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func decodeDetachedSignature(v string) ([]byte, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return nil, fmt.Errorf("missing signature")
	}

	// Accept hex (preferred) and base64 to keep backend/client rollout flexible.
	if sig, err := hex.DecodeString(raw); err == nil {
		return sig, nil
	}
	if sig, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return sig, nil
	}
	if sig, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
		return sig, nil
	}
	return nil, fmt.Errorf("invalid signature encoding")
}
