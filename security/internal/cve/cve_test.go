package cve_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/pmx-cloud/agents/security/internal/cve"
	_ "modernc.org/sqlite"
)

func TestUpdateDBRejectsHashMismatch(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("not-a-sqlite")
	keysetPath, priv := writeDetachedVerifyKey(t)
	sig := ed25519.Sign(priv, payload)
	err := cve.UpdateDB(cve.UpdateParams{
		DBBase64:   base64.StdEncoding.EncodeToString(payload),
		SHA256:     "deadbeef",
		Signature:  hex.EncodeToString(sig),
		DBPath:     filepath.Join(dir, "cve.db"),
		KeysetPath: keysetPath,
	})
	if err == nil {
		t.Fatal("expected signature mismatch")
	}
}

type fakeProvider struct{}

func (p *fakeProvider) ListInstalled(ctx context.Context) ([]cve.Package, error) {
	return []cve.Package{{Name: "openssh", Version: "1.0"}}, nil
}

func TestScanMissingDB(t *testing.T) {
	_, err := cve.Scan(context.Background(), filepath.Join(t.TempDir(), "missing.db"), &fakeProvider{})
	if err == nil || err.Error() != "CVE_DB_MISSING" {
		t.Fatalf("expected CVE_DB_MISSING, got %v", err)
	}
}

func TestParseDpkgPackages(t *testing.T) {
	pkgs := cve.ParseDpkgPackagesForTest("a|1|1\nb|2|2\n")
	if len(pkgs) != 2 || pkgs[0].Name != "a" {
		t.Fatalf("unexpected parse result: %+v", pkgs)
	}
}

func TestUpdateDBWritesAndValidatesSQLite(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cve.db")
	keysetPath, priv := writeDetachedVerifyKey(t)
	// minimal sqlite header will still fail validation; ensure error path keeps no target.
	payload := []byte("SQLite format 3\x00")
	sum := sha256.Sum256(payload)
	sig := ed25519.Sign(priv, payload)
	err := cve.UpdateDB(cve.UpdateParams{
		DBBase64:   base64.StdEncoding.EncodeToString(payload),
		SHA256:     hex.EncodeToString(sum[:]),
		Signature:  hex.EncodeToString(sig),
		DBPath:     dbPath,
		KeysetPath: keysetPath,
	})
	if err == nil {
		t.Fatal("expected invalid sqlite db")
	}
	if _, statErr := os.Stat(dbPath); !os.IsNotExist(statErr) {
		t.Fatalf("db should not be installed on invalid payload, stat err: %v", statErr)
	}
}

func TestUpdateDBAcceptsValidDetachedSignature(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cve.db")
	payload := mustSQLitePayload(t)
	sum := sha256.Sum256(payload)

	keysetPath, priv := writeDetachedVerifyKey(t)
	sig := ed25519.Sign(priv, payload)

	err := cve.UpdateDB(cve.UpdateParams{
		DBBase64:   base64.StdEncoding.EncodeToString(payload),
		SHA256:     hex.EncodeToString(sum[:]),
		Signature:  hex.EncodeToString(sig),
		DBPath:     dbPath,
		KeysetPath: keysetPath,
	})
	if err != nil {
		t.Fatalf("update db with valid detached signature: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open installed db: %v", err)
	}
	defer db.Close()
	var one int
	if err := db.QueryRow("SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("installed db probe failed, one=%d err=%v", one, err)
	}
}

func TestUpdateDBRejectsDetachedSignatureAndKeepsOldDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cve.db")
	if err := os.WriteFile(dbPath, []byte("old-db"), 0o644); err != nil {
		t.Fatalf("write old db: %v", err)
	}

	payload := mustSQLitePayload(t)
	sum := sha256.Sum256(payload)
	keysetPath, _ := writeDetachedVerifyKey(t)

	err := cve.UpdateDB(cve.UpdateParams{
		DBBase64:   base64.StdEncoding.EncodeToString(payload),
		SHA256:     hex.EncodeToString(sum[:]),
		Signature:  "deadbeef",
		DBPath:     dbPath,
		KeysetPath: keysetPath,
	})
	if err == nil {
		t.Fatal("expected detached signature verification failure")
	}

	got, readErr := os.ReadFile(dbPath)
	if readErr != nil {
		t.Fatalf("read installed db: %v", readErr)
	}
	if string(got) != "old-db" {
		t.Fatalf("old db must be preserved on detached-signature failure, got %q", string(got))
	}
}

func writeDetachedVerifyKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keysetPath := filepath.Join(t.TempDir(), "keyset.pub")
	if err := os.WriteFile(keysetPath, []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatalf("write keyset: %v", err)
	}
	return keysetPath, priv
}

func mustSQLitePayload(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE cves (
		package TEXT,
		cve_id TEXT,
		severity TEXT,
		fixed_version TEXT
	)`); err != nil {
		_ = db.Close()
		t.Fatalf("create table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close sqlite: %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sqlite payload: %v", err)
	}
	return payload
}
