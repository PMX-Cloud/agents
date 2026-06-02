package preflight_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/shared/preflight"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func writeSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600)
	return certPath, keyPath
}

func writeExpiredCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "expired"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	certPath = filepath.Join(dir, "expired.crt")
	keyPath = filepath.Join(dir, "expired.key")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600)
	return certPath, keyPath
}

func writeKeyset(t *testing.T, dir string) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(dir, "keyset.pub")
	_ = os.WriteFile(path, []byte(hex.EncodeToString(pub)), 0o444)
	return path
}

func writeConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "agent.conf")
	_ = os.WriteFile(path, []byte("[backend]\nurl = \"wss://example.com\"\n"), 0o600)
	return path
}

// ── cert-readable PASS ────────────────────────────────────────────────────────

func TestCheckCertReadable_ExistingFiles(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)
	checks := preflight.StandardChecks("pmx-test", writeConfig(t, dir), certPath, keyPath, writeKeyset(t, dir), nil)
	var buf bytes.Buffer
	code := preflight.RunTo(&buf, checks)
	out := buf.String()
	if strings.Contains(out, "[FAIL] cert-readable") {
		t.Errorf("cert-readable must PASS for existing files, got:\n%s", out)
	}
	_ = code
}

// ── cert-valid PASS ───────────────────────────────────────────────────────────

func TestCheckCertValid_ValidCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)
	checks := preflight.StandardChecks("pmx-test", writeConfig(t, dir), certPath, keyPath, writeKeyset(t, dir), nil)
	var buf bytes.Buffer
	preflight.RunTo(&buf, checks)
	out := buf.String()
	if strings.Contains(out, "[FAIL] cert-valid") {
		t.Errorf("cert-valid must PASS for a valid cert, got:\n%s", out)
	}
}

// ── cert-valid FAIL on expired cert ──────────────────────────────────────────

func TestCheckCertValid_ExpiredCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeExpiredCert(t, dir)
	checks := preflight.StandardChecks("pmx-test", writeConfig(t, dir), certPath, keyPath, writeKeyset(t, dir), nil)
	var buf bytes.Buffer
	preflight.RunTo(&buf, checks)
	out := buf.String()
	if !strings.Contains(out, "[FAIL] cert-valid") {
		t.Errorf("cert-valid must FAIL for expired cert, got:\n%s", out)
	}
}

// ── keyset-readable PASS ──────────────────────────────────────────────────────

func TestCheckKeysetReadable_ValidKeyset(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)
	keysetPath := writeKeyset(t, dir)
	checks := preflight.StandardChecks("pmx-test", writeConfig(t, dir), certPath, keyPath, keysetPath, nil)
	var buf bytes.Buffer
	preflight.RunTo(&buf, checks)
	out := buf.String()
	if strings.Contains(out, "[FAIL] keyset-readable") {
		t.Errorf("keyset-readable must PASS for valid keyset, got:\n%s", out)
	}
}

// ── config-exists PASS ────────────────────────────────────────────────────────

func TestCheckConfigExists_ExistingConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := writeConfig(t, dir)
	certPath, keyPath := writeSelfSignedCert(t, dir)
	checks := preflight.StandardChecks("pmx-test", configPath, certPath, keyPath, writeKeyset(t, dir), nil)
	var buf bytes.Buffer
	preflight.RunTo(&buf, checks)
	out := buf.String()
	if strings.Contains(out, "[FAIL] config-exists") {
		t.Errorf("config-exists must PASS for existing file, got:\n%s", out)
	}
}
