/*
Package enroll implements the one-shot enrollment flow (architecture §6.1).

Flow:
 1. Generate fresh Ed25519 keypair locally.
 2. Build X.509 CSR with CommonName = host_fingerprint.
 3. POST { csr, token, capability } to <backend>/agents/enroll (HTTPS, not WS).
 4. Backend validates token, signs CSR, returns cert.
 5. Atomic-write cert + key to /etc/pmx-cloud/pmx-core/ (mode 0400).

Invariants:
  - Token is never stored to disk. Consumed once and discarded.
  - On any failure: print clear error, exit non-zero, do NOT overwrite existing cert.
  - On success: cert and key are mode 0400, owned by the calling user.
*/
package enroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/pmx-cloud/agents/core/internal/capability"
)

// Config holds everything needed to perform enrollment.
type Config struct {
	// EnrollURL is the HTTPS endpoint, e.g. https://api.pmxcloud.example/agents/enroll
	EnrollURL string

	// CertDir is where the cert and key are written (e.g. /etc/pmx-cloud/pmx-core/).
	CertDir string

	// Token is the one-time enrollment token. Never stored.
	Token string
}

// enrollRequest is the JSON body POSTed to the enroll endpoint.
type enrollRequest struct {
	CSR        string      `json:"csr"`
	Token      string      `json:"token"`
	Capability interface{} `json:"capability"`
}

// enrollResponse is the JSON body returned by the enroll endpoint.
type enrollResponse struct {
	Certificate string `json:"certificate"` // PEM-encoded cert chain
	Error       string `json:"error,omitempty"`
}

// Run executes the enrollment flow.
func Run(ctx context.Context, cfg *Config) error {
	if cfg.Token == "" {
		return fmt.Errorf("enroll: token is required")
	}
	if cfg.EnrollURL == "" {
		return fmt.Errorf("enroll: enroll URL is required")
	}

	certPath := filepath.Join(cfg.CertDir, "client.crt")
	keyPath := filepath.Join(cfg.CertDir, "client.key")

	// Do not overwrite existing cert unless explicitly requested.
	if _, err := os.Stat(certPath); err == nil {
		return fmt.Errorf("enroll: cert already exists at %s; use --force to re-enroll", certPath)
	}

	// 1. Generate Ed25519 keypair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("enroll: generate keypair: %w", err)
	}

	// 2. Get host fingerprint for the CSR CommonName.
	hostInfo := capability.Collect(ctx)
	fingerprint := hostInfo.HostFingerprint

	// 3. Build the CSR.
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: fingerprint,
		},
		PublicKey: pub,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return fmt.Errorf("enroll: create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// 4. POST to the enroll endpoint.
	reqBody, err := json.Marshal(enrollRequest{
		CSR:        string(csrPEM),
		Token:      cfg.Token,
		Capability: hostInfo,
	})
	if err != nil {
		return fmt.Errorf("enroll: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EnrollURL, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("enroll: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("enroll: POST %s: %w", cfg.EnrollURL, err)
	}
	defer resp.Body.Close()

	var enrollResp enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return fmt.Errorf("enroll: decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := enrollResp.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("enroll: backend error: %s", msg)
	}

	if enrollResp.Certificate == "" {
		return fmt.Errorf("enroll: backend returned empty certificate")
	}

	// 5. Atomic-write cert and key.
	if err := os.MkdirAll(cfg.CertDir, 0o750); err != nil {
		return fmt.Errorf("enroll: mkdir %s: %w", cfg.CertDir, err)
	}

	if err := atomicWrite(certPath, []byte(enrollResp.Certificate), 0o400); err != nil {
		return fmt.Errorf("enroll: write cert: %w", err)
	}

	// Encode private key as PKCS8 PEM.
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("enroll: marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	if err := atomicWrite(keyPath, keyPEM, 0o400); err != nil {
		// Roll back the cert if key write fails.
		_ = os.Remove(certPath)
		return fmt.Errorf("enroll: write key: %w", err)
	}

	return nil
}

// atomicWrite writes data to path atomically (temp file + rename) with the
// given mode. The temp file is in the same directory so rename is atomic on
// a single filesystem.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".enroll-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()

	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName) // no-op if rename succeeded
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
