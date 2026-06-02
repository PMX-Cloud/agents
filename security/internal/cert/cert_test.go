package cert_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/security/internal/cert"
)

func TestAuditBadPathReturnsFindingError(t *testing.T) {
	res, err := cert.Audit(context.Background(), cert.AuditParams{Paths: []string{"/no/such/cert.pem"}})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Error == "" {
		t.Fatalf("expected path error finding, got %+v", res.Findings)
	}
}

func TestEndpointFromHostPortIPv6(t *testing.T) {
	v := cert.EndpointFromHostPort("2001:db8::1", 443)
	if v != "[2001:db8::1]:443" {
		t.Fatalf("unexpected endpoint: %s", v)
	}
}

func TestAuditEndpointReportsSelfSignedExpiringCertificate(t *testing.T) {
	endpoint, closeFn := startSelfSignedTLSServer(t, time.Now().Add(24*time.Hour))
	defer closeFn()

	res, err := cert.Audit(context.Background(), cert.AuditParams{Endpoints: []string{endpoint}, ExpiringDays: 30})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected one finding, got %+v", res.Findings)
	}
	finding := res.Findings[0]
	if finding.Error != "" {
		t.Fatalf("expected parsed self-signed cert, got error %q", finding.Error)
	}
	if !finding.ExpiringSoon {
		t.Fatalf("expected expiring soon finding, got %+v", finding)
	}
	if finding.CommonName != "self-signed.test" {
		t.Fatalf("unexpected common name: %+v", finding)
	}
}

func startSelfSignedTLSServer(t *testing.T, notAfter time.Time) (string, func()) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "self-signed.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"self-signed.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			_ = conn.Close()
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}
