// Package cert implements cert.audit for file and endpoint TLS certificates.
package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type AuditParams struct {
	Paths          []string `json:"paths"`
	Endpoints      []string `json:"endpoints"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	ExpiringDays   int      `json:"expiring_days"`
}

type CertFinding struct {
	Source        string   `json:"source"`
	CommonName    string   `json:"common_name,omitempty"`
	SANs          []string `json:"sans,omitempty"`
	NotBefore     string   `json:"not_before,omitempty"`
	NotAfter      string   `json:"not_after,omitempty"`
	DaysRemaining int      `json:"days_remaining,omitempty"`
	ExpiringSoon  bool     `json:"expiring_soon"`
	Error         string   `json:"error,omitempty"`
}

type AuditResult struct {
	Findings []CertFinding `json:"findings"`
}

func Audit(ctx context.Context, params AuditParams) (*AuditResult, error) {
	if params.TimeoutSeconds <= 0 {
		params.TimeoutSeconds = 5
	}
	if params.ExpiringDays <= 0 {
		params.ExpiringDays = 30
	}

	res := &AuditResult{Findings: []CertFinding{}}
	for _, p := range params.Paths {
		findings := auditPath(p, params.ExpiringDays)
		res.Findings = append(res.Findings, findings...)
	}
	for _, e := range params.Endpoints {
		res.Findings = append(res.Findings, auditEndpoint(ctx, e, params.TimeoutSeconds, params.ExpiringDays))
	}
	return res, nil
}

func auditPath(path string, expiringDays int) []CertFinding {
	data, err := os.ReadFile(path)
	if err != nil {
		return []CertFinding{{Source: path, Error: err.Error()}}
	}
	findings := []CertFinding{}
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			findings = append(findings, CertFinding{Source: path, Error: err.Error()})
			continue
		}
		findings = append(findings, buildFinding(path, cert, expiringDays))
	}
	if len(findings) == 0 {
		findings = append(findings, CertFinding{Source: path, Error: "no certificate PEM blocks found"})
	}
	return findings
}

func auditEndpoint(ctx context.Context, endpoint string, timeoutSec int, expiringDays int) CertFinding {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return CertFinding{Source: endpoint, Error: fmt.Sprintf("invalid endpoint: %v", err)}
	}
	if port == "" {
		return CertFinding{Source: endpoint, Error: "missing port"}
	}

	dialer := &net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}
	// Audit mode needs certificate metadata even for private/self-signed endpoints.
	conn, err := tls.DialWithDialer(dialer, "tcp", endpoint, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true})
	if err != nil {
		return CertFinding{Source: endpoint, Error: err.Error()}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return CertFinding{Source: endpoint, Error: "no peer certificate"}
	}
	return buildFinding(endpoint, state.PeerCertificates[0], expiringDays)
}

func buildFinding(source string, cert *x509.Certificate, expiringDays int) CertFinding {
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	sans := append([]string{}, cert.DNSNames...)
	sans = append(sans, cert.EmailAddresses...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	return CertFinding{
		Source:        source,
		CommonName:    cert.Subject.CommonName,
		SANs:          sans,
		NotBefore:     cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      cert.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining: days,
		ExpiringSoon:  days < expiringDays,
	}
}

func EndpointFromHostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", host, port)
}
