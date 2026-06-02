package spice

import "testing"

func TestParseProxyInfo_PortAndTicket(t *testing.T) {
	t.Parallel()

	info, err := parseProxyInfo("proxy port: 5901 ticket: PVEVNC:abc123")
	if err != nil {
		t.Fatalf("parseProxyInfo() error = %v", err)
	}
	if info.Port != 5901 {
		t.Fatalf("port = %d", info.Port)
	}
	if info.Ticket != "PVEVNC:abc123" {
		t.Fatalf("ticket = %q", info.Ticket)
	}
}

func TestParseProxyInfo_RejectsMissingPort(t *testing.T) {
	t.Parallel()

	if _, err := parseProxyInfo("no useful output"); err == nil {
		t.Fatal("expected parseProxyInfo to fail without port")
	}
}
