// Package spice connects to Proxmox SPICE/VNC proxy endpoints for one session.
package spice

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type ProxyInfo struct {
	Port   int
	Ticket string
}

var (
	portPattern1   = regexp.MustCompile(`(?i)port\s*[:=]\s*([0-9]{2,5})`)
	portPattern2   = regexp.MustCompile(`:(\d{2,5})`)
	ticketPattern1 = regexp.MustCompile(`(?i)ticket\s*[:=]\s*['"]?([^'"\s]+)`) //nolint:lll
	ticketPattern2 = regexp.MustCompile(`(?i)password\s*[:=]\s*['"]?([^'"\s]+)`)
)

func Open(ctx context.Context, qmBinary string, vmid int, stepFn func(string)) (net.Conn, error) {
	if strings.TrimSpace(qmBinary) == "" {
		qmBinary = "/usr/sbin/qm"
	}
	attempts := [][]string{
		{"spiceproxy", strconv.Itoa(vmid)},
		{"vncproxy", strconv.Itoa(vmid)},
	}

	var lastErr error
	for _, args := range attempts {
		if stepFn != nil {
			stepFn("spice: qm " + strings.Join(args, " "))
		}
		info, err := runProxyCommand(ctx, qmBinary, args...)
		if err != nil {
			lastErr = err
			continue
		}
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Port))
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = fmt.Errorf("dial spice proxy %s: %w", addr, err)
			continue
		}
		if info.Ticket != "" {
			if _, err := conn.Write([]byte(info.Ticket + "\n")); err != nil {
				_ = conn.Close()
				lastErr = fmt.Errorf("write spice ticket: %w", err)
				continue
			}
		}
		return conn, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no proxy command succeeded")
	}
	return nil, fmt.Errorf("INTERFACE_UNAVAILABLE: spice for vmid %d: %w", vmid, lastErr)
}

func runProxyCommand(ctx context.Context, qmBinary string, args ...string) (*ProxyInfo, error) {
	cmd := exec.CommandContext(ctx, qmBinary, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("qm %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	info, parseErr := parseProxyInfo(string(out))
	if parseErr != nil {
		return nil, fmt.Errorf("parse proxy output: %w (output=%q)", parseErr, strings.TrimSpace(string(out)))
	}
	return info, nil
}

func parseProxyInfo(output string) (*ProxyInfo, error) {
	text := strings.TrimSpace(output)
	if text == "" {
		return nil, fmt.Errorf("empty proxy output")
	}
	port, err := extractPort(text)
	if err != nil {
		return nil, err
	}
	ticket := extractTicket(text)
	return &ProxyInfo{Port: port, Ticket: ticket}, nil
}

func extractPort(text string) (int, error) {
	for _, re := range []*regexp.Regexp{portPattern1, portPattern2} {
		if m := re.FindStringSubmatch(text); len(m) == 2 {
			port, err := strconv.Atoi(m[1])
			if err == nil && port > 0 && port <= 65535 {
				return port, nil
			}
		}
	}
	return 0, fmt.Errorf("no valid proxy port found")
}

func extractTicket(text string) string {
	for _, re := range []*regexp.Regexp{ticketPattern1, ticketPattern2} {
		if m := re.FindStringSubmatch(text); len(m) == 2 {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}
