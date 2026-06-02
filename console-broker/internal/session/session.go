// Package session validates the single console.open envelope payload.
package session

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	envpkg "github.com/pmx-cloud/agents/shared/envelope"
)

type OpenRequest struct {
	VMID            int
	DisplayProtocol string
	SessionToken    string
	ExpiresAt       time.Time
	BackendWSURL    string
	RateLimitMbps   int
	JobID           string
}

func FromEnvelope(env *envpkg.Envelope, defaultRateMbps int, allowedHostSuffixes []string) (*OpenRequest, error) {
	if env == nil {
		return nil, fmt.Errorf("session: envelope is required")
	}
	if env.Command != "console.open" {
		return nil, fmt.Errorf("UNSUPPORTED: %s", env.Command)
	}
	params := env.Params
	if params == nil {
		params = map[string]any{}
	}

	display := strings.ToLower(strings.TrimSpace(stringParam(params, "displayProtocol", "")))
	if display == "" {
		display = strings.ToLower(strings.TrimSpace(stringParam(params, "display_protocol", "")))
	}
	if display != "vnc" && display != "spice" && display != "serial" {
		return nil, fmt.Errorf("displayProtocol must be one of vnc|spice|serial")
	}

	vmid := intParam(params, "vmId", 0)
	if vmid <= 0 {
		vmid = intParam(params, "vmid", 0)
	}
	if vmid <= 0 {
		return nil, fmt.Errorf("vmId must be a positive integer")
	}

	token := firstNonEmpty(stringParam(params, "sessionToken", ""), stringParam(params, "session_token", ""))
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("sessionToken is required")
	}

	backendWSURL := firstNonEmpty(stringParam(params, "backendWsUrl", ""), stringParam(params, "backend_ws_url", ""))
	if strings.TrimSpace(backendWSURL) == "" {
		return nil, fmt.Errorf("backendWsUrl is required")
	}
	if err := validateBackendURL(backendWSURL, allowedHostSuffixes); err != nil {
		return nil, err
	}

	expiresAt := env.ExpiresAt
	if paramsExpires := firstNonEmpty(stringParam(params, "expiresAt", ""), stringParam(params, "expires_at", "")); paramsExpires != "" {
		t, err := time.Parse(time.RFC3339, paramsExpires)
		if err != nil {
			return nil, fmt.Errorf("expiresAt must be RFC3339: %w", err)
		}
		expiresAt = t.UTC()
	}
	if time.Now().After(expiresAt) {
		return nil, fmt.Errorf("session expired at %s", expiresAt.Format(time.RFC3339))
	}

	rate := intParam(params, "rateLimitMbps", 0)
	if rate <= 0 {
		rate = intParam(params, "rate_limit_mbps", defaultRateMbps)
	}
	if rate <= 0 {
		rate = defaultRateMbps
	}

	return &OpenRequest{
		VMID:            vmid,
		DisplayProtocol: display,
		SessionToken:    token,
		ExpiresAt:       expiresAt,
		BackendWSURL:    backendWSURL,
		RateLimitMbps:   rate,
		JobID:           env.JobID,
	}, nil
}

func validateBackendURL(rawURL string, allowedHostSuffixes []string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("backendWsUrl parse failed: %w", err)
	}
	if parsed.Scheme != "wss" {
		return fmt.Errorf("backendWsUrl must start with wss://")
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("backendWsUrl hostname is required")
	}
	if !backendConsolePathPattern.MatchString(parsed.EscapedPath()) || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("backendWsUrl must target /ws/agent/console/<session-id>")
	}
	if len(allowedHostSuffixes) == 0 {
		return fmt.Errorf("backendWsUrl allowed suffixes are required")
	}
	host := strings.ToLower(parsed.Hostname())
	for _, suffix := range allowedHostSuffixes {
		sfx := strings.ToLower(strings.TrimSpace(suffix))
		if sfx == "" {
			continue
		}
		if strings.HasPrefix(sfx, ".") {
			if strings.HasSuffix(host, sfx) || host == strings.TrimPrefix(sfx, ".") {
				return nil
			}
			continue
		}
		if host == sfx || strings.HasSuffix(host, "."+sfx) {
			return nil
		}
	}
	return fmt.Errorf("backendWsUrl host %q is not in allowed suffixes", host)
}

var backendConsolePathPattern = regexp.MustCompile(`^/ws/agent/console/[^/]+$`)

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func stringParam(params map[string]any, key, fallback string) string {
	v, ok := params[key]
	if !ok {
		return fallback
	}
	s, ok := v.(string)
	if !ok {
		return fallback
	}
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return strings.TrimSpace(s)
}

func intParam(params map[string]any, key string, fallback int) int {
	v, ok := params[key]
	if !ok {
		return fallback
	}
	switch typed := v.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return fallback
		}
		var n int
		if _, err := fmt.Sscanf(trimmed, "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}
