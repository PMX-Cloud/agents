/*
Package proxmox provides the audited subprocess interface for pmx-hypervisor.

safe.go — Argument sanitisation helpers extracted from agent/commands/dispatcher.go
and upgraded: no bash -c, exec only, arguments as separate elements.
*/
package proxmox

import (
	"fmt"
	"strings"
)

// IsSafeToken returns true if value contains only alphanumeric, '.', '-', '_', '/'.
// No whitespace, no shell metacharacters.
func IsSafeToken(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if !(c == '.' || c == '_' || c == '-' || c == '/' || isAlphaNum(c)) {
			return false
		}
	}
	return true
}

// IsSafeVolume returns true if value is a valid Proxmox volume name.
// Proxmox volumes look like "local-lvm:vm-100-disk-0"; colons separate storage from volume.
func IsSafeVolume(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if !(c == '.' || c == '_' || c == '-' || c == '/' || c == ':' || isAlphaNum(c)) {
			return false
		}
	}
	return true
}

// RequiredSafeVolume extracts a required Proxmox volume name parameter.
func RequiredSafeVolume(params map[string]any, key string) (string, error) {
	value := StringParam(params, key, "")
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	if !IsSafeVolume(value) {
		return "", fmt.Errorf("%s contains unsafe characters: %q", key, value)
	}
	return value, nil
}

// IsJobID returns true if value is a valid job ID: alphanumeric, '-', '_' only.
// Intentionally excludes '.' and '/' to prevent path traversal when a job ID is
// embedded in a file path (e.g. snippet filenames in provisioning.apply).
func IsJobID(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if !(c == '-' || c == '_' || isAlphaNum(c)) {
			return false
		}
	}
	return true
}

// RequiredSafeToken extracts a required string param that must be a safe token.
func RequiredSafeToken(params map[string]any, key string) (string, error) {
	value := StringParam(params, key, "")
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	if !IsSafeToken(value) {
		return "", fmt.Errorf("%s contains unsafe characters: %q", key, value)
	}
	return value, nil
}

// RequiredSafeTokenAny extracts the first non-empty safe token from any of the given keys.
func RequiredSafeTokenAny(params map[string]any, keys ...string) (string, error) {
	for _, key := range keys {
		value := StringParam(params, key, "")
		if value == "" {
			continue
		}
		if !IsSafeToken(value) {
			return "", fmt.Errorf("%s contains unsafe characters: %q", key, value)
		}
		return value, nil
	}
	return "", fmt.Errorf("%s is required", strings.Join(keys, " or "))
}

// RequiredVMID validates a VMID (numeric, 100–999999999).
func RequiredVMID(params map[string]any, key string) (string, error) {
	value := StringParam(params, key, "")
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	if !isNumericVMID(value) {
		return "", fmt.Errorf("%s must be a numeric VMID (100-999999999): %q", key, value)
	}
	return value, nil
}

// RequiredPCIID validates a PCI ID (hex octets with : . _ - /).
func RequiredPCIID(params map[string]any, key string) (string, error) {
	value := StringParam(params, key, "")
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	for _, c := range value {
		if !(c == ':' || c == '.' || c == '_' || c == '-' || c == '/' || isAlphaNum(c)) {
			return "", fmt.Errorf("%s contains unsafe characters: %q", key, value)
		}
	}
	return value, nil
}

// RequiredAbsolutePath validates a non-traversing absolute path.
func RequiredAbsolutePath(params map[string]any, key string) (string, error) {
	value := StringParam(params, key, "")
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return ValidateAbsolutePath(value, key)
}

// ValidateAbsolutePath validates value as a non-traversing absolute path.
func ValidateAbsolutePath(value, key string) (string, error) {
	if !strings.HasPrefix(value, "/") || strings.Contains(value, "..") ||
		strings.ContainsAny(value, "\n\r\x00") {
		return "", fmt.Errorf("%s must be an absolute path without traversal: %q", key, value)
	}
	return value, nil
}

// RequiredDevicePath validates a /dev/ path.
func RequiredDevicePath(params map[string]any, key string) (string, error) {
	value := StringParam(params, key, "")
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	if !strings.HasPrefix(value, "/dev/") || strings.Contains(value, "..") {
		return "", fmt.Errorf("%s must be an absolute /dev path: %q", key, value)
	}
	return value, nil
}

// StringParam extracts a string param with a fallback.
func StringParam(params map[string]any, key string, fallback string) string {
	v, ok := params[key]
	if !ok {
		return fallback
	}
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return fallback
	}
	return strings.TrimSpace(s)
}

// BoolParam extracts a bool param. Accepts bool, "true"/"1"/"yes".
func BoolParam(params map[string]any, key string) bool {
	v, ok := params[key]
	if !ok {
		return false
	}
	switch typed := v.(type) {
	case bool:
		return typed
	case string:
		return typed == "true" || typed == "1" || typed == "yes"
	}
	return false
}

// IntParam extracts an int param with a fallback.
func IntParam(params map[string]any, key string, fallback int) int {
	v, ok := params[key]
	if !ok {
		return fallback
	}
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	}
	return fallback
}

// OneOf returns true if value is one of the candidates.
func OneOf(value string, candidates ...string) bool {
	for _, c := range candidates {
		if value == c {
			return true
		}
	}
	return false
}

func isAlphaNum(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isNumericVMID(s string) bool {
	if len(s) == 0 || len(s) > 9 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	// VMID must be >= 100.
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n >= 100
}
