package iso_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/iso"
	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

func TestUpload_URLNotInAllowlist(t *testing.T) {
	m := &proxmox.MockExec{}
	err := iso.Upload(context.Background(), m, map[string]any{
		"storage":      "local",
		"url":          "https://evil.example.com/evil.iso",
		"allowed_urls": []any{"https://trusted.example.com/ubuntu.iso"},
	})
	if err == nil {
		t.Fatal("expected rejection for URL not in allowlist")
	}
	if len(m.Calls) != 0 {
		t.Fatal("pvesm must not be called for non-allowlisted URL")
	}
}

func TestUpload_EmptyAllowlist(t *testing.T) {
	m := &proxmox.MockExec{}
	err := iso.Upload(context.Background(), m, map[string]any{
		"storage": "local",
		"url":     "https://trusted.example.com/ubuntu.iso",
	})
	if err == nil {
		t.Fatal("expected error for missing allowed_urls")
	}
}

func TestUpload_AllowlistedURL(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
	err := iso.Upload(context.Background(), m, map[string]any{
		"storage":      "local",
		"url":          "https://trusted.example.com/ubuntu.iso",
		"allowed_urls": []any{"https://trusted.example.com/ubuntu.iso"},
	})
	if err != nil {
		t.Fatalf("allowlisted URL rejected: %v", err)
	}
	if m.LastCall().Binary != "pvesm" {
		t.Fatalf("expected pvesm call, got %q", m.LastCall().Binary)
	}
}
