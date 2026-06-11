package proxmox_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

const storageListFixture = `[
  {"storage":"local","content":"iso,vztmpl,backup,rootdir,images","active":1,"enabled":1,"avail":6225895424},
  {"storage":"GB-250","content":"rootdir,images","active":1,"enabled":1,"avail":221731853312},
  {"storage":"GB-512","content":"rootdir,images","active":1,"enabled":1,"avail":500103643136},
  {"storage":"QNAP_BACKUP","content":"backup","active":0,"enabled":1,"avail":0},
  {"storage":"TB-1","content":"backup,iso","active":1,"enabled":1,"avail":932459831296}
]`

func TestResolveStorage_KeepsRequestedWhenUsable(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte(storageListFixture)}}
	got := proxmox.ResolveStorage(context.Background(), m, "GB-250", "images")
	if got != "GB-250" {
		t.Fatalf("expected requested storage kept, got %q", got)
	}
}

func TestResolveStorage_SubstitutesLargestActive(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte(storageListFixture)}}
	got := proxmox.ResolveStorage(context.Background(), m, "local-lvm", "images")
	if got != "GB-512" {
		t.Fatalf("expected GB-512 (largest active images storage), got %q", got)
	}
}

func TestResolveStorage_RespectsContentType(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte(storageListFixture)}}
	// TB-1 has the most space but no rootdir content; GB-512 wins for rootdir.
	got := proxmox.ResolveStorage(context.Background(), m, "local-lvm", "rootdir")
	if got != "GB-512" {
		t.Fatalf("expected GB-512 for rootdir, got %q", got)
	}
}

func TestResolveStorage_FallsBackToRequestedOnBadOutput(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte("nonsense")}}
	got := proxmox.ResolveStorage(context.Background(), m, "local-lvm", "images")
	if got != "local-lvm" {
		t.Fatalf("expected requested storage on parse failure, got %q", got)
	}
}
