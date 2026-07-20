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

// typedStorageFixture includes the "type" field. TB-1 (dir) has the most space.
const typedStorageFixture = `[
  {"storage":"local","type":"dir","content":"rootdir,images","active":1,"enabled":1,"avail":6225895424},
  {"storage":"GB-250","type":"lvmthin","content":"rootdir,images","active":1,"enabled":1,"avail":221731853312},
  {"storage":"TB-1","type":"dir","content":"rootdir,images,vztmpl","active":1,"enabled":1,"avail":932459831296}
]`

func TestResolveStorage_PrefersBlockForRootdir(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte(typedStorageFixture)}}
	// TB-1 (dir) has the most space, but a CT rootfs on dir storage needs a loop
	// device (losetup) which fails under the agent; the block storage GB-250 wins.
	got := proxmox.ResolveStorage(context.Background(), m, "local-lvm", "rootdir")
	if got != "GB-250" {
		t.Fatalf("expected GB-250 (block) for rootdir over larger dir TB-1, got %q", got)
	}
}

func TestResolveStorage_ImagesStillUsesLargestIncludingDir(t *testing.T) {
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte(typedStorageFixture)}}
	// VM disks (images) work fine on dir storage (raw file, no loop) — largest wins.
	got := proxmox.ResolveStorage(context.Background(), m, "local-lvm", "images")
	if got != "TB-1" {
		t.Fatalf("expected TB-1 (largest) for images, got %q", got)
	}
}

// Mirrors the live host: enabled block storages report active=0 (pvestatd
// status quirk) while only dir storage is active. The resolver must still pick
// an enabled block (pct activates it on create), not the active dir (losetup).
func TestResolveStorage_RootdirPicksEnabledBlockEvenIfInactive(t *testing.T) {
	const inactiveBlocks = `[
	  {"storage":"GB-512","type":"lvm","content":"rootdir,images","active":0,"enabled":1,"avail":0},
	  {"storage":"GB-250","type":"lvmthin","content":"rootdir,images","active":0,"enabled":1,"avail":0},
	  {"storage":"GB-900","type":"lvm","content":"rootdir,images","active":0,"enabled":0,"avail":0},
	  {"storage":"TB-1","type":"dir","content":"rootdir,images","active":1,"enabled":1,"avail":931825115136}
	]`
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte(inactiveBlocks)}}
	got := proxmox.ResolveStorage(context.Background(), m, "local-lvm", "rootdir")
	if got != "GB-512" && got != "GB-250" {
		t.Fatalf("expected an enabled block storage for rootdir, got %q (must not be dir TB-1 or disabled GB-900)", got)
	}
}

func TestResolveStorage_RootdirFallsBackToDirWhenNoBlock(t *testing.T) {
	const dirOnly = `[
	  {"storage":"TB-1","type":"dir","content":"rootdir,images","active":1,"enabled":1,"avail":932459831296}
	]`
	m := &proxmox.MockExec{Result: &proxmox.ExecResult{Stdout: []byte(dirOnly)}}
	got := proxmox.ResolveStorage(context.Background(), m, "local-lvm", "rootdir")
	if got != "TB-1" {
		t.Fatalf("expected TB-1 dir fallback when no block storage, got %q", got)
	}
}
