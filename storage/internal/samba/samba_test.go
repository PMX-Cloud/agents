package samba_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/pmx-cloud/agents/storage/internal/samba"
	"github.com/pmx-cloud/agents/storage/internal/storageexec"
)

func TestShareCreateUsesNetUsershare(t *testing.T) {
	m := &storageexec.MockExec{}
	err := samba.ShareCreate(context.Background(), m, samba.ShareParams{ID: "abc123", Path: t.TempDir(), Comment: "PMX share", ACL: "Everyone:F"})
	if err != nil {
		t.Fatalf("share create: %v", err)
	}
	if len(m.Calls) != 1 || m.Calls[0].Binary != "net" || m.Calls[0].Args[0] != "usershare" || m.Calls[0].Args[1] != "add" {
		t.Fatalf("expected net usershare add, got %v", m.Calls)
	}
	if got := m.Calls[0].Args[2]; got != "pmx-abc123" {
		t.Fatalf("expected PMX share prefix, got %q", got)
	}
}

func TestShareListFiltersNonPMXShares(t *testing.T) {
	m := &storageexec.MockExec{
		Results: map[string]*storageexec.Result{
			"net": {Stdout: []byte("pmx-alpha\nthirdparty\npmx-beta\n")},
		},
	}
	shares, err := samba.ShareList(context.Background(), m)
	if err != nil {
		t.Fatalf("share list: %v", err)
	}
	want := []string{"alpha", "beta"}
	if !reflect.DeepEqual(shares, want) {
		t.Fatalf("unexpected shares: got %v want %v", shares, want)
	}
}
