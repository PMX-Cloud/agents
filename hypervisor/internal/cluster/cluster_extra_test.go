package cluster_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/cluster"
	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

func successExec() *proxmox.MockExec {
	return &proxmox.MockExec{Result: &proxmox.ExecResult{ExitCode: 0}}
}

func failExec() *proxmox.MockExec {
	return &proxmox.MockExec{
		Result: &proxmox.ExecResult{ExitCode: 1},
		Err:    fmt.Errorf("exit status 1"),
	}
}

func TestJoin_Valid(t *testing.T) {
	m := successExec()
	err := cluster.Join(context.Background(), m, map[string]any{
		"leader_ip":   "192.168.1.1",
		"fingerprint": validFingerprint,
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
}

func TestJoin_PvecmError(t *testing.T) {
	err := cluster.Join(context.Background(), failExec(), map[string]any{
		"leader_ip":   "192.168.1.1",
		"fingerprint": validFingerprint,
	})
	if err == nil {
		t.Fatal("expected error from pvecm add failure")
	}
}

func TestJoin_MissingLeaderIP(t *testing.T) {
	m := &proxmox.MockExec{}
	err := cluster.Join(context.Background(), m, map[string]any{
		"fingerprint": validFingerprint,
	})
	if err == nil {
		t.Fatal("expected error for missing leader_ip")
	}
}

func TestLeave_MissingNodeName(t *testing.T) {
	m := successExec()
	err := cluster.Leave(context.Background(), m, map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing node name")
	}
}

func TestLeave_NoQuorum(t *testing.T) {
	// When pvecm status shows Quorate: No, it's safe to leave.
	m := &proxmox.MockExec{
		Result: &proxmox.ExecResult{
			Stdout:   []byte("Quorate: No\nNodes: 2"),
			ExitCode: 0,
		},
	}
	err := cluster.Leave(context.Background(), m, map[string]any{"node": "pve2"})
	if err != nil {
		t.Fatalf("Leave non-critical node: %v", err)
	}
}

func TestStatus_Valid(t *testing.T) {
	m := successExec()
	_, err := cluster.Status(context.Background(), m)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
}

func TestStatus_PvecmError(t *testing.T) {
	_, err := cluster.Status(context.Background(), failExec())
	if err == nil {
		t.Fatal("expected error from pvecm status failure")
	}
}
