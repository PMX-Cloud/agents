package cluster_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/cluster"
	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

const validFingerprint = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"

func TestJoin_BadFingerprint(t *testing.T) {
	m := &proxmox.MockExec{}
	err := cluster.Join(context.Background(), m, map[string]any{
		"leader_ip":   "192.168.1.1",
		"fingerprint": "bad-format",
	})
	if err == nil {
		t.Fatal("expected FINGERPRINT_MISMATCH error")
	}
	if len(m.Calls) != 0 {
		t.Fatal("pvecm must not be called for bad fingerprint")
	}
}

func TestJoin_InjectedIP(t *testing.T) {
	m := &proxmox.MockExec{}
	err := cluster.Join(context.Background(), m, map[string]any{
		"leader_ip":   "192.168.1.1; rm -rf /",
		"fingerprint": validFingerprint,
	})
	if err == nil {
		t.Fatal("expected error for injected IP")
	}
	if len(m.Calls) != 0 {
		t.Fatal("pvecm must not be called for unsafe IP")
	}
}

func TestLeave_QuorumCritical(t *testing.T) {
	m := &proxmox.MockExec{
		Result: &proxmox.ExecResult{
			Stdout:   []byte("Quorate: Yes\nNodes: 1"),
			ExitCode: 0,
		},
	}
	err := cluster.Leave(context.Background(), m, map[string]any{"node": "pve1"})
	if err == nil {
		t.Fatal("expected error when leaving as only quorum holder")
	}
}

func TestLeave_UnsafeNodeName(t *testing.T) {
	m := &proxmox.MockExec{}
	err := cluster.Leave(context.Background(), m, map[string]any{"node": `; rm -rf /`})
	if err == nil {
		t.Fatal("expected error for unsafe node name")
	}
}
