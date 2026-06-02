// Package cluster implements pve.cluster.* commands.
package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

// fingerprintRe matches a valid pvecm fingerprint: colon-separated hex pairs.
var fingerprintRe = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$`)

// Join adds this node to a cluster.
func Join(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	leaderIP := proxmox.StringParam(params, "leader_ip", "")
	if leaderIP == "" {
		return fmt.Errorf("pve.cluster.join: leader_ip is required")
	}
	fingerprint := proxmox.StringParam(params, "fingerprint", "")
	if !fingerprintRe.MatchString(fingerprint) {
		return fmt.Errorf("FINGERPRINT_MISMATCH: fingerprint %q has invalid format", fingerprint)
	}
	// Validate IP contains no injection.
	if strings.ContainsAny(leaderIP, "; \t\n\r`$") {
		return fmt.Errorf("pve.cluster.join: leader_ip contains unsafe characters")
	}

	if _, err := px.Pvecm(ctx, "add", leaderIP, "--fingerprint", fingerprint); err != nil {
		return fmt.Errorf("pve.cluster.join: %w", err)
	}
	return nil
}

// Status returns the parsed cluster status as a JSON-serialisable map.
func Status(ctx context.Context, px proxmox.ExecIface) (json.RawMessage, error) {
	result, err := px.Pvecm(ctx, "status", "--output-format", "json")
	if err != nil {
		return nil, fmt.Errorf("pve.cluster.status: %w", err)
	}
	return json.RawMessage(result.Stdout), nil
}

// Leave removes a node from the cluster. Refuses if this node is the last quorum-holder.
func Leave(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	nodeName, err := proxmox.RequiredSafeToken(params, "node")
	if err != nil {
		return err
	}

	// Parse quorum status to prevent leaving if we are the only quorum node.
	statusResult, err := px.Pvecm(ctx, "status")
	if err != nil {
		return fmt.Errorf("pve.cluster.leave: cannot read cluster status: %w", err)
	}
	statusStr := statusResult.StdoutString()
	if isOnlyQuorumNode(statusStr) {
		return fmt.Errorf("pve.cluster.leave: this node is the only quorum-holder; cannot leave safely")
	}

	if _, err := px.Pvecm(ctx, "delnode", nodeName); err != nil {
		return fmt.Errorf("pve.cluster.leave: %w", err)
	}
	return nil
}

// isOnlyQuorumNode parses pvecm status output to determine if we are the only quorum node.
func isOnlyQuorumNode(output string) bool {
	// Look for "Quorum information: Quorate: Yes" with "Nodes: 1".
	quorate := false
	singleNode := false
	for _, line := range strings.Split(output, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "Nodes:") && strings.Contains(l, "1") {
			singleNode = true
		}
		if strings.HasPrefix(l, "Quorate:") && strings.Contains(l, "Yes") {
			quorate = true
		}
	}
	return quorate && singleNode
}
