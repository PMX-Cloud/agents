package hardening

import (
	"context"
	"fmt"

	"github.com/pmx-cloud/agents/security/internal/rootscope"
)

func RPCBindDisable(ctx context.Context, jobID string, rr RootRunner) error {
	if rr == nil {
		rr = &DefaultRootRunner{}
	}
	if jobID == "" {
		jobID = "local"
	}
	_, err := rr.RunRoot(ctx, jobID, "rpcbind-disable", "/bin/systemctl", []string{"disable", "--now", "rpcbind.socket", "rpcbind.service"}, rootscope.Hardening{ReadWritePaths: []string{"/etc/systemd", "/run/systemd"}, AppArmorProfile: "pmx-security-disable-rpcbind"})
	if err != nil {
		return fmt.Errorf("rpcbind.disable: %w", err)
	}
	checks := [][]string{
		{"is-enabled", "rpcbind.service"},
		{"is-enabled", "rpcbind.socket"},
		{"is-active", "rpcbind.service"},
		{"is-active", "rpcbind.socket"},
	}
	for _, args := range checks {
		_, err = rr.RunRoot(ctx, jobID, "rpcbind-verify", "/bin/systemctl", args, rootscope.Hardening{ReadWritePaths: []string{"/run/systemd"}, AppArmorProfile: "pmx-security-disable-rpcbind"})
		if err == nil {
			return fmt.Errorf("rpcbind.disable: verification failed, %s %s still reports success", args[1], args[0])
		}
	}
	return nil
}
