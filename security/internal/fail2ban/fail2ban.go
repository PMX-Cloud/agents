// Package fail2ban manages the host Fail2Ban service through short-lived,
// audited root scopes. The long-running pmx-security process remains non-root.
package fail2ban

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/pmx-cloud/agents/security/internal/rootscope"
)

const (
	systemctlPath = "/usr/bin/systemctl"
	clientPath    = "/usr/bin/fail2ban-client"
)

var scopeHardening = rootscope.Hardening{
	ReadWritePaths: []string{
		"/etc/fail2ban",
		"/run/fail2ban",
		"/run/systemd",
		"/var/lib/fail2ban",
		"/var/run/fail2ban",
	},
	AppArmorProfile: "pmx-security-fail2ban",
}

type RootRunner interface {
	RunRoot(ctx context.Context, jobID, name, command string, args []string, hardening rootscope.Hardening) (*rootscope.Result, error)
}

type defaultRootRunner struct{}

func (r *defaultRootRunner) RunRoot(ctx context.Context, jobID, name, command string, args []string, hardening rootscope.Hardening) (*rootscope.Result, error) {
	return rootscope.RunRoot(ctx, jobID, name, command, args, hardening, nil)
}

type JailStatus struct {
	Banned    int      `json:"banned"`
	Total     int      `json:"total"`
	BannedIPs []string `json:"bannedIps"`
}

type StatusResult struct {
	Installed bool                  `json:"installed"`
	Running   bool                  `json:"running"`
	Jails     map[string]JailStatus `json:"jails"`
}

type BannedIP struct {
	Jail string `json:"jail"`
	IP   string `json:"ip"`
}

type BannedResult struct {
	Total     int        `json:"total"`
	BannedIPs []BannedIP `json:"bannedIps"`
}

type UnbanParams struct {
	Jail string `json:"jail"`
	IP   string `json:"ip"`
}

func Install(ctx context.Context, jobID string, runner RootRunner) (*StatusResult, error) {
	runner = withDefaultRunner(runner)
	result, err := runner.RunRoot(
		ctx,
		jobID,
		"fail2ban-install",
		systemctlPath,
		[]string{"start", "fail2ban.service"},
		scopeHardening,
	)
	if err != nil || result == nil || result.ExitCode != 0 {
		return nil, commandError("start fail2ban", result, err)
	}
	return Status(ctx, jobID, runner)
}

func Status(ctx context.Context, jobID string, runner RootRunner) (*StatusResult, error) {
	runner = withDefaultRunner(runner)
	status := &StatusResult{
		Jails: map[string]JailStatus{
			"proxmox": emptyJailStatus(),
			"ssh":     emptyJailStatus(),
		},
	}

	loaded, err := runner.RunRoot(
		ctx,
		jobID,
		"fail2ban-loaded",
		systemctlPath,
		[]string{"show", "fail2ban.service", "--property=LoadState", "--value"},
		scopeHardening,
	)
	if err != nil || loaded == nil || loaded.ExitCode != 0 {
		return nil, commandError("read fail2ban load state", loaded, err)
	}
	status.Installed = strings.TrimSpace(string(loaded.Stdout)) == "loaded"
	if !status.Installed {
		return status, nil
	}

	active, err := runner.RunRoot(
		ctx,
		jobID,
		"fail2ban-active",
		systemctlPath,
		[]string{"is-active", "--quiet", "fail2ban.service"},
		scopeHardening,
	)
	status.Running = err == nil && active != nil && active.ExitCode == 0
	if !status.Running {
		return status, nil
	}

	for apiName, hostName := range map[string]string{"proxmox": "proxmox", "ssh": "sshd"} {
		result, runErr := runner.RunRoot(
			ctx,
			jobID,
			"fail2ban-jail-"+apiName,
			clientPath,
			[]string{"status", hostName},
			scopeHardening,
		)
		// A host may not configure both optional jails. Preserve a truthful zero
		// record for an absent jail without hiding service-level failures.
		if runErr != nil || result == nil || result.ExitCode != 0 {
			continue
		}
		status.Jails[apiName] = parseJailStatus(string(result.Stdout))
	}

	return status, nil
}

func Banned(ctx context.Context, jobID string, runner RootRunner) (*BannedResult, error) {
	status, err := Status(ctx, jobID, runner)
	if err != nil {
		return nil, err
	}
	result := &BannedResult{BannedIPs: []BannedIP{}}
	for _, jail := range []string{"proxmox", "ssh"} {
		for _, ip := range status.Jails[jail].BannedIPs {
			result.BannedIPs = append(result.BannedIPs, BannedIP{Jail: jail, IP: ip})
		}
	}
	result.Total = len(result.BannedIPs)
	return result, nil
}

func Unban(ctx context.Context, jobID string, params UnbanParams, runner RootRunner) (*StatusResult, error) {
	runner = withDefaultRunner(runner)
	hostJail, ok := map[string]string{"proxmox": "proxmox", "ssh": "sshd"}[params.Jail]
	if !ok {
		return nil, fmt.Errorf("fail2ban.unban: jail must be proxmox or ssh")
	}
	if net.ParseIP(strings.TrimSpace(params.IP)) == nil {
		return nil, fmt.Errorf("fail2ban.unban: invalid IP address")
	}

	result, err := runner.RunRoot(
		ctx,
		jobID,
		"fail2ban-unban-"+params.Jail,
		clientPath,
		[]string{"set", hostJail, "unbanip", strings.TrimSpace(params.IP)},
		scopeHardening,
	)
	if err != nil || result == nil || result.ExitCode != 0 {
		return nil, commandError("unban fail2ban address", result, err)
	}
	return Status(ctx, jobID, runner)
}

func parseJailStatus(output string) JailStatus {
	status := emptyJailStatus()
	for _, line := range strings.Split(output, "\n") {
		// fail2ban-client renders a tree with prefixes such as "   |-" and
		// "   `-". Strip the complete decoration before matching field names.
		key, value, ok := strings.Cut(strings.TrimLeft(line, " \t|-`"), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Currently banned":
			status.Banned = parseNonNegativeInt(value)
		case "Total banned":
			status.Total = parseNonNegativeInt(value)
		case "Banned IP list":
			for _, candidate := range strings.Fields(value) {
				if net.ParseIP(candidate) != nil {
					status.BannedIPs = append(status.BannedIPs, candidate)
				}
			}
			sort.Strings(status.BannedIPs)
		}
	}
	// Prefer the concrete list over a contradictory CLI counter.
	status.Banned = len(status.BannedIPs)
	return status
}

func parseNonNegativeInt(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}

func emptyJailStatus() JailStatus {
	return JailStatus{BannedIPs: []string{}}
}

func withDefaultRunner(runner RootRunner) RootRunner {
	if runner == nil {
		return &defaultRootRunner{}
	}
	return runner
}

func commandError(action string, result *rootscope.Result, err error) error {
	message := ""
	if result != nil {
		message = strings.TrimSpace(string(result.Stderr))
	}
	if message != "" {
		return fmt.Errorf("fail2ban: %s failed: %s", action, message)
	}
	if err != nil {
		return fmt.Errorf("fail2ban: %s failed: %w", action, err)
	}
	return fmt.Errorf("fail2ban: %s failed", action)
}
