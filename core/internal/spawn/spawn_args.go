/*
Package spawn_args contains the pure (no OS calls) argument-building logic
for ephemeral agent spawning. Extracted from spawn.go so it can be tested
without root, systemd, or Linux-specific syscalls.
*/
package spawn

import "fmt"

// buildSpawnArgs assembles the systemd-run argument list for an ephemeral
// agent unit. It is a pure function — no OS calls — so it can be tested
// without root or systemd.
func buildSpawnArgs(req EphemeralRequest, profile templateProfile) []string {
	unitName := InstantiateTemplate(req.Template, req.JobID)

	args := []string{
		"systemd-run",
		"--unit=" + unitName,
		"--property=StandardInput=fd:3",
		fmt.Sprintf("--property=Type=%s", profile.ServiceType),
		fmt.Sprintf("--property=User=%s", profile.User),
		fmt.Sprintf("--property=Group=%s", profile.Group),
		fmt.Sprintf("--property=RemainAfterExit=%s", boolSystemd(profile.RemainAfterExit)),
	}
	if profile.Restart != "" {
		args = append(args, fmt.Sprintf("--property=Restart=%s", profile.Restart))
	}
	if profile.AppArmorProfile != "" {
		args = append(args, fmt.Sprintf("--property=AppArmorProfile=%s", profile.AppArmorProfile))
	}
	runtimeMax := req.RuntimeMaxSec
	if runtimeMax <= 0 {
		runtimeMax = profile.DefaultRuntime
	}
	if runtimeMax > 0 {
		args = append(args, fmt.Sprintf("--property=RuntimeMaxSec=%d", runtimeMax))
	}
	args = append(args, TemplateToBinary(req.Template))
	return args
}

// profileForTemplate returns the template profile for a known agent template,
// falling back to a default root/oneshot profile for unknown templates.
func profileForTemplate(template string) templateProfile {
	if profile, ok := defaultTemplateProfiles[template]; ok {
		return profile
	}
	return templateProfile{
		User:            "root",
		Group:           "root",
		ServiceType:     "oneshot",
		RemainAfterExit: false,
	}
}

func boolSystemd(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
