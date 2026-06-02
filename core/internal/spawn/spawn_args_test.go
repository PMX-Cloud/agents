package spawn

import (
	"strings"
)

import "testing"

// TestBoolSystemd covers the boolSystemd helper (currently at 0% coverage).
func TestBoolSystemd(t *testing.T) {
	if got := boolSystemd(true); got != "yes" {
		t.Errorf("boolSystemd(true) = %q, want %q", got, "yes")
	}
	if got := boolSystemd(false); got != "no" {
		t.Errorf("boolSystemd(false) = %q, want %q", got, "no")
	}
}

// TestProfileForTemplate_AllKnownTemplates covers all documented templates.
func TestProfileForTemplate_AllKnownTemplates(t *testing.T) {
	cases := []struct {
		template    string
		wantUser    string
		wantType    string
		wantRuntime int
	}{
		{"pmx-hardware-installer@.service", "root", "oneshot", 0},
		{"pmx-updater@.service", "root", "oneshot", 0},
		{"pmx-console-broker@.service", "pmx-console", "simple", 14400},
	}
	for _, tc := range cases {
		p := profileForTemplate(tc.template)
		if p.User != tc.wantUser {
			t.Errorf("%s: User = %q, want %q", tc.template, p.User, tc.wantUser)
		}
		if p.ServiceType != tc.wantType {
			t.Errorf("%s: ServiceType = %q, want %q", tc.template, p.ServiceType, tc.wantType)
		}
		if p.DefaultRuntime != tc.wantRuntime {
			t.Errorf("%s: DefaultRuntime = %d, want %d", tc.template, p.DefaultRuntime, tc.wantRuntime)
		}
	}
}

// TestProfileForTemplate_FallbackIsRoot covers the fallback for unknown templates.
func TestProfileForTemplate_Fallback(t *testing.T) {
	p := profileForTemplate("unknown@.service")
	if p.User != "root" {
		t.Errorf("fallback User = %q, want root", p.User)
	}
	if p.ServiceType != "oneshot" {
		t.Errorf("fallback ServiceType = %q, want oneshot", p.ServiceType)
	}
	if p.RemainAfterExit {
		t.Error("fallback RemainAfterExit should be false")
	}
}

// TestInstantiateTemplate_VariousInputs covers edge cases in template instantiation.
func TestInstantiateTemplate_VariousInputs(t *testing.T) {
	cases := []struct {
		template, jobID, want string
	}{
		{"pmx-hardware-installer@.service", "abc-123", "pmx-hardware-installer@abc-123.service"},
		{"pmx-updater@.service", "upd-v2-001", "pmx-updater@upd-v2-001.service"},
		{"pmx-console-broker@.service", "sess-42", "pmx-console-broker@sess-42.service"},
	}
	for _, tc := range cases {
		got := InstantiateTemplate(tc.template, tc.jobID)
		if got != tc.want {
			t.Errorf("InstantiateTemplate(%q, %q) = %q, want %q", tc.template, tc.jobID, got, tc.want)
		}
	}
}

// TestTemplateToBinary_KnownTemplates covers the binary path mapping.
func TestTemplateToBinary_KnownTemplates(t *testing.T) {
	cases := []struct {
		template, want string
	}{
		{"pmx-hardware-installer@.service", "/usr/local/bin/pmx-hardware-installer"},
		{"pmx-updater@.service", "/usr/local/bin/pmx-updater"},
		{"pmx-console-broker@.service", "/usr/local/bin/pmx-console-broker"},
		{"pmx-foo@.service", "/usr/local/bin/pmx-foo"},
	}
	for _, tc := range cases {
		got := TemplateToBinary(tc.template)
		if got != tc.want {
			t.Errorf("TemplateToBinary(%q) = %q, want %q", tc.template, got, tc.want)
		}
	}
}

// TestConsoleBrokerProfile_AppArmor verifies the console-broker AppArmor profile is set.
func TestConsoleBrokerProfile_AppArmor(t *testing.T) {
	p := profileForTemplate("pmx-console-broker@.service")
	if p.AppArmorProfile != "pmx-console-broker" {
		t.Errorf("AppArmorProfile = %q, want pmx-console-broker", p.AppArmorProfile)
	}
	if p.Restart != "no" {
		t.Errorf("Restart = %q, want no", p.Restart)
	}
}

// TestBuildSpawnArgs_HardwareInstaller verifies the argv for the hardware installer.
func TestBuildSpawnArgs_HardwareInstaller(t *testing.T) {
	req := EphemeralRequest{
		Template: "pmx-hardware-installer@.service",
		JobID:    "job-001",
	}
	profile := profileForTemplate(req.Template)
	args := buildSpawnArgs(req, profile)

	if args[0] != "systemd-run" {
		t.Fatalf("args[0] = %q, want systemd-run", args[0])
	}
	if args[1] != "--unit=pmx-hardware-installer@job-001.service" {
		t.Errorf("args[1] = %q, want unit name", args[1])
	}

	// Verify no shell metacharacters leak into any arg
	forbidden := []string{";", "|", "`", "$", "&&", "||", ">", "<"}
	for _, arg := range args {
		for _, meta := range forbidden {
			if strings.Contains(arg, meta) {
				t.Errorf("arg %q contains forbidden shell metacharacter %q", arg, meta)
			}
		}
	}

	// Last arg must be the binary
	last := args[len(args)-1]
	if last != "/usr/local/bin/pmx-hardware-installer" {
		t.Errorf("last arg = %q, want binary path", last)
	}
}

// TestBuildSpawnArgs_ConsoleBroker verifies AppArmor + Restart + RuntimeMax in argv.
func TestBuildSpawnArgs_ConsoleBroker(t *testing.T) {
	req := EphemeralRequest{
		Template: "pmx-console-broker@.service",
		JobID:    "sess-42",
	}
	profile := profileForTemplate(req.Template)
	args := buildSpawnArgs(req, profile)

	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "AppArmorProfile=pmx-console-broker") {
		t.Errorf("missing AppArmorProfile in args: %v", args)
	}
	if !strings.Contains(joined, "Restart=no") {
		t.Errorf("missing Restart=no in args: %v", args)
	}
	if !strings.Contains(joined, "RuntimeMaxSec=14400") {
		t.Errorf("missing RuntimeMaxSec in args: %v", args)
	}
}

// TestBuildSpawnArgs_CustomRuntimeMaxSec verifies an explicit timeout overrides the default.
func TestBuildSpawnArgs_CustomRuntimeMaxSec(t *testing.T) {
	req := EphemeralRequest{
		Template:      "pmx-console-broker@.service",
		JobID:         "sess-99",
		RuntimeMaxSec: 3600,
	}
	profile := profileForTemplate(req.Template)
	args := buildSpawnArgs(req, profile)

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "RuntimeMaxSec=3600") {
		t.Errorf("missing RuntimeMaxSec=3600 in args: %v", args)
	}
	if strings.Contains(joined, "RuntimeMaxSec=14400") {
		t.Errorf("default runtime should be overridden, got: %v", args)
	}
}

// TestBuildSpawnArgs_NoRuntimeForOneshot verifies oneshot agents have no RuntimeMaxSec.
func TestBuildSpawnArgs_NoRuntimeForOneshot(t *testing.T) {
	req := EphemeralRequest{
		Template: "pmx-hardware-installer@.service",
		JobID:    "job-x",
	}
	profile := profileForTemplate(req.Template)
	args := buildSpawnArgs(req, profile)

	for _, a := range args {
		if strings.HasPrefix(a, "--property=RuntimeMaxSec=") {
			t.Errorf("oneshot agent should not have RuntimeMaxSec, got %q", a)
		}
	}
}
