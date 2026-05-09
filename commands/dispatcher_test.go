package commands

import (
	"context"
	"encoding/json"
	"testing"
)

func TestDispatcherSupportsInfrastructureCommandSurface(t *testing.T) {
	dispatcher := NewDispatcher(&recordingRunner{})

	for _, command := range []string{
		"hardening.apply",
		"network.optimize",
		"persistent-nic-names",
		"fail2ban.install",
		"fail2ban.unban",
		"lynis.run",
		"smart.poll",
		"iommu.enable",
		"disk.format",
		"disk.passthrough",
		"gpu.attach",
		"gpu.detach",
		"provisioning.apply",
		"community-script.run",
		"zfs.tune",
		"log2ram.install",
		"ovs.install",
		"ovs.configure",
		"ksm.configure",
		"guest-agent.enable",
	} {
		if !dispatcher.Supports(command) {
			t.Fatalf("expected %s to be supported", command)
		}
	}
}

func TestHardeningApplyBuildsRequestedIdempotentSteps(t *testing.T) {
	runner := &recordingRunner{}
	dispatcher := NewDispatcher(runner)
	payload := mustJSON(t, map[string]any{
		"enableFastReboots":     true,
		"kernelPanicAutoReboot": true,
		"increaseSystemLimits":  false,
		"optimizeJournald":      true,
		"installKernelHeaders":  false,
		"installHaveged":        false,
		"optimizeLogrotate":     false,
		"optimizeMemory":        false,
	})

	result := dispatcher.Dispatch(context.Background(), "hardening.apply", payload)

	if result.Status != "completed" {
		t.Fatalf("expected completed result, got %s: %s", result.Status, result.Error)
	}
	if len(result.Steps) != 3 {
		t.Fatalf("expected 3 requested steps, got %d", len(result.Steps))
	}
	if len(runner.steps) != 3 {
		t.Fatalf("expected runner to receive 3 steps, got %d", len(runner.steps))
	}
	assertStepContains(t, runner.steps, "enable-fast-reboots", "kexec-tools")
	assertStepContains(t, runner.steps, "kernel-panic-auto-reboot", "99-kernelpanic.conf")
	assertStepContains(t, runner.steps, "optimize-journald", "SystemMaxUse=64M")
}

func TestDiskFormatRequiresExplicitDestructiveConfirmation(t *testing.T) {
	runner := &recordingRunner{}
	dispatcher := NewDispatcher(runner)
	payload := mustJSON(t, map[string]any{
		"device":     "/dev/sdb",
		"filesystem": "ext4",
	})

	result := dispatcher.Dispatch(context.Background(), "disk.format", payload)

	if result.Status != "failed" {
		t.Fatalf("expected failed result without confirmation, got %s", result.Status)
	}
	if len(runner.steps) != 0 {
		t.Fatalf("expected no destructive command execution, got %d steps", len(runner.steps))
	}
	if result.Error == "" {
		t.Fatal("expected a validation error message")
	}
}

func TestFail2BanUnbanValidatesJailAndIp(t *testing.T) {
	runner := &recordingRunner{}
	dispatcher := NewDispatcher(runner)
	payload := mustJSON(t, map[string]any{
		"jail": "sshd",
		"ip":   "203.0.113.10",
	})

	result := dispatcher.Dispatch(context.Background(), "fail2ban.unban", payload)

	if result.Status != "completed" {
		t.Fatalf("expected completed result, got %s: %s", result.Status, result.Error)
	}
	assertStepContains(t, runner.steps, "fail2ban-unban", "203.0.113.10")
}

func TestProvisioningApplyAcceptsBackendStepNamesAndBuildsRealCommands(t *testing.T) {
	runner := &recordingRunner{}
	dispatcher := NewDispatcher(runner)
	payload := mustJSON(t, map[string]any{
		"steps": []string{
			"system-hardening",
			"security-baseline",
			"network-optimization",
			"iommu-enable",
			"nvidia-driver-install",
			"zfs-tuning",
			"log2ram-install",
			"smart-scheduling",
		},
	})

	result := dispatcher.Dispatch(context.Background(), "provisioning.apply", payload)

	if result.Status != "completed" {
		t.Fatalf("expected completed result, got %s: %s", result.Status, result.Error)
	}
	assertStepContains(t, runner.steps, "kernel-panic-auto-reboot", "99-kernelpanic.conf")
	assertStepContains(t, runner.steps, "fail2ban-install", "fail2ban")
	assertStepContains(t, runner.steps, "network-sysctl", "tcp_congestion_control=bbr")
	assertStepContains(t, runner.steps, "iommu-enable", "vfio_pci")
	assertStepContains(t, runner.steps, "nvidia-driver-install", "nvidia-driver")
	assertStepContains(t, runner.steps, "zfs-tune", "zfs_arc_max")
	assertStepContains(t, runner.steps, "log2ram-install", "log2ram")
	assertStepContains(t, runner.steps, "smart-poll", "smartctl --scan-open")
	for _, step := range runner.steps {
		if containsString(step.Command, "queued for this node") {
			t.Fatalf("provisioning step %s still uses placeholder command %q", step.Name, step.Command)
		}
	}
}

type recordingRunner struct {
	steps []Step
}

func (r *recordingRunner) Run(_ context.Context, step Step) StepResult {
	r.steps = append(r.steps, step)
	return StepResult{
		Name:     step.Name,
		Command:  step.Command,
		Status:   "completed",
		ExitCode: 0,
		Output:   "ok",
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func assertStepContains(t *testing.T, steps []Step, name string, contains string) {
	t.Helper()
	for _, step := range steps {
		if step.Name == name && containsString(step.Command, contains) {
			return
		}
	}
	t.Fatalf("expected step %s to contain %q in %#v", name, contains, steps)
}

func containsString(value string, contains string) bool {
	for i := 0; i+len(contains) <= len(value); i++ {
		if value[i:i+len(contains)] == contains {
			return true
		}
	}
	return false
}
