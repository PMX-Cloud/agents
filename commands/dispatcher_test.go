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
		"disk.import-image",
		"nvme.controller.add",
		"gpu.attach",
		"gpu.detach",
		"gpu.mode",
		"nvidia.driver.install",
		"coral.tpu.install",
		"coral.tpu.attach",
		"sriov.configure",
		"lxc.mount",
		"provisioning.apply",
		"community-script.run",
		"zfs.tune",
		"log2ram.install",
		"ovs.install",
		"ovs.configure",
		"ksm.configure",
		"guest-agent.enable",
		"vm.create.synology-dsm",
		"vm.create.zimaos",
		"rpcbind.disable",
		"smart.schedule",
		"pve.upgrade",
		"subscription-banner.remove",
		"subscription-banner.restore",
		"utilities.install",
		"apt.tune",
		"network.verify",
		"network.repair",
		"martian.fix",
		"xshok.conflict.detect",
		"agent.diagnostics",
		"nested-cloud.install-proxmox",
		"nested-cloud.configure-nat",
		"nested-cloud.verify-ready",
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

func TestAdditionalProxMenuXCommandsBuildSafeShellSteps(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		payload  map[string]any
		stepName string
		contains string
	}{
		{
			name:     "smart schedule",
			command:  "smart.schedule",
			payload:  map[string]any{"device": "/dev/sdb", "testType": "long", "schedule": "weekly"},
			stepName: "smart-schedule",
			contains: "smartd.conf",
		},
		{
			name:     "pve upgrade check",
			command:  "pve.upgrade",
			payload:  map[string]any{"targetVersion": "9", "mode": "check-only"},
			stepName: "pve-upgrade-check",
			contains: "pve8to9",
		},
		{
			name:     "subscription banner removal",
			command:  "subscription-banner.remove",
			payload:  map[string]any{},
			stepName: "subscription-banner-remove",
			contains: "proxmoxlib.js",
		},
		{
			name:     "utility install",
			command:  "utilities.install",
			payload:  map[string]any{"packages": []string{"htop", "btop"}},
			stepName: "utilities-install",
			contains: "apt-get install -y",
		},
		{
			name:     "apt tune",
			command:  "apt.tune",
			payload:  map[string]any{},
			stepName: "apt-tune",
			contains: "Acquire::Queue-Mode",
		},
		{
			name:     "network verify",
			command:  "network.verify",
			payload:  map[string]any{},
			stepName: "network-verify",
			contains: "ip -br addr",
		},
		{
			name:     "network repair",
			command:  "network.repair",
			payload:  map[string]any{"restartNetworking": true},
			stepName: "network-repair",
			contains: "ifreload -a",
		},
		{
			name:     "martian source fix",
			command:  "martian.fix",
			payload:  map[string]any{},
			stepName: "martian-source-fix",
			contains: "log_martians=0",
		},
		{
			name:     "xshok conflict detection",
			command:  "xshok.conflict.detect",
			payload:  map[string]any{},
			stepName: "xshok-conflict-detect",
			contains: "99-proxmox.conf",
		},
		{
			name:     "synology dsm vm create",
			command:  "vm.create.synology-dsm",
			payload:  map[string]any{"vmId": "301", "name": "dsm-nas", "loaderUrl": "https://example.invalid/loader.img", "dataDisks": []string{"/dev/disk/by-id/nvme-test"}},
			stepName: "vm-create-synology-dsm",
			contains: "qm create",
		},
		{
			name:     "zimaos vm create",
			command:  "vm.create.zimaos",
			payload:  map[string]any{"vmId": "302", "name": "zima-home", "imageUrl": "https://example.invalid/zimaos.img"},
			stepName: "vm-create-zimaos",
			contains: "qm importdisk",
		},
		{
			name:     "disk image import",
			command:  "disk.import-image",
			payload:  map[string]any{"vmId": "101", "source": "/var/lib/vz/template/imports/disk.qcow2", "targetStorage": "local-lvm", "format": "qcow2"},
			stepName: "disk-import-image",
			contains: "qm importdisk",
		},
		{
			name:     "nvme controller add",
			command:  "nvme.controller.add",
			payload:  map[string]any{"vmId": "101"},
			stepName: "nvme-controller-add",
			contains: "-device nvme",
		},
		{
			name:     "lxc mount",
			command:  "lxc.mount",
			payload:  map[string]any{"ctId": "201", "hostPath": "/srv/shared/backups", "containerPath": "/mnt/backups", "readOnly": true},
			stepName: "lxc-mount",
			contains: "pct set",
		},
		{
			name:     "nvidia driver install",
			command:  "nvidia.driver.install",
			payload:  map[string]any{},
			stepName: "nvidia-driver-install",
			contains: "nvidia-driver",
		},
		{
			name:     "gpu mode",
			command:  "gpu.mode",
			payload:  map[string]any{"pciId": "0000:65:00.0", "mode": "passthrough"},
			stepName: "gpu-mode",
			contains: "vfio-pci",
		},
		{
			name:     "coral tpu install",
			command:  "coral.tpu.install",
			payload:  map[string]any{"interface": "usb"},
			stepName: "coral-tpu-install",
			contains: "apex",
		},
		{
			name:     "coral tpu attach",
			command:  "coral.tpu.attach",
			payload:  map[string]any{"ctId": "201", "device": "/dev/bus/usb/001/002"},
			stepName: "coral-tpu-attach",
			contains: "lxc.cgroup2.devices.allow",
		},
		{
			name:     "sriov configure",
			command:  "sriov.configure",
			payload:  map[string]any{"pfPciId": "0000:17:00.0", "count": 4},
			stepName: "sriov-configure",
			contains: "sriov_numvfs",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &recordingRunner{}
			dispatcher := NewDispatcher(runner)

			result := dispatcher.Dispatch(context.Background(), tc.command, mustJSON(t, tc.payload))

			if result.Status != "completed" {
				t.Fatalf("expected completed result, got %s: %s", result.Status, result.Error)
			}
			assertStepContains(t, runner.steps, tc.stepName, tc.contains)
		})
	}
}

func TestAgentDiagnosticsBuildsReadOnlyRealClusterSmokeSteps(t *testing.T) {
	runner := &recordingRunner{}
	dispatcher := NewDispatcher(runner)

	result := dispatcher.Dispatch(context.Background(), "agent.diagnostics", mustJSON(t, map[string]any{}))

	if result.Status != "completed" {
		t.Fatalf("expected completed result, got %s: %s", result.Status, result.Error)
	}
	for _, expected := range []struct {
		name     string
		contains string
	}{
		{name: "host-identity", contains: "hostnamectl"},
		{name: "proxmox-readiness", contains: "pvecm status"},
		{name: "runtime-tools", contains: "command -v"},
		{name: "network-summary", contains: "ip -br addr"},
	} {
		assertStepContains(t, runner.steps, expected.name, expected.contains)
	}

	for _, step := range runner.steps {
		if step.Destructive {
			t.Fatalf("diagnostics step %s must not be marked destructive", step.Name)
		}
		for _, forbidden := range []string{
			"apt-get install",
			"mkfs.",
			"wipefs",
			"qm set",
			"pct set",
			"systemctl restart",
			"sysctl --system",
		} {
			if containsString(step.Command, forbidden) {
				t.Fatalf("diagnostics step %s contains mutating command %q in %q", step.Name, forbidden, step.Command)
			}
		}
	}
}

func TestDispatcherResultIncludesFinishedAtTimestamp(t *testing.T) {
	dispatcher := NewDispatcher(&recordingRunner{})

	result := dispatcher.Dispatch(context.Background(), "agent.diagnostics", mustJSON(t, map[string]any{}))

	if result.FinishedAt == "" {
		t.Fatal("expected finishedAt timestamp to be set")
	}
}

func TestNestedCloudInstallProxmoxBuildsGuestBootstrapCommand(t *testing.T) {
	runner := &recordingRunner{}
	dispatcher := NewDispatcher(runner)
	payload := mustJSON(t, map[string]any{
		"contractVersion":  1,
		"nestedCloudId":    "ncl_1",
		"outerVmId":        "vm_outer_1",
		"outerProxmoxVmid": 201,
		"privateCidr":      "10.77.0.0/24",
		"gateway":          "10.77.0.1",
		"dnsServers":       []string{"1.1.1.1", "8.8.8.8"},
	})

	result := dispatcher.Dispatch(context.Background(), "nested-cloud.install-proxmox", payload)

	if result.Status != "completed" {
		t.Fatalf("expected completed result, got %s: %s", result.Status, result.Error)
	}
	assertStepContains(t, runner.steps, "nested-cloud-guest-agent-ready", "qm guest ping '201'")
	assertStepContains(t, runner.steps, "nested-cloud-install-proxmox", "qm guest exec '201'")
	assertStepContains(t, runner.steps, "nested-cloud-install-proxmox", "proxmox-ve")
	assertStepContains(t, runner.steps, "nested-cloud-install-proxmox", "pveum user token add")
	assertStepContains(t, runner.steps, "nested-cloud-install-proxmox", "PMX_NESTED_CLOUD_INSTALL_RESULT")
}

func TestNestedCloudConfigureNatBuildsIdempotentPrivateNetworkCommand(t *testing.T) {
	runner := &recordingRunner{}
	dispatcher := NewDispatcher(runner)
	payload := mustJSON(t, map[string]any{
		"contractVersion":  1,
		"nestedCloudId":    "ncl_1",
		"outerVmId":        "vm_outer_1",
		"outerProxmoxVmid": 201,
		"privateCidr":      "10.77.0.0/24",
		"gateway":          "10.77.0.1",
		"dnsServers":       []string{"1.1.1.1"},
	})

	result := dispatcher.Dispatch(context.Background(), "nested-cloud.configure-nat", payload)

	if result.Status != "completed" {
		t.Fatalf("expected completed result, got %s: %s", result.Status, result.Error)
	}
	assertStepContains(t, runner.steps, "nested-cloud-configure-nat", "net.ipv4.ip_forward=1")
	assertStepContains(t, runner.steps, "nested-cloud-configure-nat", "vmbr0")
	assertStepContains(t, runner.steps, "nested-cloud-configure-nat", "MASQUERADE")
	assertStepContains(t, runner.steps, "nested-cloud-configure-nat", "iptables -t nat -C POSTROUTING")
	assertStepContains(t, runner.steps, "nested-cloud-configure-nat", "dnsmasq")
}

func TestNestedCloudVerifyReadyBuildsGuestHealthCheckCommand(t *testing.T) {
	runner := &recordingRunner{}
	dispatcher := NewDispatcher(runner)
	payload := mustJSON(t, map[string]any{
		"contractVersion":  1,
		"nestedCloudId":    "ncl_1",
		"outerVmId":        "vm_outer_1",
		"outerProxmoxVmid": 201,
		"adminUrl":         "https://192.0.2.50:8006",
	})

	result := dispatcher.Dispatch(context.Background(), "nested-cloud.verify-ready", payload)

	if result.Status != "completed" {
		t.Fatalf("expected completed result, got %s: %s", result.Status, result.Error)
	}
	assertStepContains(t, runner.steps, "nested-cloud-verify-ready", "pveversion")
	assertStepContains(t, runner.steps, "nested-cloud-verify-ready", "pveproxy")
	assertStepContains(t, runner.steps, "nested-cloud-verify-ready", "/api2/json/version")
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
