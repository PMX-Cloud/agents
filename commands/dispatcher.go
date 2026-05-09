package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

type Step struct {
	Name        string `json:"name"`
	Command     string `json:"command"`
	Destructive bool   `json:"destructive,omitempty"`
}

type StepResult struct {
	Name       string `json:"name"`
	Command    string `json:"command"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exitCode"`
	Output     string `json:"output,omitempty"`
	Error      string `json:"error,omitempty"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
}

type Result struct {
	Command    string       `json:"command"`
	Status     string       `json:"status"`
	Error      string       `json:"error,omitempty"`
	Steps      []StepResult `json:"steps"`
	StartedAt  string       `json:"startedAt"`
	FinishedAt string       `json:"finishedAt"`
}

type Runner interface {
	Run(ctx context.Context, step Step) StepResult
}

type ShellRunner struct {
	Timeout time.Duration
	Now     func() time.Time
}

type Dispatcher struct {
	runner Runner
}

type commandBuilder func(json.RawMessage) ([]Step, error)

func NewDispatcher(runner Runner) *Dispatcher {
	if runner == nil {
		runner = ShellRunner{Timeout: 10 * time.Minute}
	}

	return &Dispatcher{runner: runner}
}

func SupportedCommands() []string {
	commands := make([]string, 0, len(commandBuilders))
	for command := range commandBuilders {
		commands = append(commands, command)
	}
	sort.Strings(commands)
	return commands
}

func (d *Dispatcher) Supports(command string) bool {
	_, ok := commandBuilders[command]
	return ok
}

func (d *Dispatcher) Dispatch(ctx context.Context, command string, payload json.RawMessage) Result {
	started := time.Now()
	result := Result{
		Command:   command,
		Status:    "completed",
		Steps:     []StepResult{},
		StartedAt: started.UTC().Format(time.RFC3339Nano),
	}
	defer func() {
		result.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}()

	builder, ok := commandBuilders[command]
	if !ok {
		result.Status = "failed"
		result.Error = fmt.Sprintf("unsupported command %q", command)
		return result
	}

	steps, err := builder(payload)
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		return result
	}

	for _, step := range steps {
		stepResult := d.runner.Run(ctx, step)
		result.Steps = append(result.Steps, stepResult)
		if stepResult.Status != "completed" {
			result.Status = "failed"
			if stepResult.Error != "" {
				result.Error = stepResult.Error
			} else {
				result.Error = fmt.Sprintf("step %s failed", step.Name)
			}
			break
		}
	}

	return result
}

func (r ShellRunner) Run(ctx context.Context, step Step) StepResult {
	now := r.Now
	if now == nil {
		now = time.Now
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}

	started := now()
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "bash", "-lc", step.Command)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	finished := now()

	result := StepResult{
		Name:       step.Name,
		Command:    step.Command,
		Status:     "completed",
		ExitCode:   0,
		Output:     strings.TrimSpace(output.String()),
		StartedAt:  started.UTC().Format(time.RFC3339Nano),
		FinishedAt: finished.UTC().Format(time.RFC3339Nano),
	}

	if err == nil {
		return result
	}

	result.Status = "failed"
	result.Error = err.Error()
	if exitErr, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
	} else {
		result.ExitCode = -1
	}
	if runCtx.Err() != nil {
		result.Error = runCtx.Err().Error()
	}

	return result
}

var commandBuilders = map[string]commandBuilder{
	"hardening.apply":      buildHardeningApplySteps,
	"network.optimize":     buildNetworkOptimizeSteps,
	"persistent-nic-names": buildPersistentNicNameSteps,
	"fail2ban.install":     buildFail2BanInstallSteps,
	"fail2ban.unban":       buildFail2BanUnbanSteps,
	"lynis.run":            buildLynisRunSteps,
	"smart.poll":           buildSmartPollSteps,
	"iommu.enable":         buildIommuEnableSteps,
	"disk.format":          buildDiskFormatSteps,
	"disk.passthrough":     buildDiskPassthroughSteps,
	"gpu.attach":           buildGpuAttachSteps,
	"gpu.detach":           buildGpuDetachSteps,
	"provisioning.apply":   buildProvisioningApplySteps,
	"community-script.run": buildCommunityScriptRunSteps,
	"zfs.tune":             buildZfsTuneSteps,
	"log2ram.install":      buildLog2RamInstallSteps,
	"ovs.install":          buildOvsInstallSteps,
	"ovs.configure":        buildOvsConfigureSteps,
	"ksm.configure":        buildKsmConfigureSteps,
	"guest-agent.enable":   buildGuestAgentEnableSteps,
}

func buildHardeningApplySteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}

	var steps []Step
	if boolParam(params, "enableFastReboots") {
		steps = append(steps, Step{
			Name: "enable-fast-reboots",
			Command: joinShell(
				"apt-get update",
				"DEBIAN_FRONTEND=noninteractive apt-get install -y kexec-tools",
				"systemctl enable kexec-pve.service || true",
			),
		})
	}
	if boolParam(params, "kernelPanicAutoReboot") {
		steps = append(steps, Step{
			Name: "kernel-panic-auto-reboot",
			Command: joinShell(
				"printf '%s\n' 'kernel.panic=10' > /etc/sysctl.d/99-kernelpanic.conf",
				"sysctl --system",
			),
		})
	}
	if boolParam(params, "increaseSystemLimits") {
		steps = append(steps, Step{
			Name: "increase-system-limits",
			Command: joinShell(
				"printf '%s\n' 'fs.inotify.max_user_watches=1048576' 'fs.file-max=1048576' > /etc/sysctl.d/99-pmx-cloud-limits.conf",
				"printf '%s\n' '* soft nofile 1048576' '* hard nofile 1048576' 'root soft nofile 1048576' 'root hard nofile 1048576' > /etc/security/limits.d/99-pmx-cloud.conf",
				"sysctl --system",
			),
		})
	}
	if boolParam(params, "optimizeJournald") {
		steps = append(steps, Step{
			Name: "optimize-journald",
			Command: joinShell(
				"mkdir -p /etc/systemd/journald.conf.d",
				"printf '%s\n' '[Journal]' 'SystemMaxUse=64M' > /etc/systemd/journald.conf.d/99-pmx-cloud.conf",
				"systemctl restart systemd-journald",
			),
		})
	}
	if boolParam(params, "optimizeMemory") {
		steps = append(steps, Step{
			Name: "optimize-memory",
			Command: joinShell(
				"printf '%s\n' 'vm.swappiness=10' 'vm.dirty_ratio=15' 'vm.overcommit_memory=1' > /etc/sysctl.d/99-pmx-cloud-memory.conf",
				"if [ -w /proc/sys/vm/compaction_proactiveness ]; then printf '%s' 20 > /proc/sys/vm/compaction_proactiveness; fi",
				"sysctl --system",
			),
		})
	}
	if boolParam(params, "installHaveged") {
		steps = append(steps, Step{
			Name: "install-haveged",
			Command: joinShell(
				"apt-get update",
				"DEBIAN_FRONTEND=noninteractive apt-get install -y haveged",
				"sed -i 's/^DAEMON_ARGS=.*/DAEMON_ARGS=\"-w 1024\"/' /etc/default/haveged || true",
				"systemctl enable --now haveged",
			),
		})
	}
	if boolParam(params, "installKernelHeaders") {
		steps = append(steps, Step{
			Name:    "install-kernel-headers",
			Command: "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \"linux-headers-$(uname -r)\"",
		})
	}
	if boolParam(params, "optimizeLogrotate") {
		steps = append(steps, Step{
			Name: "optimize-logrotate",
			Command: joinShell(
				"if [ ! -f /etc/logrotate.conf.pmx-cloud.bak ]; then cp /etc/logrotate.conf /etc/logrotate.conf.pmx-cloud.bak; fi",
				"printf '%s\n' 'daily' 'rotate 7' 'size 10M' 'compress' 'missingok' 'notifempty' 'include /etc/logrotate.d' > /etc/logrotate.conf",
			),
		})
	}

	return requireAtLeastOneStep(steps, "hardening.apply")
}

func buildNetworkOptimizeSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}

	var steps []Step
	if boolParam(params, "applyNetworkSysctl") {
		steps = append(steps, Step{
			Name: "network-sysctl",
			Command: joinShell(
				"printf '%s\n' 'net.core.rmem_max=134217728' 'net.core.wmem_max=134217728' 'net.core.netdev_max_backlog=250000' 'net.ipv4.tcp_rmem=4096 87380 134217728' 'net.ipv4.tcp_wmem=4096 65536 134217728' 'net.ipv4.tcp_congestion_control=bbr' 'net.ipv4.tcp_fastopen=3' 'net.ipv4.conf.all.log_martians=0' 'net.ipv4.conf.default.log_martians=0' > /etc/sysctl.d/99-network-performance.conf",
				"sysctl --system",
			),
		})
	}
	if boolParam(params, "enableTcpBBR") {
		steps = append(steps, Step{
			Name: "enable-tcp-bbr",
			Command: joinShell(
				"printf '%s\n' tcp_bbr > /etc/modules-load.d/bbr.conf",
				"modprobe tcp_bbr || true",
				"printf '%s\n' 'net.core.default_qdisc=fq' 'net.ipv4.tcp_congestion_control=bbr' > /etc/sysctl.d/99-tcp-bbr.conf",
				"printf '%s\n' 'net.ipv4.tcp_fastopen=3' > /etc/sysctl.d/99-tcp-fastopen.conf",
				"sysctl --system",
			),
		})
	}
	if boolParam(params, "forceAptIPv4") {
		steps = append(steps, Step{
			Name:    "force-apt-ipv4",
			Command: "printf '%s\n' 'Acquire::ForceIPv4 \"true\";' > /etc/apt/apt.conf.d/99-force-ipv4",
		})
	}
	if boolParam(params, "installOpenVSwitch") {
		steps = append(steps, buildOvsInstallCommandStep())
	}
	if boolParam(params, "optimizeNICSettings") {
		steps = append(steps, Step{
			Name: "optimize-nic-settings",
			Command: joinShell(
				"for dev in $(ls /sys/class/net | grep -Ev '^(lo|veth|tap|fwbr|fwln|fwpr)'); do ip link set \"$dev\" txqueuelen 10000 || true; done",
				"printf '%s\n' 'ACTION==\"add\", SUBSYSTEM==\"net\", KERNEL!=\"lo\", RUN+=\"/sbin/ip link set $name txqueuelen 10000\"' > /etc/udev/rules.d/99-pmx-cloud-nic.rules",
			),
		})
	}

	return requireAtLeastOneStep(steps, "network.optimize")
}

func buildPersistentNicNameSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name: "persistent-nic-names",
		Command: joinShell(
			"mkdir -p /etc/systemd/network",
			"for dev in $(ls /sys/class/net | grep -Ev '^(lo|veth|tap|fwbr|fwln|fwpr|vmbr|bond)'); do mac=$(cat \"/sys/class/net/$dev/address\"); printf '[Match]\\nMACAddress=%s\\n\\n[Link]\\nNamePolicy=keep kernel database onboard slot path\\n' \"$mac\" > \"/etc/systemd/network/10-$dev.link\"; done",
			"systemctl restart systemd-udevd || true",
		),
	}}, nil
}

func buildFail2BanInstallSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name: "fail2ban-install",
		Command: joinShell(
			"apt-get update",
			"DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban",
			"printf '%s\n' '[Definition]' 'failregex = pvedaemon\\[.*authentication failure; rhost=<HOST> user=.* msg=.*' 'ignoreregex =' > /etc/fail2ban/filter.d/proxmox.conf",
			"printf '%s\n' '[proxmox]' 'enabled = true' 'port = 8006,8007' 'filter = proxmox' 'logpath = /var/log/daemon.log' 'maxretry = 3' 'bantime = 3600' > /etc/fail2ban/jail.d/proxmox.conf",
			"printf '%s\n' '[sshd]' 'enabled = true' 'maxretry = 2' 'bantime = 86400' 'logpath = /var/log/auth.log' > /etc/fail2ban/jail.local",
			"systemctl enable --now fail2ban",
			"fail2ban-client reload",
		),
	}}, nil
}

func buildFail2BanUnbanSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	jail, err := requiredSafeToken(params, "jail")
	if err != nil {
		return nil, err
	}
	ip, err := requiredSafeToken(params, "ip")
	if err != nil {
		return nil, err
	}
	return []Step{{
		Name:    "fail2ban-unban",
		Command: fmt.Sprintf("fail2ban-client set %s unbanip %s", shellQuote(jail), shellQuote(ip)),
	}}, nil
}

func buildLynisRunSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name: "lynis-run",
		Command: joinShell(
			"if [ -d /opt/lynis/.git ]; then git -C /opt/lynis pull --ff-only; else git clone --depth=1 https://github.com/CISOfy/lynis /opt/lynis; fi",
			"/opt/lynis/lynis audit system --quiet --no-colors",
		),
	}}, nil
}

func buildSmartPollSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name: "smart-poll",
		Command: joinShell(
			"command -v smartctl >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y smartmontools",
			"smartctl --scan-open",
			"for device in $(smartctl --scan-open | awk '{print $1}'); do smartctl -a \"$device\" || true; done",
		),
	}}, nil
}

func buildIommuEnableSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name: "iommu-enable",
		Command: joinShell(
			"if grep -q GenuineIntel /proc/cpuinfo; then iommu='intel_iommu=on iommu=pt'; else iommu='amd_iommu=on iommu=pt'; fi",
			"if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub; then sed -i \"s/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\\\"quiet $iommu\\\"/\" /etc/default/grub; fi",
			"printf '%s\n' vfio vfio_iommu_type1 vfio_pci vfio_virqfd > /etc/modules-load.d/vfio.conf",
			"update-grub",
		),
	}}, nil
}

func buildDiskFormatSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	if !boolParam(params, "confirm") && !boolParam(params, "allowDestructive") {
		return nil, errors.New("disk.format requires confirm=true or allowDestructive=true")
	}
	device, err := requiredDevicePath(params, "device")
	if err != nil {
		return nil, err
	}
	filesystem, err := requiredSafeToken(params, "filesystem")
	if err != nil {
		return nil, err
	}
	if !oneOf(filesystem, "ext4", "xfs", "zfs") {
		return nil, fmt.Errorf("unsupported filesystem %q", filesystem)
	}

	formatCommand := fmt.Sprintf("mkfs.%s -F %s", filesystem, shellQuote(device))
	if filesystem == "zfs" {
		poolName := stringParam(params, "poolName", "pmx-data")
		if !isSafeToken(poolName) {
			return nil, fmt.Errorf("poolName contains unsafe characters")
		}
		formatCommand = fmt.Sprintf("zpool create -f %s %s", shellQuote(poolName), shellQuote(device))
	}

	return []Step{{
		Name:        "disk-format",
		Destructive: true,
		Command: joinShell(
			fmt.Sprintf("test -b %s", shellQuote(device)),
			fmt.Sprintf("if findmnt -S %s >/dev/null 2>&1; then echo 'device is mounted' >&2; exit 1; fi", shellQuote(device)),
			fmt.Sprintf("wipefs -a %s", shellQuote(device)),
			formatCommand,
		),
	}}, nil
}

func buildDiskPassthroughSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	device, err := requiredDevicePath(params, "device")
	if err != nil {
		return nil, err
	}
	targetType := stringParam(params, "targetType", stringParam(params, "type", "vm"))
	targetId, err := requiredSafeTokenAny(params, "targetId", "vmId", "ctId")
	if err != nil {
		return nil, err
	}
	slot := stringParam(params, "slot", "scsi1")

	if targetType == "container" || targetType == "lxc" {
		return []Step{{
			Name:    "disk-passthrough-lxc",
			Command: fmt.Sprintf("pct set %s -mp0 %s,mp=%s", shellQuote(targetId), shellQuote(device), shellQuote(stringParam(params, "mountPath", "/mnt/passthrough"))),
		}}, nil
	}

	if !isSafeToken(slot) {
		return nil, fmt.Errorf("slot contains unsafe characters")
	}
	return []Step{{
		Name:    "disk-passthrough-vm",
		Command: fmt.Sprintf("qm set %s -%s %s", shellQuote(targetId), shellQuote(slot), shellQuote(device)),
	}}, nil
}

func buildGpuAttachSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	vmID, err := requiredSafeTokenAny(params, "vmId", "targetId")
	if err != nil {
		return nil, err
	}
	pciID, err := requiredPciID(params, "pciId")
	if err != nil {
		return nil, err
	}
	slot := stringParam(params, "slot", "hostpci0")
	if !isSafeToken(slot) {
		return nil, fmt.Errorf("slot contains unsafe characters")
	}
	primary := "0"
	if boolParam(params, "primary") || boolParam(params, "x_vga") {
		primary = "1"
	}
	return []Step{{
		Name:    "gpu-attach",
		Command: fmt.Sprintf("qm set %s -%s %s,pcie=1,x-vga=%s", shellQuote(vmID), shellQuote(slot), shellQuote(pciID), primary),
	}}, nil
}

func buildGpuDetachSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	vmID, err := requiredSafeTokenAny(params, "vmId", "targetId")
	if err != nil {
		return nil, err
	}
	slot := stringParam(params, "slot", "hostpci0")
	if !isSafeToken(slot) {
		return nil, fmt.Errorf("slot contains unsafe characters")
	}
	return []Step{{
		Name:    "gpu-detach",
		Command: fmt.Sprintf("qm set %s -delete %s", shellQuote(vmID), shellQuote(slot)),
	}}, nil
}

func buildProvisioningApplySteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	rawSteps, _ := params["steps"].([]any)
	if len(rawSteps) == 0 {
		rawSteps = []any{"hardening", "security", "network"}
	}

	var steps []Step
	for _, raw := range rawSteps {
		name, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("provisioning step must be a string")
		}
		switch name {
		case "hardening", "system-hardening":
			hardeningSteps, err := buildProvisioningHardeningSteps()
			if err != nil {
				return nil, err
			}
			steps = append(steps, hardeningSteps...)
		case "security", "security-baseline":
			securitySteps, err := buildFail2BanInstallSteps(nil)
			if err != nil {
				return nil, err
			}
			steps = append(steps, securitySteps...)
		case "network", "network-optimization":
			networkSteps, err := buildProvisioningNetworkSteps()
			if err != nil {
				return nil, err
			}
			steps = append(steps, networkSteps...)
		case "smart", "smart-scheduling":
			smartSteps, err := buildSmartPollSteps(nil)
			if err != nil {
				return nil, err
			}
			steps = append(steps, smartSteps...)
		case "iommu", "iommu-enable":
			iommuSteps, err := buildIommuEnableSteps(nil)
			if err != nil {
				return nil, err
			}
			steps = append(steps, iommuSteps...)
		case "nvidia", "nvidia-driver", "nvidia-driver-install":
			nvidiaSteps, err := buildNvidiaDriverInstallSteps(nil)
			if err != nil {
				return nil, err
			}
			steps = append(steps, nvidiaSteps...)
		case "zfs", "zfs-tuning":
			zfsSteps, err := buildZfsTuneSteps(payload)
			if err != nil {
				return nil, err
			}
			steps = append(steps, zfsSteps...)
		case "log2ram", "log2ram-install":
			logSteps, err := buildLog2RamInstallSteps(nil)
			if err != nil {
				return nil, err
			}
			steps = append(steps, logSteps...)
		default:
			return nil, fmt.Errorf("unsupported provisioning step %q", name)
		}
	}

	return requireAtLeastOneStep(steps, "provisioning.apply")
}

func buildProvisioningHardeningSteps() ([]Step, error) {
	return buildHardeningApplySteps(json.RawMessage(`{
		"kernelPanicAutoReboot": true,
		"increaseSystemLimits": true,
		"optimizeJournald": true,
		"optimizeMemory": true,
		"installKernelHeaders": true,
		"optimizeLogrotate": true
	}`))
}

func buildProvisioningNetworkSteps() ([]Step, error) {
	return buildNetworkOptimizeSteps(json.RawMessage(`{
		"applyNetworkSysctl": true,
		"enableTcpBBR": true,
		"forceAptIPv4": true,
		"optimizeNICSettings": true
	}`))
}

func buildNvidiaDriverInstallSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name: "nvidia-driver-install",
		Command: joinShell(
			"apt-get update",
			"headers_pkg=$(if apt-cache show \"proxmox-headers-$(uname -r)\" >/dev/null 2>&1; then printf '%s' \"proxmox-headers-$(uname -r)\"; elif apt-cache show \"pve-headers-$(uname -r)\" >/dev/null 2>&1; then printf '%s' \"pve-headers-$(uname -r)\"; else printf '%s' pve-headers; fi)",
			"DEBIAN_FRONTEND=noninteractive apt-get install -y \"$headers_pkg\" nvidia-driver",
			"update-initramfs -u -k all || true",
			"nvidia-smi || true",
		),
	}}, nil
}

func buildCommunityScriptRunSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	scriptPath := stringParam(params, "scriptPath", "")
	url := stringParam(params, "url", "")
	checksum := stringParam(params, "checksum", "")

	if scriptPath != "" {
		if !strings.HasPrefix(scriptPath, "/var/lib/pmxcloud/scripts/") && !strings.HasPrefix(scriptPath, "/opt/pmxcloud/scripts/") {
			return nil, fmt.Errorf("scriptPath must be inside the pmx-cloud script cache")
		}
		return []Step{{
			Name:    "community-script-run",
			Command: fmt.Sprintf("test -x %s && %s", shellQuote(scriptPath), shellQuote(scriptPath)),
		}}, nil
	}

	if url == "" {
		return nil, fmt.Errorf("community-script.run requires scriptPath or url")
	}
	if checksum == "" && !boolParam(params, "allowUnverified") {
		return nil, fmt.Errorf("community-script.run url mode requires checksum or allowUnverified=true")
	}

	checksumCommand := "true"
	if checksum != "" {
		checksumCommand = fmt.Sprintf("printf '%%s  %%s\n' %s \"$tmp\" | sha256sum -c -", shellQuote(checksum))
	}

	return []Step{{
		Name: "community-script-run",
		Command: joinShell(
			"tmp=$(mktemp)",
			fmt.Sprintf("curl -fsSL %s -o \"$tmp\"", shellQuote(url)),
			checksumCommand,
			"chmod 700 \"$tmp\"",
			"bash \"$tmp\"",
			"rm -f \"$tmp\"",
		),
	}}, nil
}

func buildZfsTuneSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	arcMaxMB := intParam(params, "arcMaxMb", intParam(params, "arcMaxMB", 0))
	if arcMaxMB <= 0 {
		arcMaxMB = 4096
	}
	arcBytes := arcMaxMB * 1024 * 1024
	return []Step{{
		Name: "zfs-tune",
		Command: joinShell(
			fmt.Sprintf("printf '%%s\n' 'options zfs zfs_arc_max=%d' > /etc/modprobe.d/zfs.conf", arcBytes),
			"update-initramfs -u -k all || true",
		),
	}}, nil
}

func buildLog2RamInstallSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name: "log2ram-install",
		Command: joinShell(
			"apt-get update",
			"DEBIAN_FRONTEND=noninteractive apt-get install -y rsync git",
			"if [ -d /opt/log2ram/.git ]; then git -C /opt/log2ram pull --ff-only; else git clone --depth=1 https://github.com/azlux/log2ram /opt/log2ram; fi",
			"cd /opt/log2ram && chmod +x install.sh && ./install.sh",
		),
	}}, nil
}

func buildOvsInstallSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{buildOvsInstallCommandStep()}, nil
}

func buildOvsInstallCommandStep() Step {
	return Step{
		Name: "ovs-install",
		Command: joinShell(
			"apt-get update",
			"DEBIAN_FRONTEND=noninteractive apt-get install -y openvswitch-switch openvswitch-common",
			"systemctl enable --now openvswitch-switch",
		),
	}
}

func buildOvsConfigureSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	bridgeName, err := requiredSafeTokenAny(params, "bridgeName", "name")
	if err != nil {
		return nil, err
	}
	command := fmt.Sprintf("ovs-vsctl --may-exist add-br %s", shellQuote(bridgeName))
	ports, _ := params["ports"].([]any)
	for _, raw := range ports {
		port, ok := raw.(string)
		if !ok || !isSafeToken(port) {
			return nil, fmt.Errorf("ports must contain safe interface names")
		}
		command = joinShell(command, fmt.Sprintf("ovs-vsctl --may-exist add-port %s %s", shellQuote(bridgeName), shellQuote(port)))
	}
	return []Step{{Name: "ovs-configure", Command: command}}, nil
}

func buildKsmConfigureSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	enabled := boolParam(params, "enabled")
	sleepMs := intParam(params, "sleepMs", 100)
	runValue := "0"
	if enabled {
		runValue = "1"
	}
	return []Step{{
		Name: "ksm-configure",
		Command: joinShell(
			fmt.Sprintf("printf '%s' %s > /sys/kernel/mm/ksm/run", runValue, shellQuote(runValue)),
			fmt.Sprintf("printf '%d' > /sys/kernel/mm/ksm/sleep_millisecs", sleepMs),
		),
	}}, nil
}

func buildGuestAgentEnableSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	vmID, err := requiredSafeTokenAny(params, "vmId", "targetId")
	if err != nil {
		return nil, err
	}
	return []Step{{
		Name:    "guest-agent-enable",
		Command: fmt.Sprintf("qm set %s --agent enabled=1", shellQuote(vmID)),
	}}, nil
}

func readObject(payload json.RawMessage) (map[string]any, error) {
	if len(payload) == 0 || string(payload) == "null" {
		return map[string]any{}, nil
	}
	var params map[string]any
	if err := json.Unmarshal(payload, &params); err != nil {
		return nil, fmt.Errorf("invalid command payload: %w", err)
	}
	return params, nil
}

func boolParam(params map[string]any, key string) bool {
	value, ok := params[key]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return typed == "true" || typed == "1" || typed == "yes"
	default:
		return false
	}
}

func stringParam(params map[string]any, key string, fallback string) string {
	value, ok := params[key]
	if !ok {
		return fallback
	}
	if typed, ok := value.(string); ok && strings.TrimSpace(typed) != "" {
		return strings.TrimSpace(typed)
	}
	return fallback
}

func intParam(params map[string]any, key string, fallback int) int {
	value, ok := params[key]
	if !ok {
		return fallback
	}
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	default:
		return fallback
	}
}

func requiredSafeToken(params map[string]any, key string) (string, error) {
	value := stringParam(params, key, "")
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	if !isSafeToken(value) {
		return "", fmt.Errorf("%s contains unsafe characters", key)
	}
	return value, nil
}

func requiredSafeTokenAny(params map[string]any, keys ...string) (string, error) {
	for _, key := range keys {
		value := stringParam(params, key, "")
		if value == "" {
			continue
		}
		if !isSafeToken(value) {
			return "", fmt.Errorf("%s contains unsafe characters", key)
		}
		return value, nil
	}
	return "", fmt.Errorf("%s is required", strings.Join(keys, " or "))
}

func requiredDevicePath(params map[string]any, key string) (string, error) {
	value := stringParam(params, key, "")
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	if !strings.HasPrefix(value, "/dev/") || strings.Contains(value, "..") {
		return "", fmt.Errorf("%s must be an absolute /dev path", key)
	}
	return value, nil
}

func requiredPciID(params map[string]any, key string) (string, error) {
	value := stringParam(params, key, "")
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	for _, char := range value {
		if !(char == ':' || char == '.' || char == '_' || char == '-' || char == '/' || isAlphaNum(char)) {
			return "", fmt.Errorf("%s contains unsafe characters", key)
		}
	}
	return value, nil
}

func isSafeToken(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if !(char == '.' || char == '_' || char == '-' || char == '/' || isAlphaNum(char)) {
			return false
		}
	}
	return true
}

func isAlphaNum(char rune) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')
}

func joinShell(commands ...string) string {
	filtered := make([]string, 0, len(commands))
	for _, command := range commands {
		if strings.TrimSpace(command) != "" {
			filtered = append(filtered, strings.TrimSpace(command))
		}
	}
	return strings.Join(filtered, " && ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func requireAtLeastOneStep(steps []Step, command string) ([]Step, error) {
	if len(steps) == 0 {
		return nil, fmt.Errorf("%s did not include any enabled options", command)
	}
	return steps, nil
}

func oneOf(value string, values ...string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
