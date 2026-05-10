package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
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
	return d.DispatchWithObserver(ctx, command, payload, nil)
}

func (d *Dispatcher) DispatchWithObserver(
	ctx context.Context,
	command string,
	payload json.RawMessage,
	observer func(step StepResult, stepIndex int, stepCount int),
) (result Result) {
	started := time.Now()
	result = Result{
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

	for index, step := range steps {
		stepResult := d.runner.Run(ctx, step)
		result.Steps = append(result.Steps, stepResult)
		if observer != nil {
			observer(stepResult, index, len(steps))
		}
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
	"hardening.apply":              buildHardeningApplySteps,
	"network.optimize":             buildNetworkOptimizeSteps,
	"persistent-nic-names":         buildPersistentNicNameSteps,
	"fail2ban.install":             buildFail2BanInstallSteps,
	"fail2ban.unban":               buildFail2BanUnbanSteps,
	"lynis.run":                    buildLynisRunSteps,
	"rpcbind.disable":              buildRpcbindDisableSteps,
	"smart.poll":                   buildSmartPollSteps,
	"smart.schedule":               buildSmartScheduleSteps,
	"iommu.enable":                 buildIommuEnableSteps,
	"apt.tune":                     buildAptTuneSteps,
	"agent.diagnostics":            buildAgentDiagnosticsSteps,
	"disk.format":                  buildDiskFormatSteps,
	"disk.passthrough":             buildDiskPassthroughSteps,
	"disk.import-image":            buildDiskImportImageSteps,
	"nvme.controller.add":          buildNvmeControllerAddSteps,
	"gpu.attach":                   buildGpuAttachSteps,
	"gpu.detach":                   buildGpuDetachSteps,
	"gpu.mode":                     buildGpuModeSteps,
	"nvidia.driver.install":        buildNvidiaDriverInstallSteps,
	"coral.tpu.install":            buildCoralTpuInstallSteps,
	"coral.tpu.attach":             buildCoralTpuAttachSteps,
	"sriov.configure":              buildSriovConfigureSteps,
	"lxc.mount":                    buildLxcMountSteps,
	"provisioning.apply":           buildProvisioningApplySteps,
	"community-script.run":         buildCommunityScriptRunSteps,
	"zfs.tune":                     buildZfsTuneSteps,
	"log2ram.install":              buildLog2RamInstallSteps,
	"ovs.install":                  buildOvsInstallSteps,
	"ovs.configure":                buildOvsConfigureSteps,
	"ksm.configure":                buildKsmConfigureSteps,
	"guest-agent.enable":           buildGuestAgentEnableSteps,
	"vm.create.synology-dsm":       buildSynologyDsmVmCreateSteps,
	"vm.create.zimaos":             buildZimaOsVmCreateSteps,
	"pve.upgrade":                  buildPveUpgradeSteps,
	"subscription-banner.remove":   buildSubscriptionBannerRemoveSteps,
	"subscription-banner.restore":  buildSubscriptionBannerRestoreSteps,
	"utilities.install":            buildUtilitiesInstallSteps,
	"network.verify":               buildNetworkVerifySteps,
	"network.repair":               buildNetworkRepairSteps,
	"martian.fix":                  buildMartianFixSteps,
	"xshok.conflict.detect":        buildXshokConflictDetectSteps,
	"nested-cloud.install-proxmox": buildNestedCloudInstallProxmoxSteps,
	"nested-cloud.configure-nat":   buildNestedCloudConfigureNatSteps,
	"nested-cloud.verify-ready":    buildNestedCloudVerifyReadySteps,
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

func buildRpcbindDisableSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name:    "rpcbind-disable",
		Command: "systemctl disable --now rpcbind rpcbind.socket || true",
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

func buildSmartScheduleSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	device, err := requiredDevicePath(params, "device")
	if err != nil {
		return nil, err
	}
	testType, err := requiredSafeToken(params, "testType")
	if err != nil {
		return nil, err
	}
	schedule, err := requiredSafeToken(params, "schedule")
	if err != nil {
		return nil, err
	}

	testCode := map[string]string{
		"short":      "S",
		"long":       "L",
		"conveyance": "C",
	}[testType]
	if testCode == "" {
		return nil, fmt.Errorf("testType must be short, long, or conveyance")
	}

	scheduleExpr := map[string]string{
		"daily":  fmt.Sprintf("%s/../.././03", testCode),
		"weekly": fmt.Sprintf("%s/../../7/03", testCode),
	}[schedule]
	if scheduleExpr == "" {
		return nil, fmt.Errorf("schedule must be daily or weekly")
	}

	entry := fmt.Sprintf("%s -a -s %s", device, scheduleExpr)
	return []Step{{
		Name: "smart-schedule",
		Command: joinShell(
			"apt-get update",
			"DEBIAN_FRONTEND=noninteractive apt-get install -y smartmontools",
			"touch /etc/smartd.conf",
			fmt.Sprintf("grep -v %s /etc/smartd.conf > /etc/smartd.conf.pmx-cloud || true", shellQuote("^"+device+" ")),
			fmt.Sprintf("printf '%%s\n' %s >> /etc/smartd.conf.pmx-cloud", shellQuote(entry)),
			"mv /etc/smartd.conf.pmx-cloud /etc/smartd.conf",
			"systemctl enable --now smartmontools || systemctl enable --now smartd || true",
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

func buildAptTuneSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name: "apt-tune",
		Command: joinShell(
			"printf '%s\n' 'Acquire::Queue-Mode \"access\";' 'Acquire::Retries \"3\";' 'Acquire::http::Pipeline-Depth \"5\";' 'APT::Get::Show-Upgraded \"true\";' > /etc/apt/apt.conf.d/99-pmx-cloud-performance",
			"printf '%s\n' 'Acquire::Languages \"none\";' > /etc/apt/apt.conf.d/99-pmx-cloud-no-languages",
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

func buildDiskImportImageSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	vmID, err := requiredSafeTokenAny(params, "vmId", "targetId")
	if err != nil {
		return nil, err
	}
	source := stringParam(params, "source", stringParam(params, "localPath", ""))
	imageURL := stringParam(params, "imageUrl", "")
	if source == "" && imageURL == "" {
		return nil, fmt.Errorf("source, localPath, or imageUrl is required")
	}
	if source != "" {
		if _, err := requiredAbsolutePathValue(source, "source"); err != nil {
			return nil, err
		}
	}
	targetStorage, err := requiredSafeToken(params, "targetStorage")
	if err != nil {
		return nil, err
	}
	format := stringParam(params, "format", "qcow2")
	if !oneOf(format, "img", "qcow2", "vmdk", "raw") {
		return nil, fmt.Errorf("format must be img, qcow2, vmdk, or raw")
	}

	importSource := source
	downloadCommand := ""
	if imageURL != "" {
		if !strings.HasPrefix(imageURL, "https://") && !strings.HasPrefix(imageURL, "http://") {
			return nil, fmt.Errorf("imageUrl must be http or https")
		}
		importSource = fmt.Sprintf("/var/lib/vz/template/imports/pmxcloud-%s.%s", vmID, format)
		downloadCommand = joinShell(
			"mkdir -p /var/lib/vz/template/imports",
			fmt.Sprintf("curl -fL %s -o %s", shellQuote(imageURL), shellQuote(importSource)),
		)
	}

	return []Step{{
		Name: "disk-import-image",
		Command: joinShell(
			downloadCommand,
			fmt.Sprintf("test -f %s", shellQuote(importSource)),
			fmt.Sprintf("qm importdisk %s %s %s --format %s", shellQuote(vmID), shellQuote(importSource), shellQuote(targetStorage), shellQuote(format)),
		),
	}}, nil
}

func buildNvmeControllerAddSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	vmID, err := requiredSafeTokenAny(params, "vmId", "targetId")
	if err != nil {
		return nil, err
	}
	slot := stringParam(params, "slot", "args")
	if !isSafeToken(slot) {
		return nil, fmt.Errorf("slot contains unsafe characters")
	}

	return []Step{{
		Name: "nvme-controller-add",
		Command: joinShell(
			fmt.Sprintf("existing=$(qm config %s | awk -F': ' '/^args:/{print $2}')", shellQuote(vmID)),
			fmt.Sprintf("qm set %s --%s \"$existing -device nvme,id=pmxnvme0,serial=pmxcloud\"", shellQuote(vmID), slot),
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

func buildGpuModeSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	pciID, err := requiredPciID(params, "pciId")
	if err != nil {
		return nil, err
	}
	mode, err := requiredSafeToken(params, "mode")
	if err != nil {
		return nil, err
	}
	if !oneOf(mode, "host", "passthrough", "sriov") {
		return nil, fmt.Errorf("mode must be host, passthrough, or sriov")
	}

	if mode == "host" {
		return []Step{{
			Name: "gpu-mode",
			Command: joinShell(
				fmt.Sprintf("vendor_device=$(lspci -n -s %s | awk '{print $3}')", shellQuote(pciID)),
				"test -n \"$vendor_device\"",
				"sed -i \"/$vendor_device/d\" /etc/modprobe.d/vfio.conf 2>/dev/null || true",
				"update-initramfs -u -k all || true",
			),
		}}, nil
	}

	return []Step{{
		Name: "gpu-mode",
		Command: joinShell(
			fmt.Sprintf("vendor_device=$(lspci -n -s %s | awk '{print $3}')", shellQuote(pciID)),
			"test -n \"$vendor_device\"",
			"printf '%s\n' vfio vfio_iommu_type1 vfio_pci vfio_virqfd > /etc/modules-load.d/vfio.conf",
			"printf 'options vfio-pci ids=%s\n' \"$vendor_device\" > /etc/modprobe.d/vfio.conf",
			"update-initramfs -u -k all || true",
		),
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

const nestedCloudInstallResultMarker = "PMX_NESTED_CLOUD_INSTALL_RESULT"

type nestedCloudCommandParams struct {
	outerProxmoxVmid int
	privateCidr      string
	gateway          string
	dnsServers       []string
	adminURL         string
	resultMarker     string
}

func buildNestedCloudInstallProxmoxSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readNestedCloudCommandParams(payload, true, false)
	if err != nil {
		return nil, err
	}

	return []Step{
		nestedCloudGuestPingStep(params.outerProxmoxVmid),
		{
			Name:    "nested-cloud-install-proxmox",
			Command: nestedCloudGuestExecCommand(params.outerProxmoxVmid, nestedCloudInstallProxmoxScript(params), 1800),
		},
	}, nil
}

func buildNestedCloudConfigureNatSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readNestedCloudCommandParams(payload, true, false)
	if err != nil {
		return nil, err
	}

	return []Step{
		nestedCloudGuestPingStep(params.outerProxmoxVmid),
		{
			Name:    "nested-cloud-configure-nat",
			Command: nestedCloudGuestExecCommand(params.outerProxmoxVmid, nestedCloudConfigureNatScript(params), 900),
		},
	}, nil
}

func buildNestedCloudVerifyReadySteps(payload json.RawMessage) ([]Step, error) {
	params, err := readNestedCloudCommandParams(payload, false, true)
	if err != nil {
		return nil, err
	}

	return []Step{
		nestedCloudGuestPingStep(params.outerProxmoxVmid),
		{
			Name:    "nested-cloud-verify-ready",
			Command: nestedCloudGuestExecCommand(params.outerProxmoxVmid, nestedCloudVerifyReadyScript(params), 120),
		},
	}, nil
}

func readNestedCloudCommandParams(
	payload json.RawMessage,
	requireNetwork bool,
	requireAdminURL bool,
) (nestedCloudCommandParams, error) {
	params, err := readObject(payload)
	if err != nil {
		return nestedCloudCommandParams{}, err
	}

	vmid := intParam(params, "outerProxmoxVmid", intParam(params, "vmid", 0))
	if vmid <= 0 {
		return nestedCloudCommandParams{}, fmt.Errorf("outerProxmoxVmid is required")
	}

	if nestedCloudID := stringParam(params, "nestedCloudId", ""); nestedCloudID != "" && !isSafeToken(nestedCloudID) {
		return nestedCloudCommandParams{}, fmt.Errorf("nestedCloudId contains unsafe characters")
	}
	if outerVMID := stringParam(params, "outerVmId", ""); outerVMID != "" && !isSafeToken(outerVMID) {
		return nestedCloudCommandParams{}, fmt.Errorf("outerVmId contains unsafe characters")
	}

	result := nestedCloudCommandParams{
		outerProxmoxVmid: vmid,
		dnsServers:       []string{"1.1.1.1", "8.8.8.8"},
		resultMarker:     stringParam(params, "resultMarker", nestedCloudInstallResultMarker),
	}
	if !isSafeToken(result.resultMarker) {
		return nestedCloudCommandParams{}, fmt.Errorf("resultMarker contains unsafe characters")
	}

	if requireNetwork {
		privateCidr := stringParam(params, "privateCidr", "")
		if err := validateIPv4Cidr(privateCidr, "privateCidr"); err != nil {
			return nestedCloudCommandParams{}, err
		}
		gateway := stringParam(params, "gateway", "")
		if err := validateIPv4Address(gateway, "gateway"); err != nil {
			return nestedCloudCommandParams{}, err
		}
		dnsServers := stringSliceParam(params, "dnsServers")
		if len(dnsServers) > 0 {
			for _, server := range dnsServers {
				if err := validateIPv4Address(server, "dnsServers"); err != nil {
					return nestedCloudCommandParams{}, err
				}
			}
			result.dnsServers = dnsServers
		}
		result.privateCidr = privateCidr
		result.gateway = gateway
	}

	if requireAdminURL {
		adminURL := stringParam(params, "adminUrl", "")
		if adminURL == "" || strings.ContainsAny(adminURL, "\n\r") {
			return nestedCloudCommandParams{}, fmt.Errorf("adminUrl is required")
		}
		result.adminURL = adminURL
	}

	return result, nil
}

func nestedCloudGuestPingStep(vmid int) Step {
	return Step{
		Name:    "nested-cloud-guest-agent-ready",
		Command: fmt.Sprintf("qm guest ping %s", shellQuote(strconv.Itoa(vmid))),
	}
}

func nestedCloudGuestExecCommand(vmid int, script string, timeoutSeconds int) string {
	return fmt.Sprintf(
		"qm guest exec %s --timeout %d --synchronous 1 -- bash -lc %s",
		shellQuote(strconv.Itoa(vmid)),
		timeoutSeconds,
		shellQuote(script),
	)
}

func nestedCloudInstallProxmoxScript(params nestedCloudCommandParams) string {
	return joinScript(
		"set -euo pipefail",
		"export DEBIAN_FRONTEND=noninteractive",
		shellAssign("PMX_GATEWAY", params.gateway),
		shellAssign("PMX_RESULT_MARKER", params.resultMarker),
		"PMX_TOKEN_NAME='pmx-cloud'",
		"PMX_TOKEN_ID='root@pam!pmx-cloud'",
		"if ! test -f /etc/debian_version; then echo 'nested cloud bootstrap requires a Debian-based guest' >&2; exit 1; fi",
		"admin_ip=\"$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i==\"src\") {print $(i+1); exit}}')\"",
		"if [ -z \"${admin_ip:-}\" ]; then admin_ip=\"$(hostname -I 2>/dev/null | awk '{print $1}')\"; fi",
		"if [ -z \"${admin_ip:-}\" ]; then admin_ip=\"$PMX_GATEWAY\"; fi",
		"short_host=\"$(hostname -s 2>/dev/null || hostname)\"",
		"fqdn=\"$(hostname -f 2>/dev/null || hostname)\"",
		"if ! grep -q \" $short_host\" /etc/hosts 2>/dev/null; then printf '%s %s %s\\n' \"$admin_ip\" \"$fqdn\" \"$short_host\" >> /etc/hosts; fi",
		"codename=\"$(. /etc/os-release && printf '%s' \"${VERSION_CODENAME:-bookworm}\")\"",
		"if ! command -v pveversion >/dev/null 2>&1; then",
		"  apt-get update",
		"  DEBIAN_FRONTEND=noninteractive apt-get install -y curl gnupg ca-certificates debconf-utils",
		"  curl -fsSL \"https://enterprise.proxmox.com/debian/proxmox-release-${codename}.gpg\" -o \"/etc/apt/trusted.gpg.d/proxmox-release-${codename}.gpg\" || true",
		"  printf 'deb http://download.proxmox.com/debian/pve %s pve-no-subscription\\n' \"$codename\" > /etc/apt/sources.list.d/pve-install-repo.list",
		"  printf 'postfix postfix/mailname string %s\\npostfix postfix/main_mailer_type string Local only\\n' \"$fqdn\" | debconf-set-selections || true",
		"  apt-get update",
		"  DEBIAN_FRONTEND=noninteractive apt-get install -y proxmox-ve postfix open-iscsi chrony qemu-guest-agent",
		"fi",
		"systemctl enable --now pvedaemon pveproxy pvestatd qemu-guest-agent || true",
		"pveum user token remove root@pam \"$PMX_TOKEN_NAME\" >/dev/null 2>&1 || true",
		"token_json=\"$(pveum user token add root@pam \"$PMX_TOKEN_NAME\" --privsep 0 --output-format json)\"",
		"token_secret=\"$(printf '%s' \"$token_json\" | sed -n 's/.*\"value\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p')\"",
		"if [ -z \"${token_secret:-}\" ]; then echo 'failed to create Proxmox API token' >&2; exit 1; fi",
		"printf '%s={\"adminUrl\":\"https://%s:8006\",\"apiTokenId\":\"%s\",\"apiTokenSecret\":\"%s\"}\\n' \"$PMX_RESULT_MARKER\" \"$admin_ip\" \"$PMX_TOKEN_ID\" \"$token_secret\"",
	)
}

func nestedCloudConfigureNatScript(params nestedCloudCommandParams) string {
	return joinScript(
		"set -euo pipefail",
		"export DEBIAN_FRONTEND=noninteractive",
		shellAssign("PMX_PRIVATE_CIDR", params.privateCidr),
		shellAssign("PMX_GATEWAY", params.gateway),
		shellAssign("PMX_DNS_SERVERS", strings.Join(params.dnsServers, ",")),
		"prefix=\"${PMX_PRIVATE_CIDR#*/}\"",
		"gateway_with_prefix=\"${PMX_GATEWAY}/${prefix}\"",
		"wan_if=\"$(ip -4 route list default | awk '{print $5; exit}')\"",
		"if [ -z \"${wan_if:-}\" ]; then echo 'default route interface not found' >&2; exit 1; fi",
		"apt-get update",
		"DEBIAN_FRONTEND=noninteractive apt-get install -y ifupdown2 bridge-utils iptables-persistent dnsmasq",
		"printf '%s\\n' 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-pmx-nested-cloud-nat.conf",
		"sysctl -w net.ipv4.ip_forward=1",
		"mkdir -p /etc/network/interfaces.d",
		"cat > /etc/network/interfaces.d/pmx-nested-cloud.cfg <<EOF\n"+
			"auto vmbr0\n"+
			"iface vmbr0 inet static\n"+
			"    address ${gateway_with_prefix}\n"+
			"    bridge-ports none\n"+
			"    bridge-stp off\n"+
			"    bridge-fd 0\n"+
			"    post-up iptables -t nat -C POSTROUTING -s ${PMX_PRIVATE_CIDR} -o ${wan_if} -j MASQUERADE || iptables -t nat -A POSTROUTING -s ${PMX_PRIVATE_CIDR} -o ${wan_if} -j MASQUERADE\n"+
			"    post-down iptables -t nat -D POSTROUTING -s ${PMX_PRIVATE_CIDR} -o ${wan_if} -j MASQUERADE || true\n"+
			"EOF",
		"if command -v ifreload >/dev/null 2>&1; then ifreload -a; else systemctl restart networking || true; fi",
		"iptables -t nat -C POSTROUTING -s \"$PMX_PRIVATE_CIDR\" -o \"$wan_if\" -j MASQUERADE || iptables -t nat -A POSTROUTING -s \"$PMX_PRIVATE_CIDR\" -o \"$wan_if\" -j MASQUERADE",
		"netfilter-persistent save || true",
		"dhcp_base=\"$(printf '%s\\n' \"$PMX_GATEWAY\" | awk -F. '{print $1\".\"$2\".\"$3}')\"",
		"cat > /etc/dnsmasq.d/pmx-nested-cloud.conf <<EOF\n"+
			"interface=vmbr0\n"+
			"bind-interfaces\n"+
			"dhcp-range=${dhcp_base}.100,${dhcp_base}.199,12h\n"+
			"dhcp-option=3,${PMX_GATEWAY}\n"+
			"dhcp-option=6,${PMX_DNS_SERVERS}\n"+
			"EOF",
		"systemctl enable --now dnsmasq",
		"systemctl restart dnsmasq",
	)
}

func nestedCloudVerifyReadyScript(params nestedCloudCommandParams) string {
	return joinScript(
		"set -euo pipefail",
		shellAssign("PMX_ADMIN_URL", params.adminURL),
		"pveversion",
		"systemctl is-active --quiet pveproxy",
		"curl -kfsS https://127.0.0.1:8006/api2/json/version >/dev/null",
		"printf 'nested cloud ready at %s\\n' \"$PMX_ADMIN_URL\"",
	)
}

func validateIPv4Cidr(value string, key string) error {
	if value == "" {
		return fmt.Errorf("%s is required", key)
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("%s must be an IPv4 CIDR", key)
	}
	return nil
}

func validateIPv4Address(value string, key string) error {
	if value == "" {
		return fmt.Errorf("%s is required", key)
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() {
		return fmt.Errorf("%s must be an IPv4 address", key)
	}
	return nil
}

func shellAssign(name string, value string) string {
	return fmt.Sprintf("%s=%s", name, shellQuote(value))
}

func joinScript(lines ...string) string {
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			filtered = append(filtered, line)
		}
	}
	return strings.Join(filtered, "\n")
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

func buildCoralTpuInstallSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	tpuInterface := stringParam(params, "interface", "usb")
	if !oneOf(tpuInterface, "usb", "m2") {
		return nil, fmt.Errorf("interface must be usb or m2")
	}
	packages := "gasket-dkms libedgetpu1-std"
	if tpuInterface == "m2" {
		packages = "gasket-dkms libedgetpu1-max"
	}

	return []Step{{
		Name: "coral-tpu-install",
		Command: joinShell(
			"printf '%s\n' 'deb https://packages.cloud.google.com/apt coral-edgetpu-stable main' > /etc/apt/sources.list.d/coral-edgetpu.list",
			"curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/coral-edgetpu.gpg || true",
			"apt-get update",
			fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get install -y %s", packages),
			"modprobe apex || true",
		),
	}}, nil
}

func buildCoralTpuAttachSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	ctID, err := requiredSafeTokenAny(params, "ctId", "containerId", "targetId")
	if err != nil {
		return nil, err
	}
	device, err := requiredDevicePath(params, "device")
	if err != nil {
		return nil, err
	}
	mp := stringParam(params, "mountPath", device)
	if _, err := requiredAbsolutePathValue(mp, "mountPath"); err != nil {
		return nil, err
	}

	return []Step{{
		Name: "coral-tpu-attach",
		Command: joinShell(
			fmt.Sprintf("test -e %s", shellQuote(device)),
			fmt.Sprintf(
				"printf '%%s\n' %s %s >> /etc/pve/lxc/%s.conf",
				shellQuote("lxc.cgroup2.devices.allow: c 189:* rwm"),
				shellQuote(fmt.Sprintf("lxc.mount.entry: %s %s none bind,optional,create=file 0 0", device, strings.TrimPrefix(mp, "/"))),
				shellQuote(ctID),
			),
		),
	}}, nil
}

func buildSriovConfigureSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	pfPciID, err := requiredPciID(params, "pfPciId")
	if err != nil {
		return nil, err
	}
	count := intParam(params, "count", -1)
	if count < 0 || count > 256 {
		return nil, fmt.Errorf("count must be between 0 and 256")
	}
	sysfsPath := fmt.Sprintf("/sys/bus/pci/devices/%s/sriov_numvfs", pfPciID)

	return []Step{{
		Name: "sriov-configure",
		Command: joinShell(
			fmt.Sprintf("test -w %s", shellQuote(sysfsPath)),
			fmt.Sprintf("printf '0' > %s", shellQuote(sysfsPath)),
			fmt.Sprintf("printf '%d' > %s", count, shellQuote(sysfsPath)),
		),
	}}, nil
}

func buildLxcMountSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	ctID, err := requiredSafeTokenAny(params, "ctId", "containerId", "targetId")
	if err != nil {
		return nil, err
	}
	hostPath, err := requiredAbsolutePath(params, "hostPath")
	if err != nil {
		return nil, err
	}
	containerPath := stringParam(params, "containerPath", stringParam(params, "mountPath", ""))
	if _, err := requiredAbsolutePathValue(containerPath, "containerPath"); err != nil {
		return nil, err
	}
	slot := stringParam(params, "slot", "mp0")
	if !isSafeToken(slot) {
		return nil, fmt.Errorf("slot contains unsafe characters")
	}
	options := fmt.Sprintf("%s,mp=%s", hostPath, containerPath)
	if boolParam(params, "readOnly") {
		options += ",ro=1"
	}

	return []Step{{
		Name: "lxc-mount",
		Command: joinShell(
			fmt.Sprintf("mkdir -p %s", shellQuote(hostPath)),
			fmt.Sprintf("pct set %s -%s %s", shellQuote(ctID), slot, shellQuote(options)),
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

func buildSynologyDsmVmCreateSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	vmID, err := requiredSafeTokenAny(params, "vmId", "targetId")
	if err != nil {
		return nil, err
	}
	name, err := requiredSafeToken(params, "name")
	if err != nil {
		return nil, err
	}
	loaderURL := stringParam(params, "loaderUrl", "")
	if loaderURL == "" || strings.ContainsAny(loaderURL, "\n\r") {
		return nil, fmt.Errorf("loaderUrl is required")
	}
	storage := stringParam(params, "storage", "local-lvm")
	bridge := stringParam(params, "bridge", "vmbr0")
	cores := intParam(params, "cores", 2)
	memory := intParam(params, "memory", 4096)
	loaderPath := fmt.Sprintf("/var/lib/vz/template/iso/pmx-dsm-loader-%s.img", vmID)
	commands := []string{
		"mkdir -p /var/lib/vz/template/iso",
		fmt.Sprintf("curl -fsSL %s -o %s", shellQuote(loaderURL), shellQuote(loaderPath)),
		fmt.Sprintf("qm create %s --name %s --memory %d --cores %d --net0 %s --scsihw virtio-scsi-single", shellQuote(vmID), shellQuote(name), memory, cores, shellQuote("virtio,bridge="+bridge)),
		fmt.Sprintf("qm importdisk %s %s %s", shellQuote(vmID), shellQuote(loaderPath), shellQuote(storage)),
		fmt.Sprintf("qm set %s --scsi0 %s --boot order=scsi0 --agent enabled=1", shellQuote(vmID), shellQuote(storage+":vm-"+vmID+"-disk-0")),
	}
	for index, diskPath := range stringSliceParam(params, "dataDisks") {
		device, err := requiredAbsolutePathValue(diskPath, "dataDisks")
		if err != nil {
			return nil, err
		}
		commands = append(commands, fmt.Sprintf("qm set %s --scsi%d %s", shellQuote(vmID), index+1, shellQuote(device)))
	}
	return []Step{{
		Name:    "vm-create-synology-dsm",
		Command: joinShell(commands...),
	}}, nil
}

func buildZimaOsVmCreateSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	vmID, err := requiredSafeTokenAny(params, "vmId", "targetId")
	if err != nil {
		return nil, err
	}
	name, err := requiredSafeToken(params, "name")
	if err != nil {
		return nil, err
	}
	imageURL := stringParam(params, "imageUrl", "")
	if imageURL == "" || strings.ContainsAny(imageURL, "\n\r") {
		return nil, fmt.Errorf("imageUrl is required")
	}
	storage := stringParam(params, "storage", "local-lvm")
	bridge := stringParam(params, "bridge", "vmbr0")
	cores := intParam(params, "cores", 2)
	memory := intParam(params, "memory", 4096)
	imagePath := fmt.Sprintf("/var/lib/vz/template/iso/pmx-zimaos-%s.img", vmID)
	return []Step{{
		Name: "vm-create-zimaos",
		Command: joinShell(
			"mkdir -p /var/lib/vz/template/iso",
			fmt.Sprintf("curl -fsSL %s -o %s", shellQuote(imageURL), shellQuote(imagePath)),
			fmt.Sprintf("qm create %s --name %s --memory %d --cores %d --net0 %s --scsihw virtio-scsi-single", shellQuote(vmID), shellQuote(name), memory, cores, shellQuote("virtio,bridge="+bridge)),
			fmt.Sprintf("qm importdisk %s %s %s", shellQuote(vmID), shellQuote(imagePath), shellQuote(storage)),
			fmt.Sprintf("qm set %s --scsi0 %s --boot order=scsi0 --agent enabled=1", shellQuote(vmID), shellQuote(storage+":vm-"+vmID+"-disk-0")),
		),
	}}, nil
}

func buildPveUpgradeSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	targetVersion, err := requiredSafeToken(params, "targetVersion")
	if err != nil {
		return nil, err
	}
	mode, err := requiredSafeToken(params, "mode")
	if err != nil {
		return nil, err
	}
	if !oneOf(mode, "automatic", "check-only", "interactive") {
		return nil, fmt.Errorf("mode must be automatic, check-only, or interactive")
	}

	checker := "if command -v pve8to9 >/dev/null 2>&1; then pve8to9 --full; else pve8to9; fi"
	if targetVersion != "9" {
		checker = "pveversion && apt-get -s dist-upgrade"
	}
	if mode == "check-only" {
		return []Step{{
			Name:    "pve-upgrade-check",
			Command: checker,
		}}, nil
	}

	return []Step{{
		Name: "pve-upgrade",
		Command: joinShell(
			checker,
			"apt-get update",
			"DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y",
			"pveversion",
		),
	}}, nil
}

func buildSubscriptionBannerRemoveSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name: "subscription-banner-remove",
		Command: joinShell(
			"target=/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js",
			"backup_dir=/root/.pmxcloud/backups",
			"test -f \"$target\"",
			"mkdir -p \"$backup_dir\"",
			"cp -a \"$target\" \"$backup_dir/proxmoxlib.$(date -u +%Y%m%dT%H%M%SZ).js\"",
			"perl -0pi -e \"s/Ext.Msg.show\\(\\{\\s*title: gettext\\('No valid subscription'\\).*?\\}\\);/void(0);/s\" \"$target\" || true",
			"systemctl restart pveproxy || true",
		),
	}}, nil
}

func buildSubscriptionBannerRestoreSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name: "subscription-banner-restore",
		Command: joinShell(
			"target=/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js",
			"latest=$(ls -1t /root/.pmxcloud/backups/proxmoxlib.*.js 2>/dev/null | head -n1)",
			"test -n \"$latest\"",
			"cp -a \"$latest\" \"$target\"",
			"systemctl restart pveproxy || true",
		),
	}}, nil
}

func buildUtilitiesInstallSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	rawPackages, ok := params["packages"].([]any)
	if !ok || len(rawPackages) == 0 {
		return nil, fmt.Errorf("packages must be a non-empty array")
	}

	allowed := map[string]bool{
		"axel": true, "htop": true, "btop": true, "iftop": true, "iotop": true,
		"iperf3": true, "tmux": true, "dialog": true, "msr-tools": true,
		"net-tools": true, "libguestfs-tools": true, "s-tui": true,
		"intel-gpu-tools": true,
	}
	packages := make([]string, 0, len(rawPackages))
	seen := map[string]bool{}
	for _, raw := range rawPackages {
		packageName, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("packages must contain strings")
		}
		packageName = strings.TrimSpace(packageName)
		if !isSafeToken(packageName) || !allowed[packageName] {
			return nil, fmt.Errorf("unsupported utility package %q", packageName)
		}
		if !seen[packageName] {
			packages = append(packages, packageName)
			seen[packageName] = true
		}
	}

	quotedPackages := make([]string, 0, len(packages))
	for _, packageName := range packages {
		quotedPackages = append(quotedPackages, shellQuote(packageName))
	}

	return []Step{{
		Name: "utilities-install",
		Command: joinShell(
			"apt-get update",
			fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get install -y %s", strings.Join(quotedPackages, " ")),
		),
	}}, nil
}

func buildAgentDiagnosticsSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{
		{
			Name: "host-identity",
			Command: joinShell(
				"{ hostnamectl 2>/dev/null || hostname; }",
				"uname -a",
				"if command -v pveversion >/dev/null 2>&1; then pveversion; else printf '%s\n' 'pveversion=missing'; fi",
			),
		},
		{
			Name: "proxmox-readiness",
			Command: joinShell(
				"if [ -d /etc/pve ]; then ls -ld /etc/pve; else printf '%s\n' '/etc/pve=missing'; fi",
				"if command -v pvecm >/dev/null 2>&1; then pvecm status || true; else printf '%s\n' 'pvecm=missing'; fi",
				"if command -v pvesh >/dev/null 2>&1; then pvesh get /nodes --output-format json || true; else printf '%s\n' 'pvesh=missing'; fi",
			),
		},
		{
			Name:    "runtime-tools",
			Command: "for tool in qm pct pvesh pveversion pvecm wg ip systemctl smartctl; do if command -v \"$tool\" >/dev/null 2>&1; then printf '%s=present\\n' \"$tool\"; else printf '%s=missing\\n' \"$tool\"; fi; done",
		},
		{
			Name: "network-summary",
			Command: joinShell(
				"ip -br addr || true",
				"ip route || true",
				"if command -v resolvectl >/dev/null 2>&1; then resolvectl status || true; fi",
			),
		},
	}, nil
}

func buildNetworkVerifySteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name: "network-verify",
		Command: joinShell(
			"ip -br addr",
			"ip route",
			"bridge link || true",
			"if command -v ifquery >/dev/null 2>&1; then ifquery --list; fi",
		),
	}}, nil
}

func buildNetworkRepairSteps(payload json.RawMessage) ([]Step, error) {
	params, err := readObject(payload)
	if err != nil {
		return nil, err
	}
	commands := []string{
		"systemctl restart systemd-networkd || true",
		"if command -v ifreload >/dev/null 2>&1; then ifreload -a; else systemctl restart networking || true; fi",
	}
	if boolParam(params, "restartOpenVSwitch") {
		commands = append(commands, "systemctl restart openvswitch-switch || true")
	}

	return []Step{{
		Name:    "network-repair",
		Command: joinShell(commands...),
	}}, nil
}

func buildMartianFixSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name: "martian-source-fix",
		Command: joinShell(
			"printf '%s\n' 'net.ipv4.conf.all.log_martians=0' 'net.ipv4.conf.default.log_martians=0' 'net.ipv4.conf.all.rp_filter=2' 'net.ipv4.conf.default.rp_filter=2' > /etc/sysctl.d/99-pmx-cloud-martian.conf",
			"sysctl --system",
		),
	}}, nil
}

func buildXshokConflictDetectSteps(_ json.RawMessage) ([]Step, error) {
	return []Step{{
		Name: "xshok-conflict-detect",
		Command: joinShell(
			"set -u",
			"paths='/etc/sysctl.d/99-proxmox.conf /etc/motd /etc/motd.d /root/.bashrc /root/.profile'",
			"matches=''",
			"for path in $paths; do if [ -e \"$path\" ] && grep -RIlE 'xshok|proxmox-ve-post-install|PVESMART|Proxmox VE Post Install' \"$path\" 2>/dev/null; then matches=\"$matches $path\"; fi; done",
			"if [ -n \"$matches\" ]; then printf '%s\\n' 'xshok-conflict-detected' $matches; else printf '%s\\n' 'xshok-conflict-clear'; fi",
		),
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

func stringSliceParam(params map[string]any, key string) []string {
	value, ok := params[key]
	if !ok {
		return nil
	}
	rawItems, ok := value.([]any)
	if !ok {
		return nil
	}
	items := make([]string, 0, len(rawItems))
	for _, raw := range rawItems {
		if item, ok := raw.(string); ok && strings.TrimSpace(item) != "" {
			items = append(items, strings.TrimSpace(item))
		}
	}
	return items
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

func requiredAbsolutePath(params map[string]any, key string) (string, error) {
	return requiredAbsolutePathValue(stringParam(params, key, ""), key)
}

func requiredAbsolutePathValue(value string, key string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	if !strings.HasPrefix(value, "/") || strings.Contains(value, "..") || strings.ContainsAny(value, "\n\r") {
		return "", fmt.Errorf("%s must be an absolute path", key)
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
