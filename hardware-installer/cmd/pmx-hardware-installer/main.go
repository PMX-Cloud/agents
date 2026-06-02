/*
Command pmx-hardware-installer executes one signed, one-shot hardware job.

Flow:
 1. Load config and run optional preflight checks.
 2. Read a single signed envelope from stdin (sealed memfd from pmx-core).
 3. Verify signature + audience + host fingerprint.
 4. Dispatch one privileged hardware command.
 5. Emit JSON result to stdout, append audit, and exit.
*/
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pmx-cloud/agents/hardware-installer/internal/apt"
	"github.com/pmx-cloud/agents/hardware-installer/internal/communityscript"
	hwcfg "github.com/pmx-cloud/agents/hardware-installer/internal/config"
	"github.com/pmx-cloud/agents/hardware-installer/internal/coral"
	"github.com/pmx-cloud/agents/hardware-installer/internal/gpu"
	"github.com/pmx-cloud/agents/hardware-installer/internal/iommu"
	"github.com/pmx-cloud/agents/hardware-installer/internal/kernel"
	"github.com/pmx-cloud/agents/hardware-installer/internal/ksm"
	"github.com/pmx-cloud/agents/hardware-installer/internal/nvidia"
	"github.com/pmx-cloud/agents/hardware-installer/internal/sriov"
	"github.com/pmx-cloud/agents/hardware-installer/internal/upgrade"
	"github.com/pmx-cloud/agents/hardware-installer/internal/utilities"
	"github.com/pmx-cloud/agents/hardware-installer/internal/xshok"
	"github.com/pmx-cloud/agents/shared/audit"
	envpkg "github.com/pmx-cloud/agents/shared/envelope"
	"github.com/pmx-cloud/agents/shared/preflight"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

const (
	agentClass         = "pmx-hardware-installer"
	defaultOutputLimit = int64(10 * 1024 * 1024)
)

func main() {
	var (
		configPath  = flag.String("config", "/etc/pmx-cloud/pmx-hardware-installer.conf", "path to config")
		isPreflight = flag.Bool("preflight", false, "validate config and exit")
		isVersion   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	log := slog.Default()
	if *isVersion {
		fmt.Printf("pmx-hardware-installer version %s commit %s built %s\n", Version, Commit, BuildDate)
		os.Exit(0)
	}

	cfg, err := hwcfg.Load(*configPath)
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	checks := preflight.StandardChecks(agentClass, *configPath,
		cfg.Identity.Cert, cfg.Identity.Key, cfg.Keyset.Path, nil)
	for _, path := range []string{
		cfg.Paths.AptGet,
		cfg.Paths.SystemdRun,
		cfg.Paths.Systemctl,
		cfg.Paths.Modprobe,
	} {
		binPath := path
		name := "binary-readable:" + filepath.Base(path)
		checks = append(checks, preflight.Check{
			Name: name,
			Run: func(ctx context.Context) error {
				_, err := os.Stat(binPath)
				return err
			},
		})
	}
	checks = append(checks, preflight.Check{
		Name: "release-key-readable",
		Run: func(ctx context.Context) error {
			_, err := os.Stat(cfg.Files.CommunityReleaseKeyPath)
			return err
		},
	})

	if *isPreflight {
		os.Exit(preflight.Run(checks))
	}

	if err := run(cfg, log); err != nil {
		log.Error("pmx-hardware-installer failed", "err", err)
		os.Exit(1)
	}
}

func run(cfg *hwcfg.Config, log *slog.Logger) error {
	start := time.Now()
	auditLog, err := audit.Open("/var/log/pmx-cloud/pmx-hardware-installer.audit.log")
	if err != nil {
		auditLog, _ = audit.Open("/tmp/pmx-hardware-installer.audit.log")
	}
	if auditLog != nil {
		defer auditLog.Close()
	}

	env, err := readAndVerifyEnvelope(cfg)
	if err != nil {
		jobID := "unknown"
		command := "unknown"
		if env != nil {
			jobID = env.JobID
			command = env.Command
		}
		log.Error("envelope verification failed", "PMX_REJECT_REASON", classifyReject(err), "err", err)
		appendAudit(auditLog, audit.Entry{
			Timestamp:  time.Now(),
			JobID:      jobID,
			Command:    command,
			Step:       "reject:" + classifyReject(err),
			Exit:       1,
			DurationMs: time.Since(start).Milliseconds(),
		})
		return err
	}

	params := env.Params
	if params == nil {
		params = map[string]any{}
	}

	ctx := context.Background()
	stepFn := func(step string) {
		log.Info("hardware step", "job_id", env.JobID, "command", env.Command, "step", step)
	}

	result, dispatchErr := dispatch(ctx, cfg, env.Command, params, stepFn)
	if result != nil {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			log.Warn("write result failed", "err", err)
		}
	}

	exit := 0
	if dispatchErr != nil {
		exit = 1
	}
	appendAudit(auditLog, audit.Entry{
		Timestamp:  time.Now(),
		JobID:      env.JobID,
		Command:    env.Command,
		Step:       "complete",
		Exit:       exit,
		DurationMs: time.Since(start).Milliseconds(),
	})
	return dispatchErr
}

func dispatch(ctx context.Context, cfg *hwcfg.Config, command string, params map[string]any, stepFn func(string)) (any, error) {
	switch command {
	case "iommu.enable":
		return iommu.Enable(ctx, iommu.Params{
			CPUInfoPath: cfg.Files.CPUInfoPath,
			GrubPath:    cfg.Files.GrubDefaultPath,
			UpdateGrub:  cfg.Paths.UpdateGrub,
			OutputLimit: defaultOutputLimit,
		}, stepFn)

	case "nvidia.driver.install":
		return nvidia.Install(ctx, nvidia.Params{
			AptGet:      cfg.Paths.AptGet,
			AptCache:    cfg.Paths.AptCache,
			LSPCI:       cfg.Paths.LSPCI,
			DKMS:        cfg.Paths.DKMS,
			OutputLimit: defaultOutputLimit,
		}, stepFn)

	case "coral.tpu.install":
		var req coral.InstallRequest
		if err := decodeParams(params, &req); err != nil {
			return nil, err
		}
		return coral.Install(ctx, coral.Params{
			AptGet:      cfg.Paths.AptGet,
			LSPCI:       cfg.Paths.LSPCI,
			DKMS:        cfg.Paths.DKMS,
			OutputLimit: defaultOutputLimit,
		}, req, stepFn)

	case "coral.tpu.attach":
		return coral.Attach(ctx, coral.Params{
			LSPCI:       cfg.Paths.LSPCI,
			OutputLimit: defaultOutputLimit,
		}, stepFn)

	case "gpu.attach":
		vmid, err := requiredIntParamAny(params, "vmid", "vmId", "targetId")
		if err != nil {
			return nil, err
		}
		pciID := firstNonEmpty(stringParam(params, "pci_id", ""), stringParam(params, "pciId", ""))
		if pciID == "" {
			return nil, fmt.Errorf("gpu.attach: pciId is required")
		}
		res, err := gpu.Attach(ctx, gpu.Params{
			QM:          cfg.Paths.QM,
			OutputLimit: defaultOutputLimit,
		}, gpu.AttachRequest{
			VMID:    vmid,
			PCIID:   pciID,
			Slot:    stringParam(params, "slot", "hostpci0"),
			Primary: boolParam(params, "primary") || boolParam(params, "x_vga"),
		}, stepFn)
		return res, err

	case "gpu.detach":
		vmid, err := requiredIntParamAny(params, "vmid", "vmId", "targetId")
		if err != nil {
			return nil, err
		}
		return gpu.Detach(ctx, gpu.Params{
			QM:          cfg.Paths.QM,
			OutputLimit: defaultOutputLimit,
		}, gpu.DetachRequest{
			VMID: vmid,
			Slot: stringParam(params, "slot", "hostpci0"),
		}, stepFn)

	case "gpu.mode":
		req := gpu.ModeRequest{Mode: stringParam(params, "mode", "compute")}
		if idx, ok := intParamOptional(params, "gpu_index", "gpuIndex"); ok {
			req.GPUIndex = &idx
		}
		return gpu.Mode(ctx, gpu.Params{
			NvidiaSMI:   "/usr/bin/nvidia-smi",
			OutputLimit: defaultOutputLimit,
		}, req, stepFn)

	case "gpu.attach.lxc":
		vmid, err := requiredIntParamAny(params, "vmid", "ctId", "containerId", "targetId")
		if err != nil {
			return nil, err
		}
		return gpu.AttachLXC(ctx, gpu.Params{
			LXCConfigDir: cfg.Files.LXCConfigDir,
		}, gpu.AttachLXCRequest{
			VMID: vmid,
			Type: stringParam(params, "type", "nvidia"),
		}, stepFn)

	case "sriov.pf.enable":
		req := sriov.EnableRequest{
			Driver: firstNonEmpty(stringParam(params, "driver", ""), stringParam(params, "module", "")),
			MaxVFs: intParam(params, "max_vfs", 0),
			Count:  intParam(params, "count", 0),
		}
		if req.Driver == "" {
			return nil, fmt.Errorf("sriov.pf.enable: driver is required")
		}
		return sriov.EnablePF(ctx, sriov.Params{
			CPUInfoPath:        cfg.Files.CPUInfoPath,
			GrubPath:           cfg.Files.GrubDefaultPath,
			ModprobeConfigPath: cfg.Files.SriovModprobeConfigPath,
			UpdateGrubPath:     cfg.Paths.UpdateGrub,
			OutputLimit:        defaultOutputLimit,
		}, req, stepFn)

	case "apt.tune":
		var req apt.Request
		if err := decodeParams(params, &req); err != nil {
			return nil, err
		}
		return apt.Tune(ctx, apt.Params{
			AptGetPath:  cfg.Paths.AptGet,
			ConfigDir:   cfg.Files.AptTuneConfigDir,
			OutputLimit: defaultOutputLimit,
		}, req, stepFn)

	case "ksm.configure":
		req := ksm.ConfigureRequest{Enabled: boolParam(params, "enabled")}
		req.SleepMsec = firstNonZero(intParam(params, "sleep_millisecs", 0), intParam(params, "sleepMs", 0))
		req.PagesToScan = firstNonZero(intParam(params, "pages_to_scan", 0), intParam(params, "pagesToScan", 0))
		req.MergeAcrossNodes = firstNonZero(intParam(params, "merge_across_nodes", 0), intParam(params, "mergeAcrossNodes", 0))
		return ksm.Configure(ctx, ksm.Params{
			ConfigPath:  cfg.Files.KSMTuneConfigPath,
			Systemctl:   cfg.Paths.Systemctl,
			OutputLimit: defaultOutputLimit,
		}, req, stepFn)

	case "utilities.install":
		packages, err := stringSliceParam(params, "packages")
		if err != nil {
			return nil, err
		}
		return utilities.Install(ctx, utilities.Params{
			AptGet:          cfg.Paths.AptGet,
			AllowedPackages: cfg.Policy.AllowedUtilityPackages,
			OutputLimit:     defaultOutputLimit,
		}, utilities.InstallRequest{Packages: packages}, stepFn)

	case "xshok.conflict.detect":
		return xshok.Detect(xshok.Params{})

	case "pve.upgrade.run":
		req := upgrade.RunRequest{Mode: stringParam(params, "mode", "automatic")}
		if boolParam(params, "check_only") {
			req.Mode = "check-only"
		}
		return upgrade.Run(ctx, upgrade.Params{
			AptGet:      cfg.Paths.AptGet,
			PVEUpgrade:  cfg.Paths.PVEUpgrade,
			OutputLimit: defaultOutputLimit,
		}, req, stepFn)

	case "kernel.module.load":
		module := firstNonEmpty(stringParam(params, "module", ""), stringParam(params, "name", ""))
		if module == "" {
			return nil, fmt.Errorf("kernel.module.load: module is required")
		}
		options, err := stringSliceParamOptional(params, "options")
		if err != nil {
			return nil, err
		}
		return kernel.LoadModule(ctx, kernel.Params{
			ModprobePath:   cfg.Paths.Modprobe,
			AllowedModules: cfg.Policy.AllowedKernelModules,
			OutputLimit:    defaultOutputLimit,
		}, kernel.LoadRequest{Module: module, Options: options}, stepFn)

	case "community-script.run":
		var req communityscript.RunRequest
		if err := decodeParams(params, &req); err != nil {
			return nil, err
		}
		res, err := communityscript.Run(ctx, communityscript.Params{
			SystemdRunPath:      cfg.Paths.SystemdRun,
			ReleaseKeyPath:      cfg.Files.CommunityReleaseKeyPath,
			AllowedInterpreters: cfg.Policy.AllowedScriptInterpreters,
			AllowedWriteRoots:   cfg.Policy.AllowedScriptWriteRoots,
			OutputLimitBytes:    cfg.Policy.CommunityOutputLimitBytes,
			MaxTimeoutSec:       cfg.Policy.CommunityMaxTimeoutSec,
		}, req, stepFn)
		return res, err

	default:
		return nil, fmt.Errorf("unsupported command %q", command)
	}
}

func readAndVerifyEnvelope(cfg *hwcfg.Config) (*envpkg.Envelope, error) {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read envelope stdin: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty envelope on stdin")
	}
	env, err := envpkg.Unmarshal(raw)
	if err != nil {
		return nil, fmt.Errorf("envelope decode failed: %w", err)
	}

	ks, err := envpkg.LoadKeySet(cfg.Keyset.Path)
	if err != nil {
		return nil, fmt.Errorf("load keyset: %w", err)
	}
	replay := envpkg.NewReplayCache(8, 2*time.Hour)
	defer replay.Close()

	hostFingerprintRaw, err := os.ReadFile(cfg.Identity.HostFingerprintFile)
	if err != nil {
		return nil, fmt.Errorf("load host fingerprint: %w", err)
	}
	hostFingerprint := strings.TrimSpace(string(hostFingerprintRaw))
	if hostFingerprint == "" {
		return nil, fmt.Errorf("host fingerprint file is empty")
	}

	if err := env.Verify(ks, agentClass, hostFingerprint, replay); err != nil {
		return env, err
	}
	return env, nil
}

func classifyReject(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "bad signature"):
		return "BAD_SIGNATURE"
	case strings.Contains(msg, "audience mismatch"):
		return "AUDIENCE_MISMATCH"
	case strings.Contains(msg, "expired"):
		return "EXPIRED"
	case strings.Contains(msg, "replay"):
		return "REPLAY"
	default:
		return "VERIFY_FAILED"
	}
}

func appendAudit(log *audit.Log, entry audit.Entry) {
	if log == nil {
		return
	}
	_, _ = log.Append(entry)
}

func decodeParams(params map[string]any, out any) error {
	b, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("encode params: %w", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode params: %w", err)
	}
	return nil
}

func stringParam(params map[string]any, key, fallback string) string {
	v, ok := params[key]
	if !ok {
		return fallback
	}
	s, ok := v.(string)
	if !ok {
		return fallback
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	return s
}

func boolParam(params map[string]any, key string) bool {
	v, ok := params[key]
	if !ok {
		return false
	}
	switch typed := v.(type) {
	case bool:
		return typed
	case string:
		s := strings.ToLower(strings.TrimSpace(typed))
		return s == "1" || s == "true" || s == "yes"
	case float64:
		return typed != 0
	case int:
		return typed != 0
	default:
		return false
	}
}

func intParam(params map[string]any, key string, fallback int) int {
	v, ok := params[key]
	if !ok {
		return fallback
	}
	switch typed := v.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		if n, err := typed.Int64(); err == nil {
			return int(n)
		}
	case string:
		t := strings.TrimSpace(typed)
		if t == "" {
			return fallback
		}
		n, err := strconv.Atoi(t)
		if err == nil {
			return n
		}
	}
	return fallback
}

func requiredIntParamAny(params map[string]any, keys ...string) (int, error) {
	for _, key := range keys {
		if _, ok := params[key]; !ok {
			continue
		}
		n := intParam(params, key, 0)
		if n > 0 {
			return n, nil
		}
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return 0, fmt.Errorf("%s is required", strings.Join(keys, " or "))
}

func intParamOptional(params map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		if _, ok := params[key]; !ok {
			continue
		}
		return intParam(params, key, 0), true
	}
	return 0, false
}

func stringSliceParam(params map[string]any, key string) ([]string, error) {
	v, ok := params[key]
	if !ok {
		return nil, fmt.Errorf("%s is required", key)
	}
	return parseStringSlice(v)
}

func stringSliceParamOptional(params map[string]any, key string) ([]string, error) {
	v, ok := params[key]
	if !ok {
		return nil, nil
	}
	return parseStringSlice(v)
}

func parseStringSlice(v any) ([]string, error) {
	raw, ok := v.([]any)
	if !ok {
		if direct, ok := v.([]string); ok {
			out := make([]string, 0, len(direct))
			for _, item := range direct {
				if trimmed := strings.TrimSpace(item); trimmed != "" {
					out = append(out, trimmed)
				}
			}
			return out, nil
		}
		return nil, errors.New("must be an array of strings")
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s, ok := item.(string)
		if !ok {
			return nil, errors.New("must be an array of strings")
		}
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
