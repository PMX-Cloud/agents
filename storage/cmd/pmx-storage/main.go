/*
Command pmx-storage handles disk, ZFS, share, SMART, and NVMe operations.

It runs as root with an explicit binary allowlist and AppArmor confinement.
No shell execution is permitted; all subprocesses are argv-style.
*/
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pmx-cloud/agents/shared/audit"
	envpkg "github.com/pmx-cloud/agents/shared/envelope"
	"github.com/pmx-cloud/agents/shared/preflight"
	"github.com/pmx-cloud/agents/shared/wsclient"
	storCfg "github.com/pmx-cloud/agents/storage/internal/config"
	"github.com/pmx-cloud/agents/storage/internal/disk"
	"github.com/pmx-cloud/agents/storage/internal/nfs"
	"github.com/pmx-cloud/agents/storage/internal/nvme"
	"github.com/pmx-cloud/agents/storage/internal/samba"
	"github.com/pmx-cloud/agents/storage/internal/smart"
	"github.com/pmx-cloud/agents/storage/internal/storageexec"
	"github.com/pmx-cloud/agents/storage/internal/zfs"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

const agentClass = "pmx-storage"

func main() {
	var (
		configPath  = flag.String("config", "/etc/pmx-cloud/pmx-storage.conf", "path to config")
		isPreflight = flag.Bool("preflight", false, "validate config and exit")
		isVersion   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	log := slog.Default()

	if *isVersion {
		fmt.Printf("pmx-storage version %s commit %s built %s\n", Version, Commit, BuildDate)
		os.Exit(0)
	}

	cfg, err := storCfg.Load(*configPath)
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	checks := preflight.StandardChecks(agentClass, *configPath,
		cfg.Identity.Cert, cfg.Identity.Key, cfg.Keyset.Path, nil)
	checks = append(checks, preflight.Check{
		Name: "host-fingerprint-readable",
		Run: func(ctx context.Context) error {
			_, err := loadHostFingerprint("/etc/pmx-cloud/host-fingerprint")
			return err
		},
	})
	if *isPreflight {
		os.Exit(preflight.Run(checks))
	}

	if err := run(cfg, log); err != nil {
		log.Error("pmx-storage exited with error", "err", err)
		os.Exit(1)
	}
}

func run(cfg *storCfg.Config, log *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ks, err := envpkg.LoadKeySet(cfg.Keyset.Path)
	if err != nil {
		return fmt.Errorf("load keyset: %w", err)
	}
	cache := envpkg.NewReplayCache(100_000, 24*time.Hour)
	defer cache.Close()

	hostFingerprint, err := loadHostFingerprint("/etc/pmx-cloud/host-fingerprint")
	if err != nil {
		return fmt.Errorf("load host fingerprint: %w", err)
	}

	auditLog, err := audit.OpenWithFallback(
		"/var/log/pmx-cloud/pmx-storage.audit.log",
		"/tmp/pmx-storage.audit.log",
		log,
	)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	h := &storageHandler{
		cfg:      cfg,
		auditLog: auditLog,
		log:      log,
	}

	client, err := wsclient.New(wsclient.Config{
		BackendURL:        cfg.Backend.URL,
		AgentClass:        agentClass,
		AuthToken:         cfg.Backend.AuthToken,
		CertPath:          cfg.Identity.Cert,
		KeyPath:           cfg.Identity.Key,
		KeySet:            ks,
		ReplayCache:       cache,
		HostFingerprint:   hostFingerprint,
		HeartbeatInterval: 30 * time.Second,
		HeartbeatTimeout:  90 * time.Second,
		Handler:           h,
		Logger:            log,
		AuditChainHead:    auditLog.Head,
	})
	if err != nil {
		return fmt.Errorf("wsclient init: %w", err)
	}

	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Info("pmx-storage starting", "version", Version, "backend", cfg.Backend.URL)
	return client.Run(sigCtx)
}

type storageHandler struct {
	cfg      *storCfg.Config
	auditLog *audit.Log
	log      *slog.Logger
}

func (h *storageHandler) OnConnect(ctx context.Context, c *wsclient.Client) error {
	h.log.Info("pmx-storage: connected to backend")
	return nil
}

func (h *storageHandler) OnEnvelope(ctx context.Context, env *envpkg.Envelope) ([]byte, error) {
	start := time.Now()
	ex := h.newExec(env.JobID)
	result, err := h.dispatch(ctx, env, ex)
	elapsed := time.Since(start).Milliseconds()
	code := 0
	if err != nil {
		code = 1
	}
	h.auditLog.Append(audit.Entry{
		Timestamp:  time.Now(),
		JobID:      env.JobID,
		Command:    env.Command,
		Step:       "complete",
		Exit:       code,
		DurationMs: elapsed,
	})
	return result, err
}

func (h *storageHandler) newExec(jobID string) *storageexec.Exec {
	ex := storageexec.New()
	ex.JobID = jobID
	ex.AuditLog = h.auditLog
	ex.Logger = h.log
	// Resolve the configured command paths against the host (handles usr-merged
	// layouts where the configured /sbin/* path is not a real file) and rebuild
	// the allowlist from the resolved set so the allowlist stays in sync.
	ex.Paths, ex.AllowedBinaries = storageexec.ResolvePaths(map[string]string{
		"lsblk":      h.cfg.Commands.LsblkPath,
		"parted":     h.cfg.Commands.PartedPath,
		"wipefs":     h.cfg.Commands.WipefsPath,
		"mkfs.ext4":  h.cfg.Commands.MkfsExt4,
		"mkfs.xfs":   h.cfg.Commands.MkfsXfs,
		"mkfs.btrfs": h.cfg.Commands.MkfsBtrfs,
		"zpool":      h.cfg.Commands.ZpoolPath,
		"zfs":        h.cfg.Commands.ZfsPath,
		"smartctl":   h.cfg.Commands.Smartctl,
		"exportfs":   h.cfg.Commands.Exportfs,
		"net":        h.cfg.Commands.NetPath,
		"nvme":       h.cfg.Commands.NvmePath,
		"qemu-img":   h.cfg.Commands.QemuImgPath,
	})
	return ex
}

func (h *storageHandler) dispatch(ctx context.Context, env *envpkg.Envelope, ex storageexec.Interface) ([]byte, error) {
	params := env.Params
	if params == nil {
		params = map[string]any{}
	}

	switch env.Command {
	case "disk.inventory":
		res, err := disk.Inventory(ctx, ex)
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(res)

	case "disk.format":
		p := disk.FormatParams{
			Device: stringParam(params, "device", ""),
			FSType: stringParam(params, "fstype", ""),
			Force:  boolParam(params, "force"),
			// Live dispatch is pinned to host safety files; no envelope overrides.
			MountsPath: "",
			FstabPath:  "",
		}
		return okOrErr(disk.Format(ctx, ex, p))

	case "disk.passthrough":
		res, err := disk.Passthrough(disk.PassthroughParams{
			WWN:     stringParam(params, "wwn", ""),
			ByIDDir: stringParam(params, "by_id_dir", ""),
		})
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(res)

	case "disk.import-image":
		p := disk.ImportImageParams{
			ID:             stringParam(params, "id", ""),
			SourceURL:      stringParam(params, "source_url", ""),
			AllowedHosts:   stringSliceParam(params, "allowed_hosts"),
			SourceFormat:   stringParam(params, "source_format", ""),
			Destination:    stringParam(params, "destination", ""),
			StorageRoot:    h.cfg.State.Dir,
			HTTPTimeoutSec: intParam(params, "http_timeout_seconds", 300),
		}
		res, err := disk.ImportImage(ctx, ex, p)
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(res)

	case "zfs.status":
		res, err := zfs.Status(ctx, ex)
		if err != nil {
			return errJSON(err), err
		}
		return res, nil

	case "zfs.pool.create":
		return okOrErr(zfs.PoolCreate(ctx, ex, zfs.PoolCreateParams{
			Name:     stringParam(params, "name", ""),
			Topology: stringParam(params, "topology", ""),
			Devices:  stringSliceParam(params, "devices"),
		}))

	case "zfs.pool.destroy":
		return okOrErr(zfs.PoolDestroy(ctx, ex, zfs.PoolDestroyParams{
			Name:  stringParam(params, "name", ""),
			Force: boolParam(params, "force"),
		}))

	case "zfs.dataset.create":
		return okOrErr(zfs.DatasetCreate(ctx, ex, zfs.DatasetCreateParams{
			Dataset:    stringParam(params, "dataset", ""),
			Options:    mapParam(params, "options"),
			AllowDedup: boolParam(params, "allow_dedup"),
		}))

	case "zfs.dataset.destroy":
		return okOrErr(zfs.DatasetDestroy(ctx, ex, zfs.DatasetDestroyParams{
			Dataset:   stringParam(params, "dataset", ""),
			Recursive: boolParam(params, "recursive"),
		}))

	case "zfs.snapshot.create":
		return okOrErr(zfs.SnapshotCreate(ctx, ex, zfs.SnapshotCreateParams{Snapshot: stringParam(params, "snapshot", "")}))

	case "zfs.snapshot.send":
		return okOrErr(zfs.SnapshotSend(ctx, ex, zfs.SnapshotSendParams{
			Snapshot:    stringParam(params, "snapshot", ""),
			Destination: stringParam(params, "destination", ""),
		}))

	case "zfs.scrub.start":
		return okOrErr(zfs.ScrubStart(ctx, ex, zfs.ScrubParams{Pool: stringParam(params, "pool", "")}))

	case "zfs.scrub.status":
		res, err := zfs.ScrubStatus(ctx, ex, zfs.ScrubParams{Pool: stringParam(params, "pool", "")})
		if err != nil {
			return errJSON(err), err
		}
		return res, nil

	case "zfs.tune":
		return okOrErr(zfs.Tune(ctx, ex, zfs.TuneParams{
			Dataset:    stringParam(params, "dataset", ""),
			Property:   stringParam(params, "property", ""),
			Value:      stringParam(params, "value", ""),
			AllowDedup: boolParam(params, "allow_dedup"),
		}))

	case "nfs.share.create":
		return okOrErr(nfs.ShareCreate(ctx, ex, nfs.ShareParams{
			ID:      stringParam(params, "id", ""),
			Path:    stringParam(params, "path", ""),
			Network: stringParam(params, "network", ""),
			Options: stringSliceParam(params, "options"),
			// Live dispatch is pinned to /etc/exports.d; no envelope overrides.
			ExportsDir: "",
		}))

	case "nfs.share.delete":
		return okOrErr(nfs.ShareDelete(ctx, ex, nfs.ShareParams{
			ID:         stringParam(params, "id", ""),
			ExportsDir: "",
		}))

	case "nfs.share.list":
		shares, err := nfs.ShareList(nfs.ShareParams{ExportsDir: ""})
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(map[string]any{"shares": shares})

	case "samba.share.create":
		return okOrErr(samba.ShareCreate(ctx, ex, samba.ShareParams{
			ID:      stringParam(params, "id", ""),
			Path:    stringParam(params, "path", ""),
			Comment: stringParam(params, "comment", ""),
			ACL:     stringParam(params, "acl", ""),
		}))

	case "samba.share.delete":
		return okOrErr(samba.ShareDelete(ctx, ex, samba.ShareParams{ID: stringParam(params, "id", "")}))

	case "samba.share.list":
		shares, err := samba.ShareList(ctx, ex)
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(map[string]any{"shares": shares})

	case "smart.poll":
		res, err := smart.Poll(ctx, ex, stringSliceParam(params, "devices"))
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(res)

	case "smart.schedule":
		statePath, err := smart.Schedule(ctx, smart.ScheduleParams{
			Interval: stringParam(params, "interval", "15m"),
			StateDir: h.cfg.State.Dir,
		})
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(map[string]any{"ok": true, "state_path": statePath})

	case "nvme.controller.add":
		return okOrErr(nvme.ControllerAdd(ctx, ex, nvme.ControllerParams{
			Controller:  stringParam(params, "controller", ""),
			SizeBlocks:  int64(intParam(params, "size_blocks", 0)),
			BlockSize:   intParam(params, "block_size", 4096),
			NamespaceID: intParam(params, "namespace_id", 1),
		}))

	default:
		h.log.Warn("pmx-storage: unsupported command", "command", env.Command, "job_id", env.JobID)
		return errJSON(fmt.Errorf("UNSUPPORTED: %s", env.Command)), nil
	}
}

func okOrErr(err error) ([]byte, error) {
	if err != nil {
		return errJSON(err), err
	}
	b, _ := json.Marshal(map[string]bool{"ok": true})
	return b, nil
}

func errJSON(err error) []byte {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return b
}

func stringParam(params map[string]any, key string, fallback string) string {
	v, ok := params[key]
	if !ok {
		return fallback
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return fallback
	}
	return s
}

func boolParam(params map[string]any, key string) bool {
	v, ok := params[key]
	if !ok {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "1" || t == "true" || t == "yes"
	}
	return false
}

func intParam(params map[string]any, key string, fallback int) int {
	v, ok := params[key]
	if !ok {
		return fallback
	}
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	}
	return fallback
}

func stringSliceParam(params map[string]any, key string) []string {
	v, ok := params[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		if arrStr, ok2 := v.([]string); ok2 {
			return arrStr
		}
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(string)
		if ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func mapParam(params map[string]any, key string) map[string]any {
	v, ok := params[key]
	if !ok {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return m
}

func loadHostFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	fp := strings.TrimSpace(string(data))
	if fp == "" {
		return "", fmt.Errorf("host fingerprint file %s is empty", path)
	}
	return fp, nil
}
