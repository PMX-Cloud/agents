/*
Command pmx-backup orchestrates local Proxmox backups and off-host sync.

It runs as root with strict archive-root allowlisting plus AppArmor confinement.
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
	"sync"
	"syscall"
	"time"

	"github.com/pmx-cloud/agents/backup/internal/archive"
	"github.com/pmx-cloud/agents/backup/internal/config"
	"github.com/pmx-cloud/agents/backup/internal/retention"
	backupsync "github.com/pmx-cloud/agents/backup/internal/sync"
	"github.com/pmx-cloud/agents/backup/internal/verify"
	"github.com/pmx-cloud/agents/backup/internal/vzdump"
	"github.com/pmx-cloud/agents/shared/audit"
	envpkg "github.com/pmx-cloud/agents/shared/envelope"
	"github.com/pmx-cloud/agents/shared/preflight"
	"github.com/pmx-cloud/agents/shared/wsclient"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

const agentClass = "pmx-backup"

func main() {
	var (
		configPath  = flag.String("config", "/etc/pmx-cloud/pmx-backup.conf", "path to config")
		isPreflight = flag.Bool("preflight", false, "validate config and exit")
		isVersion   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	log := slog.Default()

	if *isVersion {
		fmt.Printf("pmx-backup version %s commit %s built %s\n", Version, Commit, BuildDate)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	checks := preflight.StandardChecks(agentClass, *configPath,
		cfg.Identity.Cert, cfg.Identity.Key, cfg.Keyset.Path, nil)
	checks = append(checks,
		preflight.Check{
			Name: "vzdump-binary-readable",
			Run: func(ctx context.Context) error {
				_, err := os.Stat(vzdump.ResolveBinary(cfg.VZDump.Binary))
				return err
			},
		},
		preflight.Check{
			Name: "archive-roots-present",
			Run: func(ctx context.Context) error {
				for _, root := range cfg.Storage.ArchiveRoots {
					st, err := os.Stat(root)
					if err != nil {
						return fmt.Errorf("archive root %q: %w", root, err)
					}
					if !st.IsDir() {
						return fmt.Errorf("archive root %q is not a directory", root)
					}
				}
				return nil
			},
		},
	)
	if *isPreflight {
		os.Exit(preflight.Run(checks))
	}

	if err := run(cfg, log); err != nil {
		log.Error("pmx-backup exited with error", "err", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config, log *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ks, err := envpkg.LoadKeySet(cfg.Keyset.Path)
	if err != nil {
		return fmt.Errorf("load keyset: %w", err)
	}
	cache := envpkg.NewReplayCache(100_000, 24*time.Hour)
	defer cache.Close()

	hostFingerprint := "dev-fingerprint"
	if raw, err := os.ReadFile("/etc/pmx-cloud/host-fingerprint"); err == nil {
		if v := strings.TrimSpace(string(raw)); v != "" {
			hostFingerprint = v
		}
	}

	auditLog, err := audit.OpenWithFallback(
		"/var/log/pmx-cloud/pmx-backup.audit.log",
		"/tmp/pmx-backup.audit.log",
		log,
	)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	h := &backupHandler{
		cfg:        cfg,
		auditLog:   auditLog,
		log:        log,
		syncRunner: backupsync.NewRunner(),
		jobSem:     make(chan struct{}, cfg.Limits.MaxConcurrentJobs),
		syncSem:    make(chan struct{}, cfg.Limits.MaxConcurrentSyncs),
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

	log.Info("pmx-backup starting", "version", Version, "backend", cfg.Backend.URL)
	return client.Run(sigCtx)
}

type backupHandler struct {
	cfg        *config.Config
	auditLog   *audit.Log
	log        *slog.Logger
	syncRunner *backupsync.Runner
	jobSem     chan struct{}
	syncSem    chan struct{}
	clientMu   sync.RWMutex
	client     *wsclient.Client
}

func (h *backupHandler) OnConnect(ctx context.Context, c *wsclient.Client) error {
	h.clientMu.Lock()
	h.client = c
	h.clientMu.Unlock()
	h.log.Info("pmx-backup: connected to backend")
	return nil
}

func (h *backupHandler) OnEnvelope(ctx context.Context, env *envpkg.Envelope) ([]byte, error) {
	start := time.Now()
	payload, err := h.dispatch(ctx, env)
	elapsed := time.Since(start).Milliseconds()
	exit := 0
	if err != nil {
		exit = 1
	}
	h.auditLog.Append(audit.Entry{
		Timestamp:  time.Now(),
		JobID:      env.JobID,
		Command:    env.Command,
		Step:       "complete",
		Exit:       exit,
		DurationMs: elapsed,
	})
	return payload, err
}

func (h *backupHandler) dispatch(ctx context.Context, env *envpkg.Envelope) ([]byte, error) {
	params := env.Params
	if params == nil {
		params = map[string]any{}
	}

	switch env.Command {
	case "backup.create":
		if !tryAcquire(h.jobSem) {
			return errJSON(fmt.Errorf("BUSY: max_concurrent_jobs=%d", cap(h.jobSem))), fmt.Errorf("BUSY")
		}
		defer release(h.jobSem)

		vmid, err := requiredIntParam(params, "vmid")
		if err != nil {
			return errJSON(err), err
		}
		dumpRoot := firstNonEmpty(
			stringParam(params, "archive_root", ""),
			stringParam(params, "dump_dir", ""),
			h.cfg.Storage.ArchiveRoots[0],
		)
		dumpDir, err := archive.EnsureWritableDirectory(dumpRoot, h.cfg.Storage.ArchiveRoots)
		if err != nil {
			return errJSON(err), err
		}

		res, err := vzdump.Create(ctx, vzdump.Binaries{
			VZDump:    vzdump.ResolveBinary(h.cfg.VZDump.Binary),
			QM:        vzdump.ResolveBinary(h.cfg.VZDump.QMBinary),
			QMRestore: vzdump.ResolveBinary(h.cfg.VZDump.QMRestoreBinary),
		}, vzdump.CreateParams{
			VMID:          vmid,
			DumpDir:       dumpDir,
			Mode:          stringParam(params, "mode", "snapshot"),
			Compress:      stringParam(params, "compress", "zstd"),
			NotesTemplate: stringParam(params, "notes_template", "{{guestname}} {{now}}"),
		}, h.stepEmitter(env))
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(res)

	case "backup.restore":
		if !tryAcquire(h.jobSem) {
			return errJSON(fmt.Errorf("BUSY: max_concurrent_jobs=%d", cap(h.jobSem))), fmt.Errorf("BUSY")
		}
		defer release(h.jobSem)

		archivePath := firstNonEmpty(
			stringParam(params, "archive_path", ""),
			stringParam(params, "archive", ""),
		)
		resolvedArchive, err := archive.EnsureExistingArchive(archivePath, h.cfg.Storage.ArchiveRoots)
		if err != nil {
			return errJSON(err), err
		}
		vmid, err := requiredIntParamAny(params, "target_vmid", "vmid")
		if err != nil {
			return errJSON(err), err
		}

		err = vzdump.Restore(ctx, vzdump.Binaries{
			VZDump:    vzdump.ResolveBinary(h.cfg.VZDump.Binary),
			QM:        vzdump.ResolveBinary(h.cfg.VZDump.QMBinary),
			QMRestore: vzdump.ResolveBinary(h.cfg.VZDump.QMRestoreBinary),
		}, vzdump.RestoreParams{
			ArchivePath: resolvedArchive,
			VMID:        vmid,
			Storage:     stringParam(params, "storage", ""),
			Overwrite:   boolParam(params, "overwrite"),
		}, h.stepEmitter(env))
		if err != nil {
			return errJSON(err), err
		}
		return okJSON(), nil

	case "backup.delete":
		if !tryAcquire(h.jobSem) {
			return errJSON(fmt.Errorf("BUSY: max_concurrent_jobs=%d", cap(h.jobSem))), fmt.Errorf("BUSY")
		}
		defer release(h.jobSem)

		archivePath := firstNonEmpty(
			stringParam(params, "archive_path", ""),
			stringParam(params, "archive", ""),
		)
		deleted, err := archive.DeleteArchiveWithSidecars(archivePath, h.cfg.Storage.ArchiveRoots)
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(map[string]any{"deleted": deleted})

	case "backup.verify":
		if !tryAcquire(h.jobSem) {
			return errJSON(fmt.Errorf("BUSY: max_concurrent_jobs=%d", cap(h.jobSem))), fmt.Errorf("BUSY")
		}
		defer release(h.jobSem)

		archivePath := firstNonEmpty(
			stringParam(params, "archive_path", ""),
			stringParam(params, "archive", ""),
		)
		resolvedArchive, err := archive.EnsureExistingArchive(archivePath, h.cfg.Storage.ArchiveRoots)
		if err != nil {
			return errJSON(err), err
		}
		res, err := verify.Run(ctx, verify.Params{
			ArchivePath:    resolvedArchive,
			ExpectedSHA256: firstNonEmpty(stringParam(params, "expected_sha256", ""), stringParam(params, "sha256", "")),
			TarBinary:      h.cfg.VZDump.TarBinary,
		}, h.stepEmitter(env))
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(res)

	case "backup.retention.apply":
		if !tryAcquire(h.jobSem) {
			return errJSON(fmt.Errorf("BUSY: max_concurrent_jobs=%d", cap(h.jobSem))), fmt.Errorf("BUSY")
		}
		defer release(h.jobSem)

		root := firstNonEmpty(stringParam(params, "archive_root", ""), h.cfg.Storage.ArchiveRoots[0])
		result, err := retention.Apply(retention.ApplyParams{
			ArchiveRoot:  root,
			ArchiveRoots: h.cfg.Storage.ArchiveRoots,
			VMID:         stringParam(params, "vmid", ""),
			Policy: retention.Policy{
				KeepDailies:   intParam(params, "keep_dailies", 7),
				KeepWeeklies:  intParam(params, "keep_weeklies", 4),
				KeepMonthlies: intParam(params, "keep_monthlies", 12),
			},
			DryRun: boolParam(params, "dry_run"),
		})
		if err != nil {
			return errJSON(err), err
		}
		if !result.DryRun {
			for _, deleted := range result.Deleted {
				h.auditLog.Append(audit.Entry{
					Timestamp: time.Now(),
					JobID:     env.JobID,
					Command:   env.Command,
					Step:      "delete " + deleted,
					Exit:      0,
				})
			}
		}
		return json.Marshal(result)

	case "backup.sync.push":
		if !tryAcquire(h.syncSem) {
			return errJSON(fmt.Errorf("BUSY: max_concurrent_syncs=%d", cap(h.syncSem))), fmt.Errorf("BUSY")
		}
		defer release(h.syncSem)

		var p backupsync.PushParams
		if err := decodeParams(params, &p); err != nil {
			return errJSON(err), err
		}
		if err := normalizeSyncPushParams(&p, h.cfg.Storage.ArchiveRoots); err != nil {
			return errJSON(err), err
		}
		if p.JobID == "" {
			p.JobID = env.JobID
		}
		res, err := h.syncRunner.Push(ctx, p, h.stepEmitter(env))
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(res)

	case "backup.sync.pull":
		if !tryAcquire(h.syncSem) {
			return errJSON(fmt.Errorf("BUSY: max_concurrent_syncs=%d", cap(h.syncSem))), fmt.Errorf("BUSY")
		}
		defer release(h.syncSem)

		var p backupsync.PullParams
		if err := decodeParams(params, &p); err != nil {
			return errJSON(err), err
		}
		if err := normalizeSyncPullParams(&p, h.cfg.Storage.ArchiveRoots); err != nil {
			return errJSON(err), err
		}
		if p.JobID == "" {
			p.JobID = env.JobID
		}
		res, err := h.syncRunner.Pull(ctx, p, h.stepEmitter(env))
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(res)

	default:
		h.log.Warn("pmx-backup: unsupported command", "command", env.Command, "job_id", env.JobID)
		return errJSON(fmt.Errorf("UNSUPPORTED: %s", env.Command)), nil
	}
}

func (h *backupHandler) stepEmitter(env *envpkg.Envelope) func(string) {
	return func(step string) {
		trimmed := strings.TrimSpace(step)
		if trimmed == "" {
			return
		}
		h.log.Info("pmx-backup step", "job_id", env.JobID, "command", env.Command, "step", trimmed)
		h.emitStepFrame(env.JobID, env.Command, trimmed)
	}
}

func (h *backupHandler) emitStepFrame(jobID, command, step string) {
	payload, err := json.Marshal(map[string]any{
		"type":      "step",
		"jobId":     jobID,
		"command":   command,
		"step":      step,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		h.log.Warn("pmx-backup: step frame marshal failed", "err", err)
		return
	}

	h.clientMu.RLock()
	client := h.client
	h.clientMu.RUnlock()
	if client == nil {
		return
	}
	if err := client.SendRaw(payload); err != nil {
		h.log.Warn("pmx-backup: step frame send failed", "job_id", jobID, "command", command, "err", err)
	}
}

func tryAcquire(ch chan struct{}) bool {
	select {
	case ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func release(ch chan struct{}) {
	select {
	case <-ch:
	default:
	}
}

func okJSON() []byte {
	b, _ := json.Marshal(map[string]bool{"ok": true})
	return b
}

func errJSON(err error) []byte {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return b
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
	if !ok || strings.TrimSpace(s) == "" {
		return fallback
	}
	return strings.TrimSpace(s)
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
		lower := strings.ToLower(strings.TrimSpace(typed))
		return lower == "1" || lower == "true" || lower == "yes"
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
	case uint64:
		// CBOR decodes non-negative integers (e.g. a vmid) as uint64; without
		// this case numeric params silently fall back to 0.
		return int(typed)
	case float64:
		return int(typed)
	case string:
		if strings.TrimSpace(typed) == "" {
			return fallback
		}
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(typed), "%d", &n); err == nil {
			return n
		}
		return fallback
	default:
		return fallback
	}
}

func requiredIntParam(params map[string]any, key string) (int, error) {
	if _, ok := params[key]; !ok {
		return 0, fmt.Errorf("%s is required", key)
	}
	value := intParam(params, key, 0)
	if value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return value, nil
}

func requiredIntParamAny(params map[string]any, keys ...string) (int, error) {
	for _, key := range keys {
		if _, ok := params[key]; !ok {
			continue
		}
		value := intParam(params, key, 0)
		if value > 0 {
			return value, nil
		}
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return 0, fmt.Errorf("%s is required", strings.Join(keys, " or "))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func normalizeSyncPushParams(params *backupsync.PushParams, roots []string) error {
	localPath := firstNonEmpty(params.LocalPath, params.S3.LocalPath, params.SFTP.LocalPath, params.PBS.LocalPath)
	resolved, err := archive.EnsureExistingArchive(localPath, roots)
	if err != nil {
		return err
	}
	params.LocalPath = resolved
	switch strings.ToLower(strings.TrimSpace(params.Provider)) {
	case "s3":
		params.S3.LocalPath = resolved
	case "sftp":
		params.SFTP.LocalPath = resolved
	case "pbs":
		params.PBS.LocalPath = resolved
	}
	return nil
}

func normalizeSyncPullParams(params *backupsync.PullParams, roots []string) error {
	destination := firstNonEmpty(params.LocalPath, params.S3.LocalPath, params.SFTP.LocalPath, params.PBS.LocalPath)
	resolved, err := archive.EnsurePathForCreate(destination, roots)
	if err != nil {
		return err
	}
	params.LocalPath = resolved
	switch strings.ToLower(strings.TrimSpace(params.Provider)) {
	case "s3":
		params.S3.LocalPath = resolved
	case "sftp":
		params.SFTP.LocalPath = resolved
	case "pbs":
		params.PBS.LocalPath = resolved
	}
	return nil
}
