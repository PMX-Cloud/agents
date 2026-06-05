/*
Command pmx-security handles hardening, audit/compliance, CVE scan, and cert audit.

The daemon is non-root (pmx-sec) and uses short-lived root scopes for apply jobs.
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

	"github.com/pmx-cloud/agents/security/internal/auditd"
	"github.com/pmx-cloud/agents/security/internal/cert"
	"github.com/pmx-cloud/agents/security/internal/compliance"
	"github.com/pmx-cloud/agents/security/internal/config"
	"github.com/pmx-cloud/agents/security/internal/cve"
	"github.com/pmx-cloud/agents/security/internal/hardening"
	"github.com/pmx-cloud/agents/security/internal/lynis"
	"github.com/pmx-cloud/agents/security/internal/rootscope"
	"github.com/pmx-cloud/agents/security/internal/ssh"
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

const agentClass = "pmx-security"

func main() {
	var (
		configPath  = flag.String("config", "/etc/pmx-cloud/pmx-security.conf", "path to config")
		isPreflight = flag.Bool("preflight", false, "validate config and exit")
		isVersion   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	log := slog.Default()

	if *isVersion {
		fmt.Printf("pmx-security version %s commit %s built %s\n", Version, Commit, BuildDate)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	checks := preflight.StandardChecks(agentClass, *configPath,
		cfg.Identity.Cert, cfg.Identity.Key, cfg.Keyset.Path, nil)
	checks = append(checks, preflight.Check{
		Name: "cve-signature-keyset-readable",
		Run: func(ctx context.Context) error {
			_, err := os.Stat(cfg.CVE.SignatureKeysetPath)
			return err
		},
	})
	if *isPreflight {
		if err := hardeningPreflight(cfg); err != nil {
			log.Error("preflight hardening profile verification failed", "err", err)
			os.Exit(1)
		}
		os.Exit(preflight.Run(checks))
	}

	if err := run(cfg, log); err != nil {
		log.Error("pmx-security exited with error", "err", err)
		os.Exit(1)
	}
}

func hardeningPreflight(cfg *config.Config) error {
	_ = cfg
	if os.Geteuid() == 0 {
		return fmt.Errorf("pmx-security must run as non-root user (pmx-sec)")
	}
	if _, err := os.Stat(rootscope.DefaultSystemdRunPath); err != nil {
		return fmt.Errorf("pmx-security requires %s: %w", rootscope.DefaultSystemdRunPath, err)
	}
	return hardening.ValidateProfiles()
}

func run(cfg *config.Config, log *slog.Logger) error {
	if os.Geteuid() == 0 {
		return fmt.Errorf("pmx-security daemon must not run as root")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ks, err := envpkg.LoadKeySet(cfg.Keyset.Path)
	if err != nil {
		return fmt.Errorf("load keyset: %w", err)
	}
	cache := envpkg.NewReplayCache(100_000, 24*time.Hour)
	defer cache.Close()

	auditLog, err := audit.OpenWithFallback(
		"/var/log/pmx-cloud/pmx-security.audit.log",
		"/tmp/pmx-security.audit.log",
		log,
	)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	h := &securityHandler{cfg: cfg, auditLog: auditLog, log: log}
	reconcileCtx, reconcileCancel := context.WithTimeout(ctx, 15*time.Second)
	if err := hardening.ReconcileApplyStates(reconcileCtx, cfg.State.Dir, nil); err != nil {
		log.Warn("pmx-security: hardening state reconcile failed", "err", err)
	}
	reconcileCancel()

	hostFingerprint := "dev-fingerprint"
	if raw, err := os.ReadFile("/etc/pmx-cloud/host-fingerprint"); err == nil {
		if v := strings.TrimSpace(string(raw)); v != "" {
			hostFingerprint = v
		}
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

	log.Info("pmx-security starting", "version", Version, "backend", cfg.Backend.URL)
	return client.Run(sigCtx)
}

type securityHandler struct {
	cfg      *config.Config
	auditLog *audit.Log
	log      *slog.Logger
	clientMu sync.RWMutex
	client   *wsclient.Client
}

func (h *securityHandler) OnConnect(ctx context.Context, c *wsclient.Client) error {
	h.clientMu.Lock()
	h.client = c
	h.clientMu.Unlock()
	h.log.Info("pmx-security: connected to backend")
	return nil
}

func (h *securityHandler) OnEnvelope(ctx context.Context, env *envpkg.Envelope) ([]byte, error) {
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

func (h *securityHandler) dispatch(ctx context.Context, env *envpkg.Envelope) ([]byte, error) {
	params := env.Params
	if params == nil {
		params = map[string]any{}
	}

	switch env.Command {
	case "lynis.run":
		reportPath := stringParam(params, "report_path", "/var/log/lynis-report.dat")
		res, err := lynis.Run(ctx, h.cfg.Lynis.Binary, h.cfg.Lynis.Profile, reportPath, func(step string) {
			h.log.Info("lynis step", "job_id", env.JobID, "step", step)
			h.emitStepFrame(env.JobID, env.Command, step)
		}, nil)
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(res)

	case "compliance.report":
		baseline := stringParam(params, "baseline", "cis-debian-level1")
		rep, err := compliance.RunReport(ctx, baseline, nil)
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(rep)

	case "hardening.apply":
		var p hardening.ApplyParams
		if err := decodeParams(params, &p); err != nil {
			return errJSON(err), err
		}
		p.JobID = env.JobID
		if p.StateDir == "" {
			p.StateDir = h.cfg.State.Dir
		}
		res, err := hardening.Apply(ctx, p, nil)
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(res)

	case "rpcbind.disable":
		if err := hardening.RPCBindDisable(ctx, env.JobID, nil); err != nil {
			return errJSON(err), err
		}
		return okJSON(), nil

	case "ssh.audit":
		res, err := ssh.Audit(stringParam(params, "config_path", ""), stringParam(params, "dropin_dir", ""))
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(res)

	case "ssh.harden":
		if err := ssh.Harden(ctx, ssh.HardenParams{JobID: env.JobID, StateDir: h.cfg.State.Dir}, nil); err != nil {
			return errJSON(err), err
		}
		return okJSON(), nil

	case "audit.enable":
		if err := auditd.Enable(ctx, env.JobID, h.cfg.State.Dir, nil); err != nil {
			return errJSON(err), err
		}
		return okJSON(), nil

	case "audit.disable":
		if err := auditd.Disable(ctx, env.JobID, nil); err != nil {
			return errJSON(err), err
		}
		return okJSON(), nil

	case "audit.query":
		var p auditd.QueryParams
		if err := decodeParams(params, &p); err != nil {
			return errJSON(err), err
		}
		lines, err := auditd.Query(ctx, p)
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(map[string]any{"lines": lines})

	case "security.cvedb.update":
		var p cve.UpdateParams
		if err := decodeParams(params, &p); err != nil {
			return errJSON(err), err
		}
		if p.DBPath == "" {
			p.DBPath = h.cfg.CVE.DBPath
		}
		p.KeysetPath = h.cfg.CVE.SignatureKeysetPath
		if err := cve.UpdateDB(p); err != nil {
			return errJSON(err), err
		}
		return okJSON(), nil

	case "cve.scan":
		res, err := cve.Scan(ctx, h.cfg.CVE.DBPath, nil)
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(res)

	case "cert.audit":
		var p cert.AuditParams
		if err := decodeParams(params, &p); err != nil {
			return errJSON(err), err
		}
		res, err := cert.Audit(ctx, p)
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(res)

	default:
		h.log.Warn("pmx-security: unsupported command", "command", env.Command, "job_id", env.JobID)
		err := fmt.Errorf("UNSUPPORTED: %s", env.Command)
		return errJSON(err), err
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

func (h *securityHandler) emitStepFrame(jobID, command, step string) {
	if strings.TrimSpace(step) == "" {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"type":      "step",
		"jobId":     jobID,
		"command":   command,
		"step":      step,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		h.log.Warn("pmx-security: step frame marshal failed", "err", err)
		return
	}

	h.clientMu.RLock()
	client := h.client
	h.clientMu.RUnlock()
	if client == nil {
		return
	}
	if err := client.SendRaw(payload); err != nil {
		h.log.Warn("pmx-security: step frame send failed", "job_id", jobID, "command", command, "err", err)
	}
}
