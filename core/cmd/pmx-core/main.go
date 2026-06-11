/*
Command pmx-core is the supervisor and job router for the PMX-Cloud agent fleet.

It is the ONLY mandatory agent on every host. All other agents are optional and
managed by pmx-core itself.

Flags:

	--config /path/to/pmx-core.conf   (default /etc/pmx-cloud/pmx-core.conf)
	--preflight                       validate config and exit 0/1
	--enroll --token=<one-time-token> exchange enrollment token for mTLS cert
	--version                         print version and exit
*/
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pmx-cloud/agents/core/internal/capability"
	coreCfg "github.com/pmx-cloud/agents/core/internal/config"
	"github.com/pmx-cloud/agents/core/internal/drain"
	"github.com/pmx-cloud/agents/core/internal/enroll"
	"github.com/pmx-cloud/agents/core/internal/keyset"
	"github.com/pmx-cloud/agents/core/internal/siblings"
	"github.com/pmx-cloud/agents/core/internal/spawn"
	"github.com/pmx-cloud/agents/core/internal/wire"
	"github.com/pmx-cloud/agents/shared/audit"
	sharedcap "github.com/pmx-cloud/agents/shared/capability"
	envpkg "github.com/pmx-cloud/agents/shared/envelope"
	"github.com/pmx-cloud/agents/shared/preflight"
	"github.com/pmx-cloud/agents/shared/wsclient"
)

// Build-time variables (set by -ldflags).
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
	// ReleasePubKeyHex is the hex-encoded Ed25519 release public key baked in at
	// build time.  Empty on dev builds (before the key ceremony).  When non-empty
	// it is preferred over the on-disk keyset for release-key operations (e.g.
	// emergency override validation in the updater dispatch path).
	ReleasePubKeyHex = ""
)

const agentClass = "pmx-core"

func main() {
	var (
		configPath  = flag.String("config", "/etc/pmx-cloud/pmx-core.conf", "path to config file")
		isPreflight = flag.Bool("preflight", false, "validate config and exit")
		isEnroll    = flag.Bool("enroll", false, "run enrollment")
		token       = flag.String("token", "", "one-time enrollment token (used with --enroll)")
		isVersion   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	log := slog.Default()

	if *isVersion {
		fmt.Printf("pmx-core version %s commit %s built %s\n", Version, Commit, BuildDate)
		os.Exit(0)
	}

	// ── Load config ──────────────────────────────────────────────────────────
	cfg, err := coreCfg.Load(*configPath)
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	// ── Preflight ────────────────────────────────────────────────────────────
	checks := preflight.StandardChecks(
		agentClass,
		*configPath,
		cfg.Identity.Cert,
		cfg.Identity.Key,
		cfg.Keyset.Path,
		nil,
	)
	if *isPreflight {
		os.Exit(preflight.Run(checks))
	}

	// ── Enrollment ───────────────────────────────────────────────────────────
	if *isEnroll {
		enrollCfg := &enroll.Config{
			EnrollURL: deriveEnrollURL(cfg.Backend.URL),
			CertDir:   "/etc/pmx-cloud/pmx-core",
			Token:     *token,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := enroll.Run(ctx, enrollCfg); err != nil {
			log.Error("enrollment failed", "err", err)
			os.Exit(1)
		}
		log.Info("enrollment successful; run pmx-core --preflight to verify")
		os.Exit(0)
	}

	// ── Runtime startup ──────────────────────────────────────────────────────
	if err := run(cfg, *configPath, log); err != nil {
		log.Error("pmx-core exited with error", "err", err)
		os.Exit(1)
	}
}

// run is the main runtime: wires all subsystems and blocks until SIGTERM/SIGINT.
func run(cfg *coreCfg.Config, configPath string, log *slog.Logger) error {
	// Root context cancelled on shutdown.
	ctx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()

	// ── Keyset ───────────────────────────────────────────────────────────────
	ks, err := envpkg.LoadKeySet(cfg.Keyset.Path)
	if err != nil {
		return fmt.Errorf("load keyset: %w", err)
	}
	cache := envpkg.NewReplayCache(100_000, 24*time.Hour)
	defer cache.Close()

	// Host fingerprint.
	hostInfo := capability.Collect(ctx)
	fingerprint := hostInfo.HostFingerprint

	// ── Audit log ────────────────────────────────────────────────────────────
	auditLog, err := audit.Open("/var/log/pmx-cloud/pmx-core.audit.log")
	if err != nil {
		auditLog, err = audit.Open("/tmp/pmx-core.audit.log")
		if err != nil {
			return fmt.Errorf("open audit log: %w", err)
		}
		log.Warn("using temp audit log path")
	}
	defer auditLog.Close()

	// ── Subsystems ───────────────────────────────────────────────────────────
	sibMgr := siblings.NewManager(cfg.Siblings.Allowed, cfg.Siblings.EphemeralTemplates, log)
	drainer := drain.NewDrainer(sibMgr, cancelRoot, log)
	spawner := spawn.NewSpawner(log)
	keyRotator := &keyset.Rotator{
		KeysetPath:    cfg.Keyset.Path,
		CurrentKeySet: ks,
	}

	// ── Router ───────────────────────────────────────────────────────────────
	router := wire.NewRouter(log)

	// core.identify
	router.Register("core.identify", func(ctx context.Context, env *envpkg.Envelope) (json.RawMessage, error) {
		capability.InvalidateCache()
		info := capability.Collect(ctx)
		return json.Marshal(info)
	})

	// core.agents.list
	router.Register("core.agents.list", func(ctx context.Context, env *envpkg.Envelope) (json.RawMessage, error) {
		info := capability.Collect(ctx)
		return json.Marshal(map[string]interface{}{"agents": info.Agents})
	})

	// core.agents.enable
	router.Register("core.agents.enable", func(ctx context.Context, env *envpkg.Envelope) (json.RawMessage, error) {
		unit, _ := env.Params["unit"].(string)
		if err := sibMgr.Enable(ctx, unit); err != nil {
			return errorJSON("ENABLE_FAILED", err.Error()), nil
		}
		return okJSON(), nil
	})

	// core.agents.disable
	router.Register("core.agents.disable", func(ctx context.Context, env *envpkg.Envelope) (json.RawMessage, error) {
		unit, _ := env.Params["unit"].(string)
		if err := sibMgr.Disable(ctx, unit); err != nil {
			return errorJSON("DISABLE_FAILED", err.Error()), nil
		}
		return okJSON(), nil
	})

	// core.spawn.ephemeral
	router.Register("core.spawn.ephemeral", func(ctx context.Context, env *envpkg.Envelope) (json.RawMessage, error) {
		template, _ := env.Params["template"].(string)
		if template == "" {
			return errorJSON("MISSING_PARAM", "params.template is required"), nil
		}
		if !sibMgr.Allow(template) {
			return errorJSON("NOT_ALLOWED", fmt.Sprintf("template %q is not in the allowlist", template)), nil
		}
		// When the backend includes a nested signed envelope (base64 CBOR),
		// the spawned agent receives THAT envelope instead of this outer
		// core.spawn.ephemeral one. Required for agents like console-broker
		// that verify command + audience themselves (the outer envelope is
		// addressed to pmx-core and would always be rejected). pmx-core does
		// not verify the nested envelope — the child does, against the same
		// keyset.
		childEnv := env
		jobID := env.JobID
		if nested, ok := env.Params["envelope"].(string); ok && nested != "" {
			raw, err := base64.StdEncoding.DecodeString(nested)
			if err != nil {
				return errorJSON("BAD_ENVELOPE", "params.envelope is not valid base64"), nil
			}
			parsed, err := envpkg.Unmarshal(raw)
			if err != nil {
				return errorJSON("BAD_ENVELOPE", fmt.Sprintf("nested envelope: %v", err)), nil
			}
			childEnv = parsed
			if parsed.JobID != "" {
				jobID = parsed.JobID
			}
		}
		req := spawn.EphemeralRequest{
			Template: template,
			JobID:    jobID,
			Envelope: childEnv,
		}
		if err := spawner.Spawn(ctx, req); err != nil {
			return errorJSON("SPAWN_FAILED", err.Error()), nil
		}
		return okJSON(), nil
	})

	// core.keyset.update
	router.Register("core.keyset.update", keyRotator.Handle)

	// core.preflight
	router.Register("core.preflight", func(ctx context.Context, env *envpkg.Envelope) (json.RawMessage, error) {
		checks := preflight.StandardChecks(
			agentClass, configPath, cfg.Identity.Cert,
			cfg.Identity.Key, cfg.Keyset.Path, nil,
		)
		// Collect results.
		results := map[string]string{}
		for _, c := range checks {
			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := c.Run(checkCtx); err != nil {
				results[c.Name] = "FAIL: " + err.Error()
			} else {
				results[c.Name] = "PASS"
			}
			cancel()
		}
		return json.Marshal(results)
	})

	// core.capabilities — declare pmx-core's own commands into the shared
	// capability registry, then expose the full registry via this handler.
	// Architecture §5.1: the backend queries this to track capability drift
	// across rollouts (which commands a host supports after an update).
	for _, cmd := range router.Commands() {
		sharedcap.Declare(sharedcap.Capability{
			Command:    cmd,
			Version:    1,
			Stability:  sharedcap.Stable,
			AgentClass: agentClass,
		})
	}
	router.Register("core.capabilities", func(_ context.Context, _ *envpkg.Envelope) (json.RawMessage, error) {
		caps := sharedcap.List()
		return json.Marshal(map[string]interface{}{
			"agent":        agentClass,
			"version":      Version,
			"capabilities": caps,
		})
	})
	// Also declare core.capabilities itself (registered after the initial loop).
	sharedcap.Declare(sharedcap.Capability{
		Command:    "core.capabilities",
		Version:    1,
		Stability:  sharedcap.Stable,
		AgentClass: agentClass,
	})

	// core.shutdown
	router.Register("core.shutdown", drainer.Handle)

	// ── WS client ────────────────────────────────────────────────────────────
	h := &coreHandler{
		router:   router,
		drainer:  drainer,
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
		HostFingerprint:   fingerprint,
		HeartbeatInterval: cfg.Heartbeat.HeartbeatInterval(),
		HeartbeatTimeout:  cfg.Heartbeat.HeartbeatTimeout(),
		Handler:           h,
		Logger:            log,
		AuditChainHead:    auditLog.Head,
	})
	if err != nil {
		return fmt.Errorf("wsclient init: %w", err)
	}

	// ── Signal handling ──────────────────────────────────────────────────────
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Info("pmx-core starting",
		"version", Version,
		"fingerprint", fingerprint,
		"backend", cfg.Backend.URL,
	)

	return client.Run(sigCtx)
}

// coreHandler is the wsclient.Handler implementation for pmx-core.
type coreHandler struct {
	router   *wire.Router
	drainer  *drain.Drainer
	auditLog *audit.Log
	log      *slog.Logger
}

func (h *coreHandler) OnConnect(ctx context.Context, c *wsclient.Client) error {
	h.log.Info("pmx-core: connected to backend")
	return nil
}

func (h *coreHandler) OnEnvelope(ctx context.Context, env *envpkg.Envelope) ([]byte, error) {
	// Drain check: reject new commands if draining.
	if payload, draining := h.drainer.RejectIfDraining(); draining {
		return payload, nil
	}

	start := time.Now()
	result, dispatchErr := h.router.Dispatch(ctx, env)
	elapsed := time.Since(start).Milliseconds()

	exit := 0
	if dispatchErr != nil {
		exit = 1
	}

	// Audit every dispatched command.
	if _, err := h.auditLog.Append(audit.Entry{
		Timestamp:  time.Now(),
		JobID:      env.JobID,
		Command:    env.Command,
		Step:       "complete",
		Exit:       exit,
		DurationMs: elapsed,
	}); err != nil {
		h.log.Error("audit append failed", "err", err)
	}

	// Wrap in the standard result frame.
	frame := resultFrame{
		Type:    "result",
		JobID:   env.JobID,
		Payload: result,
	}
	if dispatchErr != nil {
		frame.Error = dispatchErr.Error()
	}
	b, _ := json.Marshal(frame)
	return b, nil
}

type resultFrame struct {
	Type    string          `json:"type"`
	JobID   string          `json:"jobId"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// deriveEnrollURL converts the WS URL to an HTTPS enroll endpoint.
// wss://api.example.com/ws/agent/core → https://api.example.com/agents/enroll
func deriveEnrollURL(wsURL string) string {
	s := strings.Replace(wsURL, "wss://", "https://", 1)
	// Strip any ws-specific path.
	if idx := strings.Index(s, "/ws/"); idx >= 0 {
		s = s[:idx]
	}
	return s + "/agents/enroll"
}

// rssKB returns the current process RSS in kilobytes by reading /proc/self/status.
func rssKB() int64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.ParseInt(fields[1], 10, 64)
				return v
			}
		}
	}
	return 0
}

func errorJSON(code, message string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"error": code, "message": message})
	return b
}

func okJSON() json.RawMessage {
	return json.RawMessage(`{"ok":true}`)
}
