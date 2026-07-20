/*
Command pmx-example is a scaffold template for PMX-Cloud fleet agents.

It demonstrates:
  - --preflight flag (validates config without opening WS)
  - --config flag
  - WS client lifecycle
  - Receiving and acking one signed envelope
  - Clean shutdown on SIGTERM/SIGINT

Copy this directory, rename the binary, and add domain handlers.
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pmx-cloud/agents/shared/audit"
	"github.com/pmx-cloud/agents/shared/envelope"
	"github.com/pmx-cloud/agents/shared/preflight"
	"github.com/pmx-cloud/agents/shared/wsclient"
)

const agentClass = "pmx-example"

func main() {
	configPath := flag.String("config", "/etc/pmx-cloud/pmx-example.conf", "config file path")
	isPreflight := flag.Bool("preflight", false, "validate config and exit without connecting")
	flag.Parse()

	log := slog.Default()

	// ── Preflight ─────────────────────────────────────────────────────────────
	checks := preflight.StandardChecks(
		agentClass,
		*configPath,
		"", // certPath — empty for this scaffold; real agents set these
		"", // keyPath
		"/etc/pmx-cloud/keyset.pub",
	)
	if *isPreflight {
		os.Exit(preflight.Run(checks))
	}

	// ── Config ────────────────────────────────────────────────────────────────
	// Real agents would parse a TOML/YAML config here. For the scaffold we
	// use hard-coded dev values so the binary compiles and runs.
	backendURL := envOr("PMX_BACKEND_URL", "wss://localhost:8443")
	hostFingerprint := envOr("PMX_HOST_FINGERPRINT", "dev-fingerprint")
	keysetPath := envOr("PMX_KEYSET_PATH", "/etc/pmx-cloud/keyset.pub")

	// ── KeySet ────────────────────────────────────────────────────────────────
	// In dev, use a static test keyset. The LoadKeySet fallback creates an
	// empty keyset if the file doesn't exist so the scaffold can still compile.
	var ks *envelope.KeySet
	if _, err := os.Stat(keysetPath); err == nil {
		var loadErr error
		ks, loadErr = envelope.LoadKeySet(keysetPath)
		if loadErr != nil {
			log.Error("keyset load failed", "err", loadErr)
			os.Exit(1)
		}
	} else {
		// Dev fallback: parse an in-memory placeholder (will reject all envelopes).
		log.Warn("keyset file not found — using empty dev keyset; all envelopes will be rejected", "path", keysetPath)
		// We can't create an empty KeySet with ParseKeySet (it rejects empty),
		// so we signal this state via a flag; real agents must have a keyset.
		log.Error("cannot start without a keyset in production")
		os.Exit(1)
	}

	cache := envelope.NewReplayCache(100_000, 24*time.Hour)
	defer cache.Close()

	// ── Audit log ─────────────────────────────────────────────────────────────
	auditLog, err := audit.Open("/var/log/pmx-cloud/pmx-example.audit.log")
	if err != nil {
		// Fall back to temp path in dev.
		tmpPath := "/tmp/pmx-example.audit.log"
		log.Warn("audit log open failed, using temp path", "err", err, "path", tmpPath)
		auditLog, err = audit.Open(tmpPath)
		if err != nil {
			log.Error("cannot open audit log", "err", err)
			os.Exit(1)
		}
	}
	defer auditLog.Close()

	// ── WS client ─────────────────────────────────────────────────────────────
	handler := &exampleHandler{log: log, auditLog: auditLog}
	client, err := wsclient.New(wsclient.Config{
		BackendURL:      backendURL,
		AgentClass:      agentClass,
		KeySet:          ks,
		ReplayCache:     cache,
		HostFingerprint: hostFingerprint,
		Handler:         handler,
		Logger:          log,
		AuditChainHead:  auditLog.Head,
	})
	if err != nil {
		log.Error("wsclient init failed", "err", err)
		os.Exit(1)
	}

	// ── Signal handling ───────────────────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Info("pmx-example starting", "backend", backendURL, "agent", agentClass)
	if err := client.Run(ctx); err != nil && err != context.Canceled {
		log.Error("run error", "err", err)
		os.Exit(1)
	}
	log.Info("pmx-example stopped cleanly")
}

// exampleHandler is the trivial domain handler for the scaffold.
type exampleHandler struct {
	log      *slog.Logger
	auditLog *audit.Log
}

func (h *exampleHandler) OnConnect(ctx context.Context, c *wsclient.Client) error {
	h.log.Info("connected to backend")
	return nil
}

func (h *exampleHandler) OnEnvelope(ctx context.Context, env *envelope.Envelope) ([]byte, error) {
	h.log.Info("received envelope",
		"PMX_JOB_ID", env.JobID,
		"PMX_COMMAND", env.Command,
	)

	start := time.Now()
	result, err := h.dispatch(ctx, env)
	elapsed := time.Since(start).Milliseconds()

	exit := 0
	if err != nil {
		exit = 1
	}

	if _, auditErr := h.auditLog.Append(audit.Entry{
		Timestamp:  time.Now(),
		JobID:      env.JobID,
		Command:    env.Command,
		Step:       "complete",
		Exit:       exit,
		DurationMs: elapsed,
	}); auditErr != nil {
		h.log.Error("audit append failed", "err", auditErr)
	}

	return result, err
}

func (h *exampleHandler) dispatch(_ context.Context, env *envelope.Envelope) ([]byte, error) {
	switch env.Command {
	case "example.ping":
		return []byte(`{"ok":true,"pong":true}`), nil
	default:
		return nil, fmt.Errorf("unknown command: %s", env.Command)
	}
}

func envOr(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
