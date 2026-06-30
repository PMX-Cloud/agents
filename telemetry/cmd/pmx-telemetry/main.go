/*
Command pmx-telemetry is the read-only metrics, events, and heartbeat agent.

It collects host metrics every 10s, evaluates local thresholds, and pushes streams
to the backend. It cannot mutate anything on the host.

Flags:

	--config /path/to/pmx-telemetry.conf
	--preflight
	--version
*/
package main

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/pmx-cloud/agents/telemetry/internal/collectors"
	telCfg "github.com/pmx-cloud/agents/telemetry/internal/config"
	"github.com/pmx-cloud/agents/telemetry/internal/push"
	"github.com/pmx-cloud/agents/telemetry/internal/thresholds"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

const agentClass = "pmx-telemetry"

func main() {
	var (
		configPath  = flag.String("config", "/etc/pmx-cloud/pmx-telemetry.conf", "path to config")
		isPreflight = flag.Bool("preflight", false, "validate config and exit")
		isVersion   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	log := slog.Default()

	if *isVersion {
		fmt.Printf("pmx-telemetry version %s commit %s built %s\n", Version, Commit, BuildDate)
		os.Exit(0)
	}

	cfg, err := telCfg.Load(*configPath)
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	checks := preflight.StandardChecks(agentClass, *configPath,
		cfg.Identity.Cert, cfg.Identity.Key, cfg.Keyset.Path, nil)
	if *isPreflight {
		os.Exit(preflight.Run(checks))
	}

	// A canceled context is graceful shutdown (SIGTERM/SIGINT), not a failure:
	// run() returns wsclient.Run(sigCtx) which yields context.Canceled on signal.
	// Exiting non-zero there makes systemd mark the unit `failed` on every stop
	// (needing a manual reset-failed); exit 0 so a stop is a clean `inactive`.
	if err := run(cfg, log); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("pmx-telemetry exited with error", "err", err)
		os.Exit(1)
	}
}

func run(cfg *telCfg.Config, log *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Keyset + replay cache ─────────────────────────────────────────────────
	ks, err := envpkg.LoadKeySet(cfg.Keyset.Path)
	if err != nil {
		return fmt.Errorf("load keyset: %w", err)
	}
	cache := envpkg.NewReplayCache(100_000, 24*time.Hour)
	defer cache.Close()

	// ── Audit log ────────────────────────────────────────────────────────────
	auditLog, err := audit.OpenWithFallback(
		"/var/log/pmx-cloud/pmx-telemetry.audit.log",
		"/tmp/pmx-telemetry.audit.log",
		log,
	)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	// ── Subsystems ───────────────────────────────────────────────────────────
	ring := push.NewRingBuffer(6000)
	engine := thresholds.NewEngine()
	registry := collectors.NewRegistry(cfg.Features.ProxmoxStatus, cfg.Collection.MetricsInterval(), log)

	// ── WS handler ───────────────────────────────────────────────────────────
	var sender *push.Sender

	h := &telemetryHandler{
		auditLog: auditLog,
		registry: registry,
		engine:   engine,
		sender:   &sender, // pointer-to-pointer; set after client.New
		log:      log,
	}

	// Canonical host fingerprint provisioned by the installer and shared across
	// siblings, so the backend keys this agent to the same node identity.
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
		HeartbeatInterval: 15 * time.Second,
		HeartbeatTimeout:  45 * time.Second,
		Handler:           h,
		Logger:            log,
		AuditChainHead:    auditLog.Head,
	})
	if err != nil {
		return fmt.Errorf("wsclient init: %w", err)
	}

	// Wire sender now that we have a client. SendRaw is thread-safe and returns
	// an error when disconnected; the Sender only calls it while connected and
	// otherwise buffers in the ring for replay on reconnect.
	snd := push.NewSender(ring, client.SendRaw, log)
	*h.sender = snd

	// ── Alert drain goroutine ─────────────────────────────────────────────────
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case alert, ok := <-engine.AlertCh:
				if !ok {
					return
				}
				payload, _ := json.Marshal(alert)
				snd.SendAlert(payload, alert.Cleared)
			}
		}
	}()

	// ── Metrics collection goroutine ──────────────────────────────────────────
	go func() {
		registry.Run(ctx)
	}()

	// registry.Out() must fan out to BOTH the push sender and the threshold
	// engine. Previously two goroutines read the single channel directly, so each
	// batch reached only one of them — the sender was starved and host.metrics
	// were never shipped to the backend. Tee every batch to both consumers.
	senderCh := make(chan []collectors.Metric, 256)
	evalCh := make(chan []collectors.Metric, 256)
	go func() {
		defer close(senderCh)
		defer close(evalCh)
		for {
			select {
			case <-ctx.Done():
				return
			case batch, ok := <-registry.Out():
				if !ok {
					return
				}
				// Non-blocking: a slow/stuck consumer must never wedge collection.
				select {
				case senderCh <- batch:
				default:
				}
				select {
				case evalCh <- batch:
				default:
				}
			}
		}
	}()
	go func() {
		snd.Run(ctx, senderCh)
	}()
	// Evaluation goroutine.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case batch, ok := <-evalCh:
				if !ok {
					return
				}
				engine.Evaluate(batch)
			}
		}
	}()

	// ── Signal handling ──────────────────────────────────────────────────────
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Info("pmx-telemetry starting", "version", Version, "backend", cfg.Backend.URL)
	return client.Run(sigCtx)
}

// telemetryHandler implements wsclient.Handler for pmx-telemetry.
type telemetryHandler struct {
	auditLog *audit.Log
	registry *collectors.Registry
	engine   *thresholds.Engine
	sender   **push.Sender
	log      *slog.Logger
}

func (h *telemetryHandler) OnConnect(ctx context.Context, c *wsclient.Client) error {
	h.log.Info("pmx-telemetry: connected")
	if *h.sender != nil {
		(*h.sender).OnConnect()
	}
	return nil
}

func (h *telemetryHandler) OnEnvelope(ctx context.Context, env *envpkg.Envelope) ([]byte, error) {
	start := time.Now()
	result, dispatchErr := h.dispatch(ctx, env)
	elapsed := time.Since(start).Milliseconds()

	exit := 0
	if dispatchErr != nil {
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

	return result, dispatchErr
}

func (h *telemetryHandler) dispatch(ctx context.Context, env *envpkg.Envelope) ([]byte, error) {
	switch env.Command {
	case "telemetry.snapshot":
		metrics := h.registry.CollectOnce(ctx)
		return json.Marshal(metrics)

	case "telemetry.thresholds.set":
		raw, ok := env.Params["thresholds"]
		if !ok {
			return unsupportedJSON("missing params.thresholds"), nil
		}
		data, err := json.Marshal(raw)
		if err != nil {
			return unsupportedJSON(err.Error()), nil
		}
		if err := h.engine.SetFromJSON(data); err != nil {
			return unsupportedJSON(err.Error()), nil
		}
		return json.Marshal(map[string]bool{"ok": true})

	case "telemetry.subscribe":
		stream, _ := env.Params["stream"].(string)
		if *h.sender != nil && stream != "" {
			(*h.sender).Subscribe(stream)
		}
		return json.Marshal(map[string]bool{"ok": true})

	case "telemetry.unsubscribe":
		stream, _ := env.Params["stream"].(string)
		if *h.sender != nil && stream != "" {
			(*h.sender).Unsubscribe(stream)
		}
		return json.Marshal(map[string]bool{"ok": true})

	default:
		// Refuse all other commands. Must not call any subprocess.
		h.log.Warn("pmx-telemetry: unsupported command (read-only agent)",
			"PMX_JOB_ID", env.JobID, "PMX_COMMAND", env.Command)
		return unsupportedJSON(env.Command), nil
	}
}

func unsupportedJSON(cmd string) []byte {
	b, _ := json.Marshal(map[string]string{
		"error":   "UNSUPPORTED",
		"command": cmd,
	})
	return b
}
