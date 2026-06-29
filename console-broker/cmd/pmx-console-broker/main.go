/*
Command pmx-console-broker handles one console session per process.

Flow:
 1. Read one signed envelope from stdin (sealed memfd from pmx-core).
 2. Verify envelope and parse console.open params.
 3. Connect local Proxmox console endpoint (vnc/spice/serial).
 4. Connect backend WS and authenticate with session token first frame.
 5. Bridge both directions until disconnect or expiry, then exit.
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pmx-cloud/agents/console-broker/internal/bridge"
	"github.com/pmx-cloud/agents/console-broker/internal/config"
	"github.com/pmx-cloud/agents/console-broker/internal/serial"
	"github.com/pmx-cloud/agents/console-broker/internal/session"
	"github.com/pmx-cloud/agents/console-broker/internal/spice"
	"github.com/pmx-cloud/agents/console-broker/internal/vnc"
	"github.com/pmx-cloud/agents/shared/audit"
	envpkg "github.com/pmx-cloud/agents/shared/envelope"
	"github.com/pmx-cloud/agents/shared/preflight"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

const agentClass = "pmx-console-broker"

func main() {
	var (
		configPath  = flag.String("config", "/etc/pmx-cloud/pmx-console-broker.conf", "path to config")
		isPreflight = flag.Bool("preflight", false, "validate config and exit")
		isVersion   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	log := slog.Default()
	if *isVersion {
		fmt.Printf("pmx-console-broker version %s commit %s built %s\n", Version, Commit, BuildDate)
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
		Name: "qm-binary-readable",
		Run: func(ctx context.Context) error {
			_, err := os.Stat(cfg.Console.QMBinary)
			return err
		},
	})
	if *isPreflight {
		os.Exit(preflight.Run(checks))
	}

	if err := run(cfg, log); err != nil {
		log.Error("pmx-console-broker failed", "err", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config, log *slog.Logger) error {
	start := time.Now()
	_ = os.MkdirAll("/var/log/pmx-cloud", 0o750)
	auditLog, err := audit.Open("/var/log/pmx-cloud/pmx-console-broker.audit.log")
	if err != nil {
		auditLog, _ = audit.Open("/tmp/pmx-console-broker.audit.log")
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

	req, err := session.FromEnvelope(env, cfg.Limits.DefaultRateLimitMbps, cfg.Policy.AllowedBackendHostSuffixes)
	if err != nil {
		appendAudit(auditLog, audit.Entry{
			Timestamp:  time.Now(),
			JobID:      env.JobID,
			Command:    env.Command,
			Step:       "reject:bad_request",
			Exit:       1,
			DurationMs: time.Since(start).Milliseconds(),
		})
		return err
	}

	ctx, cancel := context.WithDeadline(context.Background(), req.ExpiresAt)
	defer cancel()

	localConn, err := openLocalConsole(ctx, cfg, req)
	if err != nil {
		appendAudit(auditLog, audit.Entry{
			Timestamp:  time.Now(),
			JobID:      req.JobID,
			Command:    env.Command,
			Step:       "local_console_failed",
			Exit:       1,
			DurationMs: time.Since(start).Milliseconds(),
		})
		return err
	}
	defer localConn.Close()

	wsConn, err := bridge.DialBackend(ctx, req.BackendWSURL, cfg.Identity.Cert, cfg.Identity.Key, req.SessionToken)
	if err != nil {
		appendAudit(auditLog, audit.Entry{
			Timestamp:  time.Now(),
			JobID:      req.JobID,
			Command:    env.Command,
			Step:       "backend_ws_failed",
			Exit:       1,
			DurationMs: time.Since(start).Milliseconds(),
		})
		return err
	}
	defer wsConn.Close()

	metrics, err := bridge.Run(ctx, localConn, wsConn, bridge.Options{RateLimitMbps: req.RateLimitMbps})
	if err != nil {
		appendAudit(auditLog, audit.Entry{
			Timestamp:  time.Now(),
			JobID:      req.JobID,
			Command:    env.Command,
			Step:       "bridge_failed",
			Exit:       1,
			DurationMs: time.Since(start).Milliseconds(),
		})
		return err
	}
	appendAudit(auditLog, audit.Entry{
		Timestamp:  time.Now(),
		JobID:      req.JobID,
		Command:    env.Command,
		Step:       "complete",
		Exit:       0,
		DurationMs: time.Since(start).Milliseconds(),
	})
	log.Info("console session ended",
		"job_id", req.JobID,
		"vmid", req.VMID,
		"protocol", req.DisplayProtocol,
		"bytes_local_to_ws", metrics.BytesLocalToWS,
		"bytes_ws_to_local", metrics.BytesWSToLocal,
		"frames_to_ws", metrics.FramesToWS,
		"frames_from_ws", metrics.FramesFromWS,
		"started_at", metrics.StartedAt.Format(time.RFC3339Nano),
		"ended_at", metrics.EndedAt.Format(time.RFC3339Nano),
	)
	return nil
}

func readAndVerifyEnvelope(cfg *config.Config) (*envpkg.Envelope, error) {
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
	replayStore, err := openReplayStore(cfg.State.ReplayCachePath, 2*time.Hour)
	if err != nil {
		return nil, err
	}
	defer replayStore.Close()
	replay := replayStore.ReplayCache()
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
	if err := replayStore.Remember(env.JobID); err != nil {
		return env, err
	}
	return env, nil
}

func openLocalConsole(ctx context.Context, cfg *config.Config, req *session.OpenRequest) (net.Conn, error) {
	switch req.DisplayProtocol {
	case "vnc":
		return vnc.Connect(ctx, cfg.Console.QemuRunDir, req.VMID)
	case "serial":
		return serial.Connect(ctx, cfg.Console.QemuRunDir, req.VMID)
	case "spice":
		return spice.Open(ctx, cfg.Console.QMBinary, req.VMID, nil)
	default:
		return nil, fmt.Errorf("UNSUPPORTED: display protocol %s", req.DisplayProtocol)
	}
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
