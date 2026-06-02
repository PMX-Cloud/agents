/*
Command pmx-hypervisor owns every VM, CT, and Proxmox cluster mutation.

It is the only agent that runs as root. Privilege is mediated by AppArmor
(mandatory) and a strict command allowlist. No bash -c anywhere.

Flags:

	--config /path/to/pmx-hypervisor.conf
	--preflight
	--version
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
	"sync"
	"syscall"
	"time"

	"github.com/pmx-cloud/agents/hypervisor/internal/cluster"
	hypCfg "github.com/pmx-cloud/agents/hypervisor/internal/config"
	"github.com/pmx-cloud/agents/hypervisor/internal/ct"
	"github.com/pmx-cloud/agents/hypervisor/internal/iso"
	"github.com/pmx-cloud/agents/hypervisor/internal/provider"
	libvirtprov "github.com/pmx-cloud/agents/hypervisor/internal/providers/libvirt"
	noneprov "github.com/pmx-cloud/agents/hypervisor/internal/providers/none"
	proxmoxprov "github.com/pmx-cloud/agents/hypervisor/internal/providers/proxmox"
	"github.com/pmx-cloud/agents/hypervisor/internal/provisioning"
	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
	"github.com/pmx-cloud/agents/hypervisor/internal/snapshot"
	"github.com/pmx-cloud/agents/hypervisor/internal/template"
	"github.com/pmx-cloud/agents/hypervisor/internal/vm"
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

const agentClass = "pmx-hypervisor"

func main() {
	var (
		configPath  = flag.String("config", "/etc/pmx-cloud/pmx-hypervisor.conf", "path to config")
		isPreflight = flag.Bool("preflight", false, "validate config and exit")
		isVersion   = flag.Bool("version", false, "print version and exit")
		providerArg = flag.String(
			"provider",
			"auto",
			"hypervisor backend: auto | proxmox | libvirt | none",
		)
	)
	flag.Parse()

	log := slog.Default()

	if *isVersion {
		fmt.Printf("pmx-hypervisor version %s commit %s built %s\n", Version, Commit, BuildDate)
		os.Exit(0)
	}

	cfg, err := hypCfg.Load(*configPath)
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	kind := resolveProviderKind(*providerArg)
	log.Info("hypervisor provider selected",
		"requested", *providerArg, "resolved", string(kind))

	requiredBinaries := []string{}
	if kind == provider.KindProxmox {
		requiredBinaries = []string{
			cfg.Proxmox.PveshPath,
			cfg.Proxmox.QmPath,
			cfg.Proxmox.PctPath,
		}
	}
	checks := preflight.StandardChecks(agentClass, *configPath,
		cfg.Identity.Cert, cfg.Identity.Key, cfg.Keyset.Path, requiredBinaries)
	if *isPreflight {
		os.Exit(preflight.Run(checks))
	}

	if err := run(cfg, log, kind); err != nil {
		log.Error("pmx-hypervisor exited with error", "err", err)
		os.Exit(1)
	}
}

// resolveProviderKind maps the --provider flag value to the runtime backend.
// "auto" probes the host (provider.Detect); the explicit values bypass the
// probe so an operator can force, e.g., the "none" provider on a Proxmox host
// for testing.
func resolveProviderKind(arg string) provider.Kind {
	switch arg {
	case "auto", "":
		return provider.Detect()
	case "proxmox":
		return provider.KindProxmox
	case "libvirt":
		return provider.KindLibvirt
	case "none":
		return provider.KindNone
	default:
		return provider.Detect()
	}
}

// buildProvider returns the concrete Provider for the resolved Kind. The
// Proxmox provider is wired to the existing pveexec-backed implementation;
// libvirt and none are scaffolding stubs whose Discover() output is the
// only piece exercised today.
func buildProvider(kind provider.Kind, exec proxmox.ExecIface) provider.Provider {
	switch kind {
	case provider.KindProxmox:
		return proxmoxprov.New(exec)
	case provider.KindLibvirt:
		return libvirtprov.New()
	default:
		return noneprov.New()
	}
}

func run(cfg *hypCfg.Config, log *slog.Logger, kind provider.Kind) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ks, err := envpkg.LoadKeySet(cfg.Keyset.Path)
	if err != nil {
		return fmt.Errorf("load keyset: %w", err)
	}
	cache := envpkg.NewReplayCache(100_000, 24*time.Hour)
	defer cache.Close()

	auditLog, err := audit.Open("/var/log/pmx-cloud/pmx-hypervisor.audit.log")
	if err != nil {
		auditLog, _ = audit.Open("/tmp/pmx-hypervisor.audit.log")
	}
	defer auditLog.Close()

	// Concurrency semaphores.
	vmCreateSem := make(chan struct{}, cfg.Limits.MaxConcurrentVMCreate)
	migrateSem := make(chan struct{}, cfg.Limits.MaxConcurrentMigration)
	for range cfg.Limits.MaxConcurrentVMCreate {
		vmCreateSem <- struct{}{}
	}
	for range cfg.Limits.MaxConcurrentMigration {
		migrateSem <- struct{}{}
	}

	// The Provider is reported in the agent.register payload via Discover().
	// Today only Discover() is consumed by the backend; VM/CT ops continue
	// to dispatch through the legacy job router. Wiring the router through
	// the Provider interface is tracked in the node-first plan (Phase 3).
	bootExec := &proxmox.Exec{
		PveshPath: cfg.Proxmox.PveshPath,
		QmPath:    cfg.Proxmox.QmPath,
		PctPath:   cfg.Proxmox.PctPath,
		PvesmPath: cfg.Proxmox.PvesmPath,
		PvecmPath: cfg.Proxmox.PvecmPath,
		AuditLog:  auditLog,
		Logger:    log,
		JobID:     "boot",
	}
	hostProvider := buildProvider(kind, bootExec)
	caps, capErr := hostProvider.Discover(ctx)
	if capErr != nil {
		log.Warn("hypervisor discover failed", "kind", string(kind), "err", capErr)
	} else {
		log.Info("hypervisor capabilities discovered",
			"hypervisor", caps.Hypervisor,
			"storage", caps.Storage,
			"network", caps.Network,
		)
	}

	h := &hypervisorHandler{
		cfg:         cfg,
		auditLog:    auditLog,
		vmCreateSem: vmCreateSem,
		migrateSem:  migrateSem,
		log:         log,
		provider:    hostProvider,
	}

	// Build the structured capability payload for agent.register. Mirrors the
	// agents/hypervisor/internal/provider Capabilities struct so the backend
	// can persist it directly onto nodes.capabilities.
	capabilitiesMap := map[string]any{
		"hypervisor.provider": caps.Hypervisor,
	}
	if len(caps.Storage) > 0 {
		capabilitiesMap["storage"] = caps.Storage
	}
	if len(caps.Network) > 0 {
		capabilitiesMap["network"] = caps.Network
	}
	if len(caps.Backup) > 0 {
		capabilitiesMap["backup"] = caps.Backup
	}
	if len(caps.Console) > 0 {
		capabilitiesMap["console"] = caps.Console
	}

	client, err := wsclient.New(wsclient.Config{
		BackendURL:        cfg.Backend.URL,
		AgentClass:        agentClass,
		CertPath:          cfg.Identity.Cert,
		KeyPath:           cfg.Identity.Key,
		KeySet:            ks,
		ReplayCache:       cache,
		HostFingerprint:   "dev-fingerprint",
		HypervisorType:    string(kind),
		Capabilities:      capabilitiesMap,
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

	log.Info("pmx-hypervisor starting", "version", Version, "backend", cfg.Backend.URL)
	return client.Run(sigCtx)
}

// hypervisorHandler dispatches pmx-hypervisor commands.
type hypervisorHandler struct {
	cfg         *hypCfg.Config
	auditLog    *audit.Log
	vmCreateSem chan struct{}
	migrateSem  chan struct{}
	log         *slog.Logger
	mu          sync.Mutex
	// provider is the active hypervisor backend selected at startup. Today
	// it is consulted only for capability discovery (reported to the backend
	// at agent.register time). VM/CT ops still flow through the legacy job
	// router; migrating those to the Provider interface is Phase 3 of the
	// node-first architecture plan.
	provider provider.Provider
}

func (h *hypervisorHandler) OnConnect(ctx context.Context, c *wsclient.Client) error {
	h.log.Info("pmx-hypervisor: connected to backend")
	return nil
}

func (h *hypervisorHandler) OnEnvelope(ctx context.Context, env *envpkg.Envelope) ([]byte, error) {
	start := time.Now()
	px := h.newExec(env.JobID)
	result, err := h.dispatch(ctx, env, px)
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
	return result, err
}

func (h *hypervisorHandler) newExec(jobID string) *proxmox.Exec {
	return &proxmox.Exec{
		PveshPath: h.cfg.Proxmox.PveshPath,
		QmPath:    h.cfg.Proxmox.QmPath,
		PctPath:   h.cfg.Proxmox.PctPath,
		PvesmPath: h.cfg.Proxmox.PvesmPath,
		PvecmPath: h.cfg.Proxmox.PvecmPath,
		AuditLog:  h.auditLog,
		Logger:    h.log,
		JobID:     jobID,
	}
}

func noopStep(s string) {} // step callback stub for commands that don't stream

func (h *hypervisorHandler) dispatch(ctx context.Context, env *envpkg.Envelope, px *proxmox.Exec) ([]byte, error) {
	params := env.Params
	if params == nil {
		params = map[string]any{}
	}
	// Inject job_id for provisioning.
	params["job_id"] = env.JobID

	switch env.Command {
	// ── VM lifecycle ──────────────────────────────────────────────────────
	case "vm.create":
		h.vmCreateSem <- struct{}{}
		defer func() { <-h.vmCreateSem }()
		return okOrErr(vm.Create(ctx, px, params, noopStep))

	case "vm.update":
		return okOrErr(vm.Update(ctx, px, params))
	case "vm.start":
		return okOrErr(vm.Start(ctx, px, params))
	case "vm.stop":
		return okOrErr(vm.Stop(ctx, px, params))
	case "vm.reboot":
		return okOrErr(vm.Reboot(ctx, px, params))
	case "vm.reset":
		return okOrErr(vm.Reset(ctx, px, params))
	case "vm.suspend":
		return okOrErr(vm.Suspend(ctx, px, params))
	case "vm.resume":
		return okOrErr(vm.Resume(ctx, px, params))
	case "vm.delete":
		return okOrErr(vm.Delete(ctx, px, params))
	case "vm.migrate":
		h.migrateSem <- struct{}{}
		defer func() { <-h.migrateSem }()
		return okOrErr(vm.Migrate(ctx, px, params, noopStep))

	// ── Disk ──────────────────────────────────────────────────────────────
	case "vm.disk.attach":
		return okOrErr(vm.DiskAttach(ctx, px, params))
	case "vm.disk.detach":
		return okOrErr(vm.DiskDetach(ctx, px, params))
	case "vm.disk.resize":
		return okOrErr(vm.DiskResize(ctx, px, params))

	// ── Snapshots ─────────────────────────────────────────────────────────
	case "vm.snapshot.create":
		return okOrErr(snapshot.Create(ctx, px, params))
	case "vm.snapshot.delete":
		return okOrErr(snapshot.Delete(ctx, px, params))
	case "vm.snapshot.rollback":
		return okOrErr(snapshot.Rollback(ctx, px, params))
	case "vm.snapshot.list":
		out, err := snapshot.List(ctx, px, params)
		if err != nil {
			return errJSON(err), err
		}
		return json.Marshal(map[string]string{"snapshots": out})

	// ── Templates + ISOs ──────────────────────────────────────────────────
	case "vm.template.convert":
		return okOrErr(template.Convert(ctx, px, params))
	case "vm.template.clone":
		return okOrErr(template.Clone(ctx, px, params))
	case "vm.iso.upload":
		return okOrErr(iso.Upload(ctx, px, params))

	// ── Container lifecycle ───────────────────────────────────────────────
	case "ct.create":
		h.vmCreateSem <- struct{}{}
		defer func() { <-h.vmCreateSem }()
		return okOrErr(ct.Create(ctx, px, params, noopStep))
	case "ct.update":
		return okOrErr(ct.Update(ctx, px, params))
	case "ct.delete":
		return okOrErr(ct.Delete(ctx, px, params))
	case "ct.start":
		return okOrErr(ct.Start(ctx, px, params))
	case "ct.stop":
		return okOrErr(ct.Stop(ctx, px, params))
	case "ct.reboot":
		return okOrErr(ct.Reboot(ctx, px, params))
	case "ct.mount.add":
		return okOrErr(ct.MountAdd(ctx, px, params))
	case "ct.mount.remove":
		return okOrErr(ct.MountRemove(ctx, px, params))

	// ── Cluster ops ───────────────────────────────────────────────────────
	case "pve.cluster.join":
		return okOrErr(cluster.Join(ctx, px, params))
	case "pve.cluster.leave":
		return okOrErr(cluster.Leave(ctx, px, params))
	case "pve.cluster.status":
		raw, err := cluster.Status(ctx, px)
		if err != nil {
			return errJSON(err), err
		}
		return raw, nil

	// ── Provisioning ──────────────────────────────────────────────────────
	case "provisioning.apply":
		return okOrErr(provisioning.Apply(ctx, px, params))
	case "provisioning.cleanup":
		return okOrErr(provisioning.Cleanup(params))

	// ── Guided builds ─────────────────────────────────────────────────────
	case "vm.create.synology-dsm":
		h.vmCreateSem <- struct{}{}
		defer func() { <-h.vmCreateSem }()
		return okOrErr(vm.Create(ctx, px, vm.SynologyDSMParams(params), noopStep))
	case "vm.create.zimaos":
		h.vmCreateSem <- struct{}{}
		defer func() { <-h.vmCreateSem }()
		return okOrErr(vm.Create(ctx, px, vm.ZimaOSParams(params), noopStep))

	default:
		h.log.Warn("pmx-hypervisor: unsupported command", "command", env.Command, "job_id", env.JobID)
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
