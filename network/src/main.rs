#![forbid(unsafe_code)]

mod audit;
mod bridge;
mod config;
mod netlink;
mod nftables;
mod ovs;
mod sriov;
mod vlan;
mod wireguard;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use audit::{AuditLog, Event, Severity};
use clap::Parser;
use config::Config;
use futures_util::future::join_all;
use netlink::Runner;
use pmx_shared::capability::{self, Stability};
use pmx_shared::envelope::Envelope;
use pmx_shared::keyset::KeySet;
use pmx_shared::replay::ReplayCache;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber::prelude::*;

const AGENT_CLASS: &str = "pmx-network";

#[derive(Parser, Debug)]
#[command(name = "pmx-network")]
struct Args {
    #[arg(long, default_value = "/etc/pmx-cloud/pmx-network.conf")]
    config: String,
    #[arg(long)]
    preflight: bool,
    #[arg(long)]
    version: bool,
}

#[derive(Clone)]
struct NetworkHandler {
    cfg: Config,
    runner: Runner,
    audit: AuditLog,
}

#[derive(Debug, Deserialize)]
struct BridgeCreateParams {
    name: String,
}

#[derive(Debug, Deserialize)]
struct BridgePortParams {
    bridge: String,
    port: String,
}

#[derive(Debug, Deserialize)]
struct VlanCreateParams {
    parent: String,
    name: String,
    vid: u16,
}

#[derive(Debug, Deserialize)]
struct VlanDestroyParams {
    name: String,
}

#[derive(Debug, Deserialize)]
struct OvsConfigureParams {
    commands: Vec<ovs::OvsCommand>,
}

#[derive(Debug, Deserialize)]
struct SriovParams {
    pf: String,
    num_vfs: u16,
}

#[derive(Debug, Deserialize)]
struct MartianFixParams {
    iface: String,
    rp_filter: u8,
    log_martians: bool,
}

#[derive(Debug, Deserialize)]
struct VerifyParams {
    probes: Vec<Probe>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Probe {
    Ping { target: String },
    Tcp { host: String, port: u16 },
}

#[derive(Debug, Serialize)]
struct ProbeResult {
    probe: String,
    ok: bool,
    error: Option<String>,
}

/// Declare all pmx-network commands in the global capability registry.
/// Called once at boot so the backend can query `*.capabilities`.
fn declare_capabilities() {
    // WireGuard
    capability::declare(AGENT_CLASS, "wg.tunnel.up", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "wg.tunnel.down", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "wg.tunnel.reload", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "wg.tunnel.status", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "wg.peer.add", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "wg.peer.remove", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "wg.peer.list", 1, Stability::Stable);

    // Firewall / nftables
    capability::declare(AGENT_CLASS, "firewall.rules.validate", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "firewall.rules.apply", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "firewall.rules.clear", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "firewall.emergency.lockdown", 1, Stability::Stable);

    // Bridge
    capability::declare(AGENT_CLASS, "bridge.create", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "bridge.destroy", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "bridge.port.add", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "bridge.port.remove", 1, Stability::Stable);

    // VLAN
    capability::declare(AGENT_CLASS, "vlan.create", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "vlan.destroy", 1, Stability::Stable);

    // OVS
    capability::declare(AGENT_CLASS, "ovs.install", 1, Stability::Beta);
    capability::declare(AGENT_CLASS, "ovs.configure", 1, Stability::Beta);

    // SR-IOV
    capability::declare(AGENT_CLASS, "sriov.vf.configure", 1, Stability::Beta);

    // Diagnostics
    capability::declare(AGENT_CLASS, "network.verify", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "network.repair", 1, Stability::Beta);
    capability::declare(AGENT_CLASS, "martian.fix", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "network.interfaces.list", 1, Stability::Stable);
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let args = Args::parse();
    if args.version {
        println!("pmx-network version {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let cfg = Config::load(&args.config)?;
    if args.preflight {
        run_preflight(&cfg)?;
        println!("preflight: ok");
        return Ok(());
    }

    // Register capabilities before connecting so the backend can query them.
    declare_capabilities();

    wireguard::ensure_key_file(&cfg)?;

    let keyset_content = fs::read_to_string(&cfg.keyset.path)
        .with_context(|| format!("read keyset {}", cfg.keyset.path))?;
    let keyset = Arc::new(KeySet::parse(&keyset_content).map_err(anyhow::Error::msg)?);

    fs::create_dir_all(&cfg.state.dir)
        .with_context(|| format!("create state dir {}", cfg.state.dir))?;
    fs::create_dir_all(&cfg.nftables.ruleset_dir)
        .with_context(|| format!("create nft dir {}", cfg.nftables.ruleset_dir))?;

    let audit = AuditLog::open("/var/log/pmx-cloud/pmx-network.audit.log")
        .or_else(|_| AuditLog::open("/tmp/pmx-network.audit.log"))?;

    let handler = Arc::new(NetworkHandler {
        cfg: cfg.clone(),
        runner: Runner::new(),
        audit,
    });

    let host_fingerprint = fs::read_to_string("/etc/pmx-cloud/host-fingerprint")
        .unwrap_or_else(|_| "dev-fingerprint".to_string())
        .trim()
        .to_string();

    info!("starting {}", AGENT_CLASS);

    let ws_cfg = pmx_shared::wsclient::Config {
        backend_url: cfg.backend.url.clone(),
        agent_class: AGENT_CLASS.to_string(),
        auth_token: if cfg.backend.auth_token.trim().is_empty() {
            None
        } else {
            Some(cfg.backend.auth_token.clone())
        },
        cert_path: cfg.identity.cert.clone(),
        key_path: cfg.identity.key.clone(),
        keyset,
        replay: ReplayCache::new(100_000, Duration::from_secs(86_400)),
        host_fingerprint,
        heartbeat_interval: Duration::from_secs(15),
        handler,
    };

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    pmx_shared::wsclient::run(ws_cfg, Box::pin(shutdown)).await;
    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let fmt_layer = tracing_subscriber::fmt::layer().with_target(true);
    let registry = tracing_subscriber::registry().with(filter).with(fmt_layer);

    if let Ok(layer) = tracing_journald::layer() {
        registry.with(layer).init();
    } else {
        registry.init();
    }
}

fn run_preflight(cfg: &Config) -> Result<()> {
    cfg.validate()?;

    for path in [&cfg.identity.cert, &cfg.identity.key, &cfg.keyset.path] {
        if !path.is_empty() && !std::path::Path::new(path).exists() {
            bail!("preflight: missing file {}", path);
        }
    }

    wireguard::ensure_key_file(cfg)?;
    wireguard::ensure_key_permissions(cfg)?;

    if nix_like_root() {
        warn!("pmx-network is expected to run as pmx-net, not root");
    }

    Ok(())
}

#[cfg(target_family = "unix")]
fn nix_like_root() -> bool {
    current_uid() == 0
}

#[cfg(not(target_family = "unix"))]
fn nix_like_root() -> bool {
    false
}

#[cfg(target_family = "unix")]
fn current_uid() -> u32 {
    // There is no stable std API for uid, so /proc parsing is used as a fallback.
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let first = rest.split_whitespace().next().unwrap_or("1000");
                if let Ok(uid) = first.parse::<u32>() {
                    return uid;
                }
            }
        }
    }
    1000
}

#[async_trait]
impl pmx_shared::wsclient::Handler for NetworkHandler {
    async fn on_connect(&self) -> std::result::Result<(), String> {
        info!("{} connected to backend", AGENT_CLASS);
        Ok(())
    }

    async fn on_envelope(&self, env: Envelope) -> std::result::Result<Option<Vec<u8>>, String> {
        match self.dispatch(&env).await {
            Ok(payload) => {
                self.audit.append(Event {
                    ts: chrono::Utc::now(),
                    severity: Severity::Info,
                    job_id: &env.job_id,
                    command: &env.command,
                    message: "ok",
                });
                Ok(Some(payload))
            }
            Err(err) => {
                let message = err.to_string();
                error!("command failed: {}", message);
                self.audit.append(Event {
                    ts: chrono::Utc::now(),
                    severity: Severity::Error,
                    job_id: &env.job_id,
                    command: &env.command,
                    message: &message,
                });
                let payload = json!({
                    "error": message,
                    "error_code": classify_error(&err),
                });
                Ok(Some(payload.to_string().into_bytes()))
            }
        }
    }
}

impl NetworkHandler {
    async fn dispatch(&self, env: &Envelope) -> Result<Vec<u8>> {
        let params_value = params_object(&env.params);

        let payload = match env.command.as_str() {
            "wg.tunnel.up" => {
                let p: wireguard::TunnelParams = serde_json::from_value(params_value)?;
                wireguard::tunnel_up(&self.runner, &self.cfg, p).await?;
                json!({"ok": true})
            }
            "wg.tunnel.down" => {
                let p: wireguard::TunnelParams = serde_json::from_value(params_value)?;
                wireguard::tunnel_down(&self.runner, &self.cfg, p).await?;
                json!({"ok": true})
            }
            "wg.tunnel.reload" => {
                let p: wireguard::TunnelParams = serde_json::from_value(params_value)?;
                wireguard::tunnel_reload(&self.runner, &self.cfg, p).await?;
                json!({"ok": true})
            }
            "wg.tunnel.status" => {
                let p: wireguard::TunnelParams = serde_json::from_value(params_value)?;
                let status = wireguard::tunnel_status(&self.runner, &self.cfg, p).await?;
                serde_json::to_value(status)?
            }
            "wg.peer.add" => {
                let p: wireguard::PeerAddParams = serde_json::from_value(params_value)?;
                wireguard::peer_add(&self.runner, &self.cfg, p).await?;
                json!({"ok": true})
            }
            "wg.peer.remove" => {
                let p: wireguard::PeerRemoveParams = serde_json::from_value(params_value)?;
                wireguard::peer_remove(&self.runner, &self.cfg, p).await?;
                json!({"ok": true})
            }
            "wg.peer.list" => {
                let p: wireguard::TunnelParams = serde_json::from_value(params_value)?;
                let peers = wireguard::peer_list(&self.runner, &self.cfg, p).await?;
                serde_json::to_value(peers)?
            }

            "firewall.rules.validate" => {
                let p: nftables::ApplyParams = serde_json::from_value(params_value)?;
                nftables::validate(&self.cfg, &self.runner, p).await?;
                json!({"ok": true})
            }
            "firewall.rules.apply" => {
                let p: nftables::ApplyParams = serde_json::from_value(params_value)?;
                let res = nftables::apply(&self.cfg, &self.runner, p).await?;
                serde_json::to_value(res)?
            }
            "firewall.rules.clear" => {
                nftables::clear(&self.cfg, &self.runner).await?;
                json!({"ok": true})
            }
            "firewall.emergency.lockdown" => {
                let p: nftables::LockdownParams = serde_json::from_value(params_value)?;
                let res = nftables::emergency_lockdown(&self.cfg, &self.runner, p).await?;
                self.audit.append(Event {
                    ts: chrono::Utc::now(),
                    severity: Severity::Critical,
                    job_id: &env.job_id,
                    command: &env.command,
                    message: "Emergency lockdown applied",
                });
                serde_json::to_value(res)?
            }

            "bridge.create" => {
                let p: BridgeCreateParams = serde_json::from_value(params_value)?;
                bridge::create(&self.runner, &p.name).await?;
                json!({"ok": true})
            }
            "bridge.destroy" => {
                let p: BridgeCreateParams = serde_json::from_value(params_value)?;
                bridge::destroy(&self.runner, &p.name).await?;
                json!({"ok": true})
            }
            "bridge.port.add" => {
                let p: BridgePortParams = serde_json::from_value(params_value)?;
                bridge::port_add(&self.runner, &p.bridge, &p.port).await?;
                json!({"ok": true})
            }
            "bridge.port.remove" => {
                let p: BridgePortParams = serde_json::from_value(params_value)?;
                bridge::port_remove(&self.runner, &p.port).await?;
                json!({"ok": true})
            }

            "vlan.create" => {
                let p: VlanCreateParams = serde_json::from_value(params_value)?;
                vlan::create(&self.runner, &p.parent, &p.name, p.vid).await?;
                json!({"ok": true})
            }
            "vlan.destroy" => {
                let p: VlanDestroyParams = serde_json::from_value(params_value)?;
                vlan::destroy(&self.runner, &p.name).await?;
                json!({"ok": true})
            }

            "ovs.install" => {
                ovs::install().await?;
                json!({"ok": true})
            }
            "ovs.configure" => {
                let p: OvsConfigureParams = serde_json::from_value(params_value)?;
                ovs::configure(&self.runner, &p.commands).await?;
                json!({"ok": true})
            }

            "sriov.vf.configure" => {
                let p: SriovParams = serde_json::from_value(params_value)?;
                sriov::configure_numvfs(&p.pf, p.num_vfs)?;
                json!({"ok": true})
            }

            "network.verify" => {
                let p: VerifyParams = serde_json::from_value(params_value)?;
                let probes = verify_probes(&self.runner, &p.probes).await;
                serde_json::to_value(json!({"results": probes}))?
            }

            "network.interfaces.list" => {
                let list = netlink::list_interfaces(&self.runner).await?;
                serde_json::to_value(json!({"interfaces": list}))?
            }

            "network.repair" => {
                let mut attempts: Vec<Value> = Vec::new();
                let mut repaired = false;

                let networkd = self
                    .runner
                    .run("systemctl", &["is-active", "systemd-networkd.service"])
                    .await
                    .ok()
                    .filter(|result| result.status == 0);

                if networkd.is_some() {
                    let result = self
                        .runner
                        .run(
                            "busctl",
                            &[
                                "call",
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "RestartUnit",
                                "ss",
                                "systemd-networkd.service",
                                "replace",
                            ],
                        )
                        .await;
                    match result {
                        Ok(output) if output.status == 0 => {
                            repaired = true;
                            attempts.push(json!({
                                "unit": "systemd-networkd.service",
                                "ok": true,
                            }));
                        }
                        Ok(output) => {
                            attempts.push(json!({
                                "unit": "systemd-networkd.service",
                                "ok": false,
                                "status": output.status,
                                "stderr": output.stderr,
                            }));
                        }
                        Err(error) => {
                            attempts.push(json!({
                                "unit": "systemd-networkd.service",
                                "ok": false,
                                "error": error.to_string(),
                            }));
                        }
                    }
                }

                if !repaired {
                    let networking = self
                        .runner
                        .run("systemctl", &["is-active", "networking.service"])
                        .await
                        .ok()
                        .filter(|result| result.status == 0);

                    if networking.is_some() {
                        let result = self
                            .runner
                            .run(
                                "busctl",
                                &[
                                    "call",
                                    "org.freedesktop.systemd1",
                                    "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "RestartUnit",
                                    "ss",
                                    "networking.service",
                                    "replace",
                                ],
                            )
                            .await;
                        match result {
                            Ok(output) if output.status == 0 => {
                                repaired = true;
                                attempts.push(json!({
                                    "unit": "networking.service",
                                    "ok": true,
                                }));
                            }
                            Ok(output) => {
                                attempts.push(json!({
                                    "unit": "networking.service",
                                    "ok": false,
                                    "status": output.status,
                                    "stderr": output.stderr,
                                }));
                            }
                            Err(error) => {
                                attempts.push(json!({
                                    "unit": "networking.service",
                                    "ok": false,
                                    "error": error.to_string(),
                                }));
                            }
                        }
                    }
                }

                if attempts.is_empty() {
                    attempts.push(json!({
                        "ok": false,
                        "reason": "No active network service found (systemd-networkd/networking)",
                    }));
                }

                json!({
                    "ok": repaired,
                    "repaired": repaired,
                    "attempts": attempts,
                })
            }

            "martian.fix" => {
                let p: MartianFixParams = serde_json::from_value(params_value)?;
                apply_martian_fix(&p)?;
                json!({"ok": true})
            }

            _ => json!({
                "error": format!("UNSUPPORTED: {}", env.command),
                "error_code": "UNSUPPORTED"
            }),
        };

        Ok(payload.to_string().into_bytes())
    }
}

fn classify_error(err: &anyhow::Error) -> &'static str {
    let msg = err.to_string();
    if msg.contains("PEER_LIMIT_EXCEEDED") {
        "PEER_LIMIT_EXCEEDED"
    } else if msg.contains("RULE_LIMIT_EXCEEDED") {
        "RULE_LIMIT_EXCEEDED"
    } else if msg.contains("LOCKDOWN_ACTIVE") {
        "LOCKDOWN_ACTIVE"
    } else if msg.contains("KERNEL_REFUSED") {
        "KERNEL_REFUSED"
    } else if msg.contains("BRIDGE_IN_USE") {
        "BRIDGE_IN_USE"
    } else if msg.contains("UNSUPPORTED") {
        "UNSUPPORTED"
    } else {
        "COMMAND_FAILED"
    }
}

async fn verify_probes(runner: &Runner, probes: &[Probe]) -> Vec<ProbeResult> {
    let checks = probes
        .iter()
        .cloned()
        .map(|probe| verify_probe(runner, probe));

    match tokio::time::timeout(Duration::from_secs(5), join_all(checks)).await {
        Ok(results) => results,
        Err(_) => probes
            .iter()
            .map(|probe| ProbeResult {
                probe: probe_name(probe),
                ok: false,
                error: Some("timeout".to_string()),
            })
            .collect(),
    }
}

async fn verify_probe(runner: &Runner, probe: Probe) -> ProbeResult {
    match probe {
        Probe::Ping { target } => {
            if !is_safe_probe_target(&target) {
                return ProbeResult {
                    probe: format!("ping:{}", target),
                    ok: false,
                    error: Some("invalid ping target".to_string()),
                };
            }
            let res = tokio::time::timeout(
                Duration::from_secs(1),
                runner.run("ping", &["-c", "1", "-W", "1", target.as_str()]),
            )
            .await;
            match res {
                Ok(Ok(cmd)) if cmd.status == 0 => ProbeResult {
                    probe: format!("ping:{}", target),
                    ok: true,
                    error: None,
                },
                Ok(Ok(cmd)) => ProbeResult {
                    probe: format!("ping:{}", target),
                    ok: false,
                    error: Some(cmd.stderr),
                },
                Ok(Err(e)) => ProbeResult {
                    probe: format!("ping:{}", target),
                    ok: false,
                    error: Some(e.to_string()),
                },
                Err(_) => ProbeResult {
                    probe: format!("ping:{}", target),
                    ok: false,
                    error: Some("timeout".to_string()),
                },
            }
        }
        Probe::Tcp { host, port } => {
            if !is_safe_probe_target(&host) {
                return ProbeResult {
                    probe: format!("tcp:{}:{}", host, port),
                    ok: false,
                    error: Some("invalid tcp host".to_string()),
                };
            }
            let probe_name = format!("tcp:{}:{}", host, port);
            let addr = to_socket_addr(&host, port);
            match tokio::time::timeout(
                Duration::from_millis(500),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            {
                Ok(Ok(_)) => ProbeResult {
                    probe: probe_name,
                    ok: true,
                    error: None,
                },
                Ok(Err(e)) => ProbeResult {
                    probe: probe_name,
                    ok: false,
                    error: Some(e.to_string()),
                },
                Err(_) => ProbeResult {
                    probe: probe_name,
                    ok: false,
                    error: Some("timeout".to_string()),
                },
            }
        }
    }
}

fn probe_name(probe: &Probe) -> String {
    match probe {
        Probe::Ping { target } => format!("ping:{}", target),
        Probe::Tcp { host, port } => format!("tcp:{}:{}", host, port),
    }
}

fn is_safe_probe_target(value: &str) -> bool {
    let target = value.trim();
    if target.is_empty() || target.starts_with('-') {
        return false;
    }
    target
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_'))
}

fn to_socket_addr(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') && !host.ends_with(']') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn apply_martian_fix(params: &MartianFixParams) -> Result<()> {
    if params.iface.is_empty()
        || params.iface.contains('/')
        || params.iface.contains("..")
        || !params
            .iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        bail!("invalid iface");
    }
    if params.rp_filter > 2 {
        bail!("invalid rp_filter (expected 0, 1, or 2)");
    }

    let rp_filter_path = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", params.iface);
    let log_martians_path = "/proc/sys/net/ipv4/conf/all/log_martians".to_string();

    if !rp_filter_path.starts_with("/proc/sys/net/ipv4/conf/") {
        bail!("sysctl path outside whitelist");
    }

    fs::write(rp_filter_path, params.rp_filter.to_string()).context("write rp_filter")?;
    fs::write(
        log_martians_path,
        if params.log_martians { "1" } else { "0" },
    )
    .context("write log_martians")?;
    Ok(())
}

fn params_object(params: &BTreeMap<String, Value>) -> Value {
    let mut map = serde_json::Map::new();
    for (k, v) in params {
        map.insert(k.clone(), v.clone());
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_safe_probe_target ─────────────────────────────────────────────────

    #[test]
    fn probe_target_accepts_ipv4() {
        assert!(is_safe_probe_target("10.0.0.1"));
        assert!(is_safe_probe_target("192.168.100.200"));
    }

    #[test]
    fn probe_target_accepts_hostname() {
        assert!(is_safe_probe_target("example.com"));
        assert!(is_safe_probe_target("my-host_1.internal"));
    }

    #[test]
    fn probe_target_accepts_ipv6() {
        assert!(is_safe_probe_target("2001:db8::1"));
    }

    #[test]
    fn probe_target_rejects_empty() {
        assert!(!is_safe_probe_target(""));
    }

    #[test]
    fn probe_target_rejects_dash_prefix() {
        assert!(!is_safe_probe_target("-n"));
        assert!(!is_safe_probe_target("-c 1 google.com"));
    }

    #[test]
    fn probe_target_rejects_shell_chars() {
        assert!(!is_safe_probe_target("10.0.0.1; ls"));
        assert!(!is_safe_probe_target("10.0.0.1 && rm -rf /"));
        assert!(!is_safe_probe_target("$(id)"));
        assert!(!is_safe_probe_target("`id`"));
    }

    #[test]
    fn probe_target_rejects_whitespace() {
        assert!(!is_safe_probe_target("10.0.0 .1"));
    }

    // ── to_socket_addr ───────────────────────────────────────────────────────

    #[test]
    fn to_socket_addr_ipv4() {
        assert_eq!(to_socket_addr("10.0.0.1", 443), "10.0.0.1:443");
    }

    #[test]
    fn to_socket_addr_hostname() {
        assert_eq!(to_socket_addr("example.com", 80), "example.com:80");
    }

    #[test]
    fn to_socket_addr_ipv6_wraps_in_brackets() {
        assert_eq!(to_socket_addr("2001:db8::1", 443), "[2001:db8::1]:443");
    }

    #[test]
    fn to_socket_addr_already_bracketed_ipv6() {
        // Already bracketed — should NOT double-bracket
        assert_eq!(to_socket_addr("[2001:db8::1]", 443), "[2001:db8::1]:443");
    }

    // ── classify_error ───────────────────────────────────────────────────────

    #[test]
    fn classify_peer_limit_exceeded() {
        let err = anyhow::anyhow!("PEER_LIMIT_EXCEEDED: current=10 max=10");
        assert_eq!(classify_error(&err), "PEER_LIMIT_EXCEEDED");
    }

    #[test]
    fn classify_rule_limit_exceeded() {
        let err = anyhow::anyhow!("RULE_LIMIT_EXCEEDED: rules=10001 max=10000");
        assert_eq!(classify_error(&err), "RULE_LIMIT_EXCEEDED");
    }

    #[test]
    fn classify_lockdown_active() {
        let err = anyhow::anyhow!("LOCKDOWN_ACTIVE: firewall.rules.clear refused");
        assert_eq!(classify_error(&err), "LOCKDOWN_ACTIVE");
    }

    #[test]
    fn classify_kernel_refused() {
        let err = anyhow::anyhow!("KERNEL_REFUSED: cannot write /sys/...");
        assert_eq!(classify_error(&err), "KERNEL_REFUSED");
    }

    #[test]
    fn classify_bridge_in_use() {
        let err = anyhow::anyhow!("BRIDGE_IN_USE: br0 still has member ports");
        assert_eq!(classify_error(&err), "BRIDGE_IN_USE");
    }

    #[test]
    fn classify_unsupported() {
        let err = anyhow::anyhow!("UNSUPPORTED: unknown.command");
        assert_eq!(classify_error(&err), "UNSUPPORTED");
    }

    #[test]
    fn classify_generic_error() {
        let err = anyhow::anyhow!("some unexpected error");
        assert_eq!(classify_error(&err), "COMMAND_FAILED");
    }

    // ── apply_martian_fix validation (no filesystem writes in validation path) ──

    #[test]
    fn martian_fix_rejects_empty_iface() {
        let params = MartianFixParams {
            iface: "".to_string(),
            rp_filter: 1,
            log_martians: false,
        };
        assert!(apply_martian_fix(&params).is_err());
    }

    #[test]
    fn martian_fix_rejects_slash_in_iface() {
        let params = MartianFixParams {
            iface: "../../etc/passwd".to_string(),
            rp_filter: 1,
            log_martians: false,
        };
        let err = apply_martian_fix(&params).unwrap_err();
        assert!(err.to_string().contains("invalid iface"), "{err}");
    }

    #[test]
    fn martian_fix_rejects_iface_with_path_traversal() {
        let params = MartianFixParams {
            iface: "eth0/../etc".to_string(),
            rp_filter: 1,
            log_martians: false,
        };
        // The char validation will catch the path separator or dotdot
        assert!(apply_martian_fix(&params).is_err());
    }

    #[test]
    fn martian_fix_rejects_rp_filter_above_two() {
        let params = MartianFixParams {
            iface: "eth0".to_string(),
            rp_filter: 3,
            log_martians: false,
        };
        let err = apply_martian_fix(&params).unwrap_err();
        assert!(err.to_string().contains("invalid rp_filter"), "{err}");
    }

    #[test]
    fn martian_fix_rejects_shell_metachar_in_iface() {
        let params = MartianFixParams {
            iface: "eth0;evil".to_string(),
            rp_filter: 0,
            log_martians: true,
        };
        assert!(apply_martian_fix(&params).is_err());
    }

    // ── probe_name ───────────────────────────────────────────────────────────

    #[test]
    fn probe_name_ping() {
        let p = Probe::Ping {
            target: "10.0.0.1".to_string(),
        };
        assert_eq!(probe_name(&p), "ping:10.0.0.1");
    }

    #[test]
    fn probe_name_tcp() {
        let p = Probe::Tcp {
            host: "example.com".to_string(),
            port: 443,
        };
        assert_eq!(probe_name(&p), "tcp:example.com:443");
    }
}
