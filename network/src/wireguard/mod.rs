use crate::config::Config;
use crate::netlink::{is_safe_ifname, is_safe_token, Runner};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Deserialize)]
pub struct TunnelParams {
    #[serde(default)]
    pub iface: Option<String>,
    #[serde(default)]
    pub listen_port: Option<u16>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerAddParams {
    #[serde(default)]
    pub iface: Option<String>,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerRemoveParams {
    #[serde(default)]
    pub iface: Option<String>,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerInfo {
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub last_handshake: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub persistent_keepalive: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct TunnelStatus {
    pub iface: String,
    pub listen_port: u16,
    pub peers: Vec<PeerInfo>,
}

pub fn ensure_key_file(cfg: &Config) -> Result<()> {
    let path = Path::new(&cfg.wireguard.key_file);
    if !path.exists() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create key dir {}", parent.display()))?;
        }
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let key = Zeroizing::new(STANDARD.encode(raw));
        fs::write(path, format!("{}\n", key.as_str())).with_context(|| "write wg private key")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))
            .with_context(|| "chmod wg key file to 0400")?;
    }
    ensure_key_permissions(cfg)
}

pub fn ensure_key_permissions(cfg: &Config) -> Result<()> {
    let meta = fs::metadata(&cfg.wireguard.key_file)
        .with_context(|| format!("stat {}", cfg.wireguard.key_file))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o400 {
        bail!(
            "WIREGUARD_KEY_PERMS_INVALID: {} must be mode 0400, got {:o}",
            cfg.wireguard.key_file,
            mode
        );
    }
    Ok(())
}

pub async fn tunnel_up(runner: &Runner, cfg: &Config, params: TunnelParams) -> Result<()> {
    let iface = params
        .iface
        .unwrap_or_else(|| cfg.wireguard.interface.clone());
    if !is_safe_ifname(&iface) {
        bail!("invalid interface name");
    }

    let port = params
        .listen_port
        .unwrap_or(cfg.wireguard.listen_port_range[0]);
    if port < cfg.wireguard.listen_port_range[0] || port > cfg.wireguard.listen_port_range[1] {
        bail!("listen port outside allowed range");
    }

    let show = runner.run("ip", &["link", "show", "dev", &iface]).await?;
    if show.status != 0 {
        runner
            .run_expect_ok("ip", &["link", "add", "dev", &iface, "type", "wireguard"])
            .await?;
    }

    let port_s = port.to_string();
    runner
        .run_expect_ok(
            "wg",
            &[
                "set",
                &iface,
                "private-key",
                &cfg.wireguard.key_file,
                "listen-port",
                &port_s,
            ],
        )
        .await?;

    runner
        .run_expect_ok("ip", &["link", "set", "up", "dev", &iface])
        .await?;
    Ok(())
}

pub async fn tunnel_down(runner: &Runner, cfg: &Config, params: TunnelParams) -> Result<()> {
    let iface = params
        .iface
        .unwrap_or_else(|| cfg.wireguard.interface.clone());
    if !is_safe_ifname(&iface) {
        bail!("invalid interface name");
    }
    runner
        .run_expect_ok("ip", &["link", "delete", "dev", &iface])
        .await?;
    Ok(())
}

pub async fn tunnel_reload(runner: &Runner, cfg: &Config, params: TunnelParams) -> Result<()> {
    let iface = params
        .iface
        .unwrap_or_else(|| cfg.wireguard.interface.clone());
    if !is_safe_ifname(&iface) {
        bail!("invalid interface name");
    }
    let port = params
        .listen_port
        .unwrap_or(cfg.wireguard.listen_port_range[0]);
    if port < cfg.wireguard.listen_port_range[0] || port > cfg.wireguard.listen_port_range[1] {
        bail!("listen port outside allowed range");
    }
    let port_s = port.to_string();
    runner
        .run_expect_ok(
            "wg",
            &[
                "set",
                &iface,
                "private-key",
                &cfg.wireguard.key_file,
                "listen-port",
                &port_s,
            ],
        )
        .await?;
    Ok(())
}

pub async fn peer_add(runner: &Runner, cfg: &Config, params: PeerAddParams) -> Result<()> {
    validate_pubkey(&params.public_key)?;
    if params.allowed_ips.is_empty() {
        bail!("allowed_ips is required");
    }
    for cidr in &params.allowed_ips {
        validate_cidr(cidr)?;
    }
    if let Some(endpoint) = &params.endpoint {
        validate_endpoint(endpoint)?;
    }

    let iface = params
        .iface
        .unwrap_or_else(|| cfg.wireguard.interface.clone());
    let status = tunnel_status(
        runner,
        cfg,
        TunnelParams {
            iface: Some(iface.clone()),
            listen_port: None,
        },
    )
    .await?;
    if status.peers.len() >= cfg.wireguard.max_peers_per_host {
        bail!(
            "PEER_LIMIT_EXCEEDED: current={} max={}",
            status.peers.len(),
            cfg.wireguard.max_peers_per_host
        );
    }

    let allowed = params.allowed_ips.join(",");
    let mut args = vec![
        "set".to_string(),
        iface,
        "peer".to_string(),
        params.public_key,
        "allowed-ips".to_string(),
        allowed,
    ];
    if let Some(endpoint) = params.endpoint {
        args.push("endpoint".to_string());
        args.push(endpoint);
    }
    if let Some(keepalive) = params.persistent_keepalive {
        args.push("persistent-keepalive".to_string());
        args.push(keepalive.to_string());
    }

    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    runner.run_expect_ok("wg", &refs).await?;
    Ok(())
}

pub async fn peer_remove(runner: &Runner, cfg: &Config, params: PeerRemoveParams) -> Result<()> {
    validate_pubkey(&params.public_key)?;
    let iface = params
        .iface
        .unwrap_or_else(|| cfg.wireguard.interface.clone());
    let status = tunnel_status(
        runner,
        cfg,
        TunnelParams {
            iface: Some(iface.clone()),
            listen_port: None,
        },
    )
    .await?;
    if !status
        .peers
        .iter()
        .any(|p| p.public_key == params.public_key)
    {
        bail!("peer not present");
    }
    runner
        .run_expect_ok("wg", &["set", &iface, "peer", &params.public_key, "remove"])
        .await?;
    Ok(())
}

pub async fn peer_list(
    runner: &Runner,
    cfg: &Config,
    params: TunnelParams,
) -> Result<Vec<PeerInfo>> {
    Ok(tunnel_status(runner, cfg, params).await?.peers)
}

pub async fn tunnel_status(
    runner: &Runner,
    cfg: &Config,
    params: TunnelParams,
) -> Result<TunnelStatus> {
    let iface = params
        .iface
        .unwrap_or_else(|| cfg.wireguard.interface.clone());
    let dump = runner
        .run_expect_ok("wg", &["show", &iface, "dump"])
        .await?
        .stdout;
    parse_dump(&iface, &dump)
}

fn parse_dump(iface: &str, dump: &str) -> Result<TunnelStatus> {
    let mut lines = dump.lines();
    let header = lines.next().unwrap_or("");
    if header.trim().is_empty() {
        return Ok(TunnelStatus {
            iface: iface.to_string(),
            listen_port: 0,
            peers: vec![],
        });
    }

    let mut listen_port: u16 = 0;
    let mut peers = Vec::new();
    for (idx, line) in dump.lines().enumerate() {
        let cols: Vec<&str> = line.split('\t').collect();
        if idx == 0 {
            if cols.len() >= 3 {
                listen_port = cols[2].parse::<u16>().unwrap_or(0);
            }
            continue;
        }
        if cols.len() < 8 {
            continue;
        }
        let allowed_ips = if cols[3].trim().is_empty() {
            vec![]
        } else {
            cols[3].split(',').map(|v| v.trim().to_string()).collect()
        };
        peers.push(PeerInfo {
            public_key: cols[0].to_string(),
            endpoint: cols[2].to_string(),
            allowed_ips,
            last_handshake: cols[4].parse::<u64>().unwrap_or(0),
            rx_bytes: cols[5].parse::<u64>().unwrap_or(0),
            tx_bytes: cols[6].parse::<u64>().unwrap_or(0),
            persistent_keepalive: cols[7].parse::<u16>().unwrap_or(0),
        });
    }

    Ok(TunnelStatus {
        iface: iface.to_string(),
        listen_port,
        peers,
    })
}

fn validate_pubkey(value: &str) -> Result<()> {
    let decoded = STANDARD
        .decode(value.trim())
        .with_context(|| "decode peer public key")?;
    if decoded.len() != 32 {
        bail!("peer public key must decode to 32 bytes");
    }
    Ok(())
}

fn validate_cidr(value: &str) -> Result<()> {
    let mut parts = value.split('/');
    let ip = parts.next().unwrap_or("");
    let prefix = parts.next().unwrap_or("");
    if parts.next().is_some() {
        bail!("invalid cidr {}", value);
    }
    let ip: IpAddr = ip
        .parse()
        .with_context(|| format!("invalid ip in cidr {}", value))?;
    let pref: u8 = prefix
        .parse::<u8>()
        .with_context(|| format!("invalid prefix in cidr {}", value))?;
    match ip {
        IpAddr::V4(_) if pref <= 32 => Ok(()),
        IpAddr::V6(_) if pref <= 128 => Ok(()),
        _ => bail!("invalid prefix in cidr {}", value),
    }
}

fn validate_endpoint(value: &str) -> Result<()> {
    if !is_safe_token(value) {
        bail!("endpoint has invalid characters");
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("endpoint must be host:port"))?;
    if host.is_empty() {
        bail!("endpoint host is empty");
    }
    let p = port
        .parse::<u16>()
        .with_context(|| "endpoint port must be numeric")?;
    if p == 0 {
        bail!("endpoint port must be > 0");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dump_extracts_peers() {
        let dump = "priv\tpub\t51820\tfwmark\npeerA\t(psk)\t1.2.3.4:51820\t10.0.0.2/32\t10\t100\t200\t25\n";
        let status = parse_dump("pmxwg0", dump).unwrap();
        assert_eq!(status.listen_port, 51820);
        assert_eq!(status.peers.len(), 1);
        assert_eq!(status.peers[0].public_key, "peerA");
    }

    #[test]
    fn cidr_validation() {
        assert!(validate_cidr("10.0.0.1/32").is_ok());
        assert!(validate_cidr("2001:db8::1/64").is_ok());
        assert!(validate_cidr("10.0.0.1/64").is_err());
    }

    // ── validate_pubkey ──────────────────────────────────────────────────────

    #[test]
    fn validate_pubkey_accepts_32_byte_base64() {
        // 32 zero bytes → base64
        let key = STANDARD.encode([0u8; 32]);
        assert!(validate_pubkey(&key).is_ok());
    }

    #[test]
    fn validate_pubkey_rejects_wrong_length() {
        // 16 bytes → too short
        let key = STANDARD.encode([0u8; 16]);
        assert!(validate_pubkey(&key).is_err());
    }

    #[test]
    fn validate_pubkey_rejects_garbage() {
        assert!(validate_pubkey("not-base64!!!").is_err());
    }

    #[test]
    fn validate_pubkey_accepts_real_wg_pubkey() {
        // A real WireGuard public key (44 chars base64, 32 bytes)
        let key = "aPxGwqVbslM6JkLzZ7FCVGwVMZ6JjUfH2yU9VKw0NUY=";
        assert!(validate_pubkey(key).is_ok());
    }

    // ── validate_endpoint ─────────────────────────────────────────────────────

    #[test]
    fn validate_endpoint_accepts_valid() {
        assert!(validate_endpoint("1.2.3.4:51820").is_ok());
    }

    #[test]
    fn validate_endpoint_rejects_no_port() {
        assert!(validate_endpoint("1.2.3.4").is_err());
    }

    #[test]
    fn validate_endpoint_rejects_port_zero() {
        assert!(validate_endpoint("1.2.3.4:0").is_err());
    }

    #[test]
    fn validate_endpoint_rejects_empty_host() {
        assert!(validate_endpoint(":51820").is_err());
    }

    #[test]
    fn validate_endpoint_rejects_invalid_chars() {
        assert!(validate_endpoint("1.2.3.4:51820;rm -rf").is_err());
    }

    // ── parse_dump edge cases ─────────────────────────────────────────────────

    #[test]
    fn parse_dump_empty_input() {
        let status = parse_dump("pmxwg0", "").unwrap();
        assert_eq!(status.listen_port, 0);
        assert!(status.peers.is_empty());
    }

    #[test]
    fn parse_dump_multiple_peers() {
        let dump = "priv\tpub\t51820\tfwmark\n\
                     peerA\t(psk)\t1.2.3.4:51820\t10.0.0.2/32,10.0.0.3/32\t10\t100\t200\t25\n\
                     peerB\t(psk)\t5.6.7.8:51820\t10.0.1.0/24\t20\t300\t400\t0\n";
        let status = parse_dump("pmxwg0", dump).unwrap();
        assert_eq!(status.peers.len(), 2);
        assert_eq!(status.peers[0].allowed_ips.len(), 2);
        assert_eq!(status.peers[1].persistent_keepalive, 0);
    }

    #[test]
    fn parse_dump_peer_with_empty_allowed_ips() {
        let dump = "priv\tpub\t51820\tfwmark\n\
                     peerA\t(psk)\t1.2.3.4:51820\t\t10\t100\t200\t25\n";
        let status = parse_dump("pmxwg0", dump).unwrap();
        assert_eq!(status.peers.len(), 1);
        assert!(status.peers[0].allowed_ips.is_empty());
    }

    // ── validate_cidr edge cases ──────────────────────────────────────────────

    #[test]
    fn validate_cidr_rejects_no_prefix() {
        assert!(validate_cidr("10.0.0.1").is_err());
    }

    #[test]
    fn validate_cidr_rejects_double_slash() {
        assert!(validate_cidr("10.0.0.1/24/32").is_err());
    }

    #[test]
    fn validate_cidr_rejects_bad_ip() {
        assert!(validate_cidr("not-an-ip/24").is_err());
    }

    #[test]
    fn validate_cidr_rejects_negative_prefix() {
        assert!(validate_cidr("10.0.0.1/-1").is_err());
    }
}
