use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Serialize;
use std::collections::HashSet;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub status: i32,
}

#[derive(Clone)]
pub struct Runner {
    allowed: HashSet<&'static str>,
}

#[async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run(&self, bin: &str, args: &[&str]) -> Result<CommandResult>;

    async fn run_expect_ok(&self, bin: &str, args: &[&str]) -> Result<CommandResult> {
        let result = self.run(bin, args).await?;
        if result.status != 0 {
            bail!(
                "{} failed with status {}: {}",
                bin,
                result.status,
                result.stderr
            );
        }
        Ok(result)
    }
}

impl Runner {
    pub fn new() -> Self {
        let allowed = HashSet::from([
            "ip",
            "wg",
            "nft",
            "ovs-vsctl",
            "systemctl",
            "busctl",
            "ping",
        ]);
        Self { allowed }
    }

    pub async fn run(&self, bin: &str, args: &[&str]) -> Result<CommandResult> {
        CommandRunner::run(self, bin, args).await
    }

    pub async fn run_expect_ok(&self, bin: &str, args: &[&str]) -> Result<CommandResult> {
        CommandRunner::run_expect_ok(self, bin, args).await
    }
}

#[async_trait]
impl CommandRunner for Runner {
    async fn run(&self, bin: &str, args: &[&str]) -> Result<CommandResult> {
        if !self.allowed.contains(bin) {
            bail!("command '{}' is not allowed", bin);
        }
        let mut argv: Vec<String> = Vec::with_capacity(args.len());
        for arg in args {
            let a = *arg;
            if !is_safe_arg(a) {
                bail!("unsafe argument rejected: {}", a);
            }
            argv.push(a.to_string());
        }

        let output = Command::new(bin)
            .args(&argv)
            .stdin(Stdio::null())
            .output()
            .await
            .with_context(|| format!("exec {}", bin))?;

        Ok(CommandResult {
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            status: output.status.code().unwrap_or(-1),
        })
    }
}

pub fn is_safe_arg(arg: &str) -> bool {
    !arg.chars()
        .any(|c| matches!(c, ';' | '|' | '&' | '`' | '$' | '\n' | '\r' | '\0'))
}

pub fn is_safe_token(value: &str) -> bool {
    !value.is_empty()
        && !value.contains("..")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'))
}

pub fn is_safe_ifname(value: &str) -> bool {
    !value.is_empty()
        && !value.contains("..")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

#[derive(Debug, serde::Deserialize)]
struct IpLinkInfo {
    info_kind: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct IpLink {
    ifname: String,
    mtu: u32,
    address: Option<String>,
    flags: Vec<String>,
    master: Option<String>,
    linkinfo: Option<IpLinkInfo>,
}

#[derive(Debug, serde::Deserialize)]
struct IpAddrInfo {
    local: Option<String>,
    prefixlen: Option<u32>,
}

#[derive(Debug, serde::Deserialize)]
struct IpAddr {
    ifname: String,
    addr_info: Vec<IpAddrInfo>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct InterfaceRecord {
    pub name: String,
    pub mac: String,
    pub mtu: u32,
    pub addresses: Vec<String>,
    pub state: String,
    pub bridge: Option<String>,
    #[serde(rename = "type")]
    pub if_type: String,
}

fn normalize_interface_type(linkinfo: Option<&IpLinkInfo>) -> String {
    match linkinfo.and_then(|info| info.info_kind.as_deref()) {
        Some(kind @ ("bridge" | "bond" | "vlan")) => kind.to_string(),
        // The API contract intentionally groups physical, loopback, veth,
        // WireGuard, and other Linux link kinds under the ethernet fallback.
        _ => "ethernet".to_string(),
    }
}

pub async fn list_interfaces(runner: &Runner) -> Result<Vec<InterfaceRecord>> {
    let link_res = runner.run("ip", &["-d", "-j", "link", "show"]).await?;
    if link_res.status != 0 {
        bail!("ip -d -j link show failed: {}", link_res.stderr);
    }
    let links: Vec<IpLink> =
        serde_json::from_str(&link_res.stdout).context("parse ip link json")?;

    let addr_res = runner.run("ip", &["-j", "addr"]).await?;
    if addr_res.status != 0 {
        bail!("ip -j addr failed: {}", addr_res.stderr);
    }
    let addrs: Vec<IpAddr> =
        serde_json::from_str(&addr_res.stdout).context("parse ip addr json")?;

    let mut addr_map = std::collections::HashMap::new();
    for addr in addrs {
        let mut list = Vec::new();
        for info in addr.addr_info {
            if let (Some(local), Some(prefixlen)) = (info.local, info.prefixlen) {
                list.push(format!("{}/{}", local, prefixlen));
            }
        }
        addr_map.insert(addr.ifname, list);
    }

    let mut records = Vec::with_capacity(links.len());
    for link in links {
        let addresses = addr_map.remove(&link.ifname).unwrap_or_default();
        let state = if link.flags.iter().any(|f| f == "UP") {
            "up".to_string()
        } else {
            "down".to_string()
        };

        let if_type = normalize_interface_type(link.linkinfo.as_ref());

        records.push(InterfaceRecord {
            name: link.ifname,
            mac: link
                .address
                .unwrap_or_else(|| "00:00:00:00:00:00".to_string()),
            mtu: link.mtu,
            addresses,
            state,
            bridge: link.master,
            if_type,
        });
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_type_preserves_supported_contract_values() {
        for kind in ["bridge", "bond", "vlan"] {
            let linkinfo = IpLinkInfo {
                info_kind: Some(kind.to_string()),
            };
            assert_eq!(normalize_interface_type(Some(&linkinfo)), kind);
        }
    }

    #[test]
    fn interface_type_normalizes_unknown_linux_link_kinds() {
        for kind in ["veth", "wireguard", "dummy"] {
            let linkinfo = IpLinkInfo {
                info_kind: Some(kind.to_string()),
            };
            assert_eq!(normalize_interface_type(Some(&linkinfo)), "ethernet");
        }
        assert_eq!(normalize_interface_type(None), "ethernet");
    }

    // ── is_safe_arg ──────────────────────────────────────────────────────────

    #[test]
    fn safe_arg_accepts_normal_strings() {
        assert!(is_safe_arg("eth0"));
        assert!(is_safe_arg("link"));
        assert!(is_safe_arg("show"));
        assert!(is_safe_arg("10.0.0.1/24"));
        assert!(is_safe_arg("-j"));
        assert!(is_safe_arg(""));
    }

    #[test]
    fn safe_arg_rejects_shell_metacharacters() {
        assert!(!is_safe_arg("eth0;ls"));
        assert!(!is_safe_arg("a|b"));
        assert!(!is_safe_arg("a&b"));
        assert!(!is_safe_arg("a`b`"));
        assert!(!is_safe_arg("$HOME"));
        assert!(!is_safe_arg("a\nb"));
        assert!(!is_safe_arg("a\rb"));
        assert!(!is_safe_arg("a\0b"));
    }

    // ── is_safe_token ────────────────────────────────────────────────────────

    #[test]
    fn safe_token_accepts_alphanumeric_and_allowed_punctuation() {
        assert!(is_safe_token("eth0"));
        assert!(is_safe_token("pmxwg0"));
        assert!(is_safe_token("10.0.0.1"));
        assert!(is_safe_token("1.2.3.4:51820"));
        assert!(is_safe_token("my-iface_1"));
        assert!(is_safe_token("/24"));
    }

    #[test]
    fn safe_token_rejects_empty_string() {
        assert!(!is_safe_token(""));
    }

    #[test]
    fn safe_token_rejects_spaces_and_shell_chars() {
        assert!(!is_safe_token("eth 0"));
        assert!(!is_safe_token("eth;0"));
        assert!(!is_safe_token("eth|0"));
        assert!(!is_safe_token("eth$0"));
    }

    // ── is_safe_ifname ───────────────────────────────────────────────────────

    #[test]
    fn safe_ifname_accepts_valid_names() {
        assert!(is_safe_ifname("eth0"));
        assert!(is_safe_ifname("br0"));
        assert!(is_safe_ifname("pmxwg0"));
        assert!(is_safe_ifname("vlan.100"));
        assert!(is_safe_ifname("my-bridge_1"));
    }

    #[test]
    fn safe_ifname_rejects_slash_prefix() {
        assert!(!is_safe_ifname("/etc/passwd"));
        assert!(!is_safe_ifname("/dev/null"));
        assert!(!is_safe_ifname("eth0/child"));
        assert!(!is_safe_ifname("eth0:1"));
    }

    #[test]
    fn safe_ifname_rejects_empty_and_shell_chars() {
        assert!(!is_safe_ifname(""));
        assert!(!is_safe_ifname("eth;0"));
        assert!(!is_safe_ifname("br 0"));
    }

    // ── additional validation edge cases ────────────────────────────────────────

    #[test]
    fn safe_ifname_rejects_dotdot() {
        assert!(!is_safe_ifname("br..evil"));
    }

    #[test]
    fn safe_ifname_rejects_backtick() {
        assert!(!is_safe_ifname("br`id`"));
    }

    #[test]
    fn safe_ifname_rejects_dollar() {
        assert!(!is_safe_ifname("br$HOME"));
    }

    #[test]
    fn safe_token_rejects_dotdot() {
        assert!(!is_safe_token(".."));
    }

    #[test]
    fn safe_arg_rejects_null_byte() {
        assert!(!is_safe_arg("eth\0root"));
    }

    #[test]
    fn safe_arg_accepts_dashes_and_dots() {
        assert!(is_safe_arg("10.0.0.1/24"));
        assert!(is_safe_arg("--may-exist"));
    }

    // ── Runner allowlist ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn runner_rejects_disallowed_binary() {
        let runner = Runner::new();
        let err = runner.run("rm", &["-rf", "/"]).await.unwrap_err();
        assert!(err.to_string().contains("not allowed"), "{err}");
    }

    #[tokio::test]
    async fn runner_rejects_unsafe_arg_in_run() {
        let runner = Runner::new();
        let err = runner.run("ip", &[";rm -rf /"]).await.unwrap_err();
        assert!(err.to_string().contains("unsafe argument"), "{err}");
    }

    #[tokio::test]
    async fn runner_rejects_pipe_in_arg() {
        let runner = Runner::new();
        let err = runner.run("ip", &["eth0|cat"]).await.unwrap_err();
        assert!(err.to_string().contains("unsafe argument"), "{err}");
    }

    #[tokio::test]
    async fn runner_rejects_backtick_in_arg() {
        let runner = Runner::new();
        let err = runner.run("ip", &["eth`id`"]).await.unwrap_err();
        assert!(err.to_string().contains("unsafe argument"), "{err}");
    }

    #[tokio::test]
    async fn runner_rejects_dollar_in_arg() {
        let runner = Runner::new();
        let err = runner.run("ip", &["$HOME"]).await.unwrap_err();
        assert!(err.to_string().contains("unsafe argument"), "{err}");
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn runner_allows_ip_with_safe_args() {
        let runner = Runner::new();
        // ip help only works on Linux; gated to avoid macOS CI failure
        let result = runner.run("ip", &["help"]).await;
        assert!(result.is_ok(), "ip help should be allowed");
    }

    // ── CommandResult construction ─────────────────────────────────────────────

    #[test]
    fn command_result_serializes() {
        let cr = CommandResult {
            stdout: "ok".to_string(),
            stderr: "".to_string(),
            status: 0,
        };
        let json = serde_json::to_string(&cr).unwrap();
        assert!(json.contains("ok"));
        assert!(json.contains("\"status\":0"));
    }
}
