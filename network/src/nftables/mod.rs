use crate::config::Config;
use crate::netlink::Runner;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

const ISOLATION_INPUT_PRIORITY: i32 = -300;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleSet {
    #[serde(default)]
    pub revision: Option<String>,
    #[serde(default = "default_family")]
    pub family: String,
    #[serde(default = "default_table")]
    pub table: String,
    #[serde(default)]
    pub chains: Vec<Chain>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Chain {
    pub name: String,
    #[serde(default)]
    pub chain_type: Option<String>,
    #[serde(default)]
    pub hook: Option<String>,
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub policy: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub chain: String,
    pub expr: Vec<Expr>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expr {
    Match {
        left: String,
        op: String,
        right: String,
    },
    Counter,
    Accept,
    Drop,
    Jump {
        target: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApplyParams {
    pub ruleset: RuleSet,
    #[serde(default)]
    pub allow_ssh_from: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LockdownParams {
    pub management_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyResult {
    pub revision: String,
    pub path: String,
    pub changed_lines: usize,
}

fn default_family() -> String {
    "inet".to_string()
}

fn default_table() -> String {
    "pmx-cloud".to_string()
}

pub async fn validate(cfg: &Config, runner: &Runner, params: ApplyParams) -> Result<String> {
    ensure_limit(cfg, &params.ruleset)?;
    ensure_ruleset_target(&params.ruleset)?;

    let rendered = render_ruleset(cfg, &params.ruleset, &params.allow_ssh_from)?;
    ensure_isolation_intact(cfg, &params.allow_ssh_from, &rendered)?;

    let tmp_path = std::env::temp_dir().join("pmx-network-validate.nft");
    fs::write(&tmp_path, rendered).with_context(|| "write validation ruleset")?;

    let path = tmp_path.display().to_string();
    runner
        .run_expect_ok("nft", &["-c", "-f", &path])
        .await
        .with_context(|| "nft syntax check")?;

    Ok("ok".to_string())
}

pub async fn apply(cfg: &Config, runner: &Runner, params: ApplyParams) -> Result<ApplyResult> {
    let was_lockdown = is_lockdown_enabled(cfg)?;

    ensure_limit(cfg, &params.ruleset)?;
    ensure_ruleset_target(&params.ruleset)?;
    fs::create_dir_all(&cfg.nftables.ruleset_dir).with_context(|| "create nft ruleset dir")?;

    let revision = normalize_revision(params.ruleset.revision.clone())?;
    let ruleset_dir = Path::new(&cfg.nftables.ruleset_dir);
    let target = Path::new(&cfg.nftables.ruleset_dir).join(format!("{}.nft", revision));
    let staging = ruleset_dir.join(format!(".{}.tmp", revision));

    let rendered = render_ruleset(cfg, &params.ruleset, &params.allow_ssh_from)?;
    ensure_isolation_intact(cfg, &params.allow_ssh_from, &rendered)?;

    let changed_lines = match read_active_path(cfg)? {
        Some(prev) if prev.exists() => {
            diff_line_count(&fs::read_to_string(prev).unwrap_or_default(), &rendered)
        }
        _ => rendered.lines().count(),
    };

    fs::write(&staging, &rendered)
        .with_context(|| format!("write ruleset {}", staging.display()))?;
    let staging_s = staging.display().to_string();

    runner
        .run_expect_ok("nft", &["-c", "-f", &staging_s])
        .await
        .with_context(|| "nft syntax check")?;
    fs::rename(&staging, &target).with_context(|| "atomically promote staged ruleset")?;
    let target_s = target.display().to_string();
    runner
        .run_expect_ok("nft", &["-f", &target_s])
        .await
        .with_context(|| "nft apply")?;

    let active_link = Path::new(&cfg.nftables.ruleset_dir).join("active.nft");
    let _ = fs::remove_file(&active_link);
    std::os::unix::fs::symlink(&target, &active_link)
        .with_context(|| "update active ruleset symlink")?;
    if was_lockdown {
        set_lockdown_enabled(cfg, false)?;
    }

    Ok(ApplyResult {
        revision,
        path: target_s,
        changed_lines,
    })
}

pub async fn clear(cfg: &Config, runner: &Runner) -> Result<()> {
    if is_lockdown_enabled(cfg)? {
        bail!("LOCKDOWN_ACTIVE: firewall.rules.clear is refused while lockdown is active");
    }

    let empty = format!(
        "flush table inet {}\n{}",
        default_table(),
        render_isolation_table(cfg, &[])?
    );

    let clear_file = Path::new(&cfg.nftables.ruleset_dir).join("clear.nft");
    fs::create_dir_all(&cfg.nftables.ruleset_dir)?;
    fs::write(&clear_file, &empty)?;
    let clear_path = clear_file.display().to_string();
    runner.run_expect_ok("nft", &["-f", &clear_path]).await?;
    Ok(())
}

pub async fn emergency_lockdown(
    cfg: &Config,
    runner: &Runner,
    params: LockdownParams,
) -> Result<ApplyResult> {
    if params.management_cidrs.is_empty() {
        bail!("management_cidrs is required for lockdown");
    }

    let lockdown_ruleset = RuleSet {
        revision: Some(format!("lockdown-{}", chrono::Utc::now().timestamp())),
        family: "inet".to_string(),
        table: default_table(),
        chains: vec![Chain {
            name: "input".to_string(),
            chain_type: Some("filter".to_string()),
            hook: Some("input".to_string()),
            priority: Some(0),
            policy: Some("drop".to_string()),
        }],
        rules: params
            .management_cidrs
            .iter()
            .map(|cidr| Rule {
                chain: "input".to_string(),
                expr: vec![
                    Expr::Match {
                        left: "ip saddr".to_string(),
                        op: "==".to_string(),
                        right: cidr.clone(),
                    },
                    Expr::Accept,
                ],
            })
            .collect(),
    };

    let result = apply(
        cfg,
        runner,
        ApplyParams {
            ruleset: lockdown_ruleset,
            allow_ssh_from: params.management_cidrs,
        },
    )
    .await?;

    set_lockdown_enabled(cfg, true)?;
    Ok(result)
}

fn ensure_limit(cfg: &Config, ruleset: &RuleSet) -> Result<()> {
    if ruleset.rules.len() > cfg.nftables.max_rules_per_host {
        bail!(
            "RULE_LIMIT_EXCEEDED: rules={} max={}",
            ruleset.rules.len(),
            cfg.nftables.max_rules_per_host
        );
    }
    Ok(())
}

fn ensure_ruleset_target(ruleset: &RuleSet) -> Result<()> {
    if ruleset.table == "pmx-isolation" {
        bail!("ruleset table 'pmx-isolation' is reserved and immutable");
    }
    if ruleset.family != "inet" && ruleset.family != "ip" && ruleset.family != "ip6" {
        bail!("unsupported table family {}", ruleset.family);
    }
    if !is_safe_ident(&ruleset.table) {
        bail!("invalid table name {}", ruleset.table);
    }
    for chain in &ruleset.chains {
        validate_chain(chain)?;
    }
    Ok(())
}

fn render_ruleset(cfg: &Config, ruleset: &RuleSet, allow_ssh_from: &[String]) -> Result<String> {
    let mut declared_chains = BTreeSet::new();
    for chain in &ruleset.chains {
        declared_chains.insert(chain.name.clone());
    }

    let mut rendered_rules: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rule in &ruleset.rules {
        if !declared_chains.contains(&rule.chain) {
            bail!("rule references undeclared chain {}", rule.chain);
        }
        let line = render_exprs(&rule.expr)?;
        rendered_rules
            .entry(rule.chain.clone())
            .or_default()
            .push(line);
    }

    let mut out = String::new();
    out.push_str(&render_isolation_table(cfg, allow_ssh_from)?);

    out.push_str(&format!(
        "\ntable {} {} {{\n",
        ruleset.family, ruleset.table
    ));
    for chain in &ruleset.chains {
        out.push_str(&format!("  chain {} {{\n", chain.name));
        if let (Some(chain_type), Some(hook)) = (&chain.chain_type, &chain.hook) {
            let priority = chain.priority.unwrap_or(0);
            let policy = chain.policy.clone().unwrap_or_else(|| "accept".to_string());
            out.push_str(&format!(
                "    type {} hook {} priority {}; policy {};\n",
                chain_type, hook, priority, policy
            ));
        }
        if let Some(lines) = rendered_rules.get(&chain.name) {
            for line in lines {
                out.push_str("    ");
                out.push_str(line);
                out.push('\n');
            }
        }
        out.push_str("  }\n");
    }
    out.push_str("}\n");
    Ok(out)
}

fn render_isolation_table(cfg: &Config, allow_ssh_from: &[String]) -> Result<String> {
    let mut allowed = cfg.isolation.allow_ssh_from.clone();
    for cidr in allow_ssh_from {
        if !allowed.contains(cidr) {
            allowed.push(cidr.clone());
        }
    }

    let mut out = String::new();
    out.push_str("table inet pmx-isolation {\n");
    out.push_str("  chain input {\n");
    out.push_str(&format!(
        "    type filter hook input priority {};\n",
        ISOLATION_INPUT_PRIORITY
    ));
    if cfg.isolation.default_drop_input {
        out.push_str("    policy drop;\n");
    } else {
        out.push_str("    policy accept;\n");
    }
    out.push_str("    ct state established,related accept\n");
    for cidr in allowed {
        let parsed = validate_ip_or_cidr(&cidr)?;
        out.push_str(&format!("    ip saddr {} tcp dport 22 accept\n", parsed));
    }
    out.push_str("  }\n");
    out.push_str("}\n");
    Ok(out)
}

fn render_exprs(exprs: &[Expr]) -> Result<String> {
    let mut out = Vec::with_capacity(exprs.len());
    for expr in exprs {
        match expr {
            Expr::Match { left, op, right } => out.push(render_match_expr(left, op, right)?),
            Expr::Counter => out.push("counter".to_string()),
            Expr::Accept => out.push("accept".to_string()),
            Expr::Drop => out.push("drop".to_string()),
            Expr::Jump { target } => {
                if !is_safe_ident(target) {
                    bail!("invalid jump target {}", target);
                }
                out.push(format!("jump {}", target));
            }
        }
    }
    Ok(out.join(" "))
}

fn ensure_isolation_intact(cfg: &Config, allow_ssh_from: &[String], rendered: &str) -> Result<()> {
    let expected = render_isolation_table(cfg, allow_ssh_from)?;
    if !rendered.starts_with(&expected) {
        bail!("isolation table is missing or modified");
    }
    Ok(())
}

fn read_active_path(cfg: &Config) -> Result<Option<PathBuf>> {
    let active = Path::new(&cfg.nftables.ruleset_dir).join("active.nft");
    if !active.exists() {
        return Ok(None);
    }
    let target = fs::read_link(active).with_context(|| "read active ruleset symlink")?;
    Ok(Some(target))
}

fn diff_line_count(old: &str, new: &str) -> usize {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let max_len = old_lines.len().max(new_lines.len());
    let mut changed = 0usize;
    for idx in 0..max_len {
        let a = old_lines.get(idx).copied().unwrap_or("");
        let b = new_lines.get(idx).copied().unwrap_or("");
        if a != b {
            changed += 1;
        }
    }
    changed
}

fn lockdown_state_path(cfg: &Config) -> PathBuf {
    Path::new(&cfg.state.dir).join("lockdown-state.json")
}

fn is_lockdown_enabled(cfg: &Config) -> Result<bool> {
    let path = lockdown_state_path(cfg);
    if !path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(path)?;
    let v: serde_json::Value = serde_json::from_str(&raw)?;
    Ok(v.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false))
}

fn set_lockdown_enabled(cfg: &Config, enabled: bool) -> Result<()> {
    fs::create_dir_all(&cfg.state.dir)?;
    let path = lockdown_state_path(cfg);
    let content = serde_json::json!({ "enabled": enabled });
    fs::write(path, serde_json::to_string_pretty(&content)?)?;
    Ok(())
}

fn normalize_revision(revision: Option<String>) -> Result<String> {
    let candidate = revision.unwrap_or_else(|| format!("rev-{}", chrono::Utc::now().timestamp()));
    let trimmed = candidate.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        bail!("invalid revision");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("invalid revision");
    }
    Ok(trimmed.to_string())
}

fn validate_chain(chain: &Chain) -> Result<()> {
    if !is_safe_ident(&chain.name) {
        bail!("invalid chain name {}", chain.name);
    }
    if chain.chain_type.is_some() != chain.hook.is_some() {
        bail!("chain {} must set chain_type and hook together", chain.name);
    }
    if let Some(chain_type) = &chain.chain_type {
        if chain_type != "filter" && chain_type != "nat" && chain_type != "route" {
            bail!("unsupported chain type {}", chain_type);
        }
    }
    if let Some(hook) = &chain.hook {
        match hook.as_str() {
            "input" | "output" | "forward" | "prerouting" | "postrouting" | "ingress" => {}
            _ => bail!("unsupported hook {}", hook),
        }
        let priority = chain.priority.unwrap_or(0);
        if hook == "input" && priority <= ISOLATION_INPUT_PRIORITY {
            bail!(
                "input chain priority {} must be greater than isolation priority {}",
                priority,
                ISOLATION_INPUT_PRIORITY
            );
        }
    }
    if let Some(policy) = &chain.policy {
        if policy != "accept" && policy != "drop" {
            bail!("unsupported policy {}", policy);
        }
    }
    Ok(())
}

fn is_safe_ident(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

fn render_match_expr(left: &str, op: &str, right: &str) -> Result<String> {
    let left = left.trim().to_lowercase();
    let op = op.trim().to_lowercase();
    let right = right.trim();

    if right.is_empty() {
        bail!("match right-hand side is required");
    }

    match left.as_str() {
        "ip saddr" | "ip daddr" | "ip6 saddr" | "ip6 daddr" => {
            let cmp = normalize_comparison_op(&op)?;
            let rhs = validate_ip_or_cidr(right)?;
            Ok(render_value_match(&left, cmp, &rhs))
        }
        "tcp dport" | "udp dport" => {
            let cmp = normalize_comparison_op(&op)?;
            let rhs = validate_port_expr(right)?;
            Ok(render_value_match(&left, cmp, &rhs))
        }
        "meta l4proto" => {
            let cmp = normalize_comparison_op(&op)?;
            let rhs = validate_l4_proto(right)?;
            Ok(render_value_match(&left, cmp, rhs))
        }
        "iifname" | "oifname" => {
            let cmp = normalize_comparison_op(&op)?;
            let rhs = validate_interface_name(right)?;
            Ok(render_value_match(&left, cmp, &format!("\"{}\"", rhs)))
        }
        "ct state" => {
            if op != "in" {
                bail!("ct state matches require op=in");
            }
            let states = validate_ct_states(right)?;
            Ok(format!("ct state {{ {} }}", states.join(", ")))
        }
        _ => bail!("unsupported match field {}", left),
    }
}

fn render_value_match(left: &str, cmp: &str, right: &str) -> String {
    if cmp == "!=" {
        format!("{} != {}", left, right)
    } else {
        format!("{} {}", left, right)
    }
}

fn normalize_comparison_op(op: &str) -> Result<&'static str> {
    match op {
        "==" | "=" => Ok("=="),
        "!=" => Ok("!="),
        "in" => Ok("in"),
        _ => bail!("unsupported match operator {}", op),
    }
}

fn validate_ip_or_cidr(value: &str) -> Result<String> {
    if let Some((ip, prefix)) = value.split_once('/') {
        let ip: IpAddr = ip
            .parse()
            .with_context(|| format!("invalid ip in cidr {}", value))?;
        let prefix: u8 = prefix
            .parse::<u8>()
            .with_context(|| format!("invalid prefix in cidr {}", value))?;
        match ip {
            IpAddr::V4(_) if prefix <= 32 => Ok(format!("{}/{}", ip, prefix)),
            IpAddr::V6(_) if prefix <= 128 => Ok(format!("{}/{}", ip, prefix)),
            _ => bail!("invalid prefix in cidr {}", value),
        }
    } else {
        let ip: IpAddr = value
            .parse()
            .with_context(|| format!("invalid ip {}", value))?;
        Ok(ip.to_string())
    }
}

fn validate_port_expr(value: &str) -> Result<String> {
    if let Some((lo, hi)) = value.split_once('-') {
        let lo: u16 = lo.trim().parse().with_context(|| "invalid lower port")?;
        let hi: u16 = hi.trim().parse().with_context(|| "invalid upper port")?;
        if lo == 0 || hi == 0 || lo > hi {
            bail!("invalid port range {}", value);
        }
        return Ok(format!("{}-{}", lo, hi));
    }
    let port: u16 = value
        .trim()
        .parse()
        .with_context(|| format!("invalid port {}", value))?;
    if port == 0 {
        bail!("invalid port {}", value);
    }
    Ok(port.to_string())
}

fn validate_l4_proto(value: &str) -> Result<&'static str> {
    match value.trim().to_lowercase().as_str() {
        "tcp" => Ok("tcp"),
        "udp" => Ok("udp"),
        "icmp" => Ok("icmp"),
        "icmpv6" => Ok("icmpv6"),
        _ => bail!("invalid l4 protocol {}", value),
    }
}

fn validate_interface_name(value: &str) -> Result<String> {
    let v = value.trim();
    if v.is_empty()
        || !v
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("invalid interface name {}", value);
    }
    Ok(v.to_string())
}

fn validate_ct_states(value: &str) -> Result<Vec<&'static str>> {
    let mut out = Vec::new();
    for raw in value.split(',') {
        let state = raw.trim().to_lowercase();
        let normalized = match state.as_str() {
            "new" => "new",
            "established" => "established",
            "related" => "related",
            "invalid" => "invalid",
            "untracked" => "untracked",
            _ => bail!("invalid conntrack state {}", state),
        };
        if !out.contains(&normalized) {
            out.push(normalized);
        }
    }
    if out.is_empty() {
        bail!("ct state list cannot be empty");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> Config {
        Config {
            backend: crate::config::Backend {
                url: "wss://example/ws".to_string(),
                auth_token: String::new(),
            },
            identity: crate::config::Identity {
                cert: "cert".to_string(),
                key: "key".to_string(),
            },
            keyset: crate::config::Keyset {
                path: "keyset".to_string(),
            },
            wireguard: crate::config::WireGuard {
                key_file: "/tmp/wg.key".to_string(),
                listen_port_range: [51820, 51830],
                max_peers_per_host: 256,
                interface: "pmxwg0".to_string(),
            },
            nftables: crate::config::Nftables {
                ruleset_dir: "/tmp/pmx-nft".to_string(),
                max_rules_per_host: 10_000,
            },
            isolation: crate::config::Isolation {
                default_drop_input: true,
                allow_ssh_from: vec![],
            },
            state: crate::config::State {
                dir: "/tmp/pmx-network-state".to_string(),
            },
        }
    }

    #[test]
    fn render_includes_isolation_table() {
        let cfg = test_cfg();
        let rs = RuleSet {
            revision: None,
            family: "inet".to_string(),
            table: "pmx-cloud".to_string(),
            chains: vec![],
            rules: vec![],
        };
        let rendered = render_ruleset(&cfg, &rs, &[]).unwrap();
        assert!(rendered.contains("table inet pmx-isolation"));
    }

    #[test]
    fn hard_limit_rejects_overflow() {
        let cfg = test_cfg();

        let mut rules = Vec::new();
        for _ in 0..10_001 {
            rules.push(Rule {
                chain: "input".to_string(),
                expr: vec![Expr::Drop],
            });
        }
        let rs = RuleSet {
            revision: None,
            family: "inet".to_string(),
            table: "pmx-cloud".to_string(),
            chains: vec![],
            rules,
        };

        assert!(ensure_limit(&cfg, &rs).is_err());
    }

    // ── normalize_revision ───────────────────────────────────────────────────

    #[test]
    fn normalize_revision_accepts_alphanumeric_with_dashes() {
        let r = normalize_revision(Some("rev-20240101_abc.1".to_string())).unwrap();
        assert_eq!(r, "rev-20240101_abc.1");
    }

    #[test]
    fn normalize_revision_rejects_empty() {
        assert!(normalize_revision(Some(String::new())).is_err());
    }

    #[test]
    fn normalize_revision_rejects_too_long() {
        let long = "a".repeat(129);
        assert!(normalize_revision(Some(long)).is_err());
    }

    #[test]
    fn normalize_revision_rejects_special_chars() {
        assert!(normalize_revision(Some("rev/1".to_string())).is_err());
        assert!(normalize_revision(Some("rev;1".to_string())).is_err());
        assert!(normalize_revision(Some("rev 1".to_string())).is_err());
    }

    #[test]
    fn normalize_revision_auto_generates_when_none() {
        let r = normalize_revision(None).unwrap();
        // Should start with "rev-" and contain digits
        assert!(
            r.starts_with("rev-"),
            "auto revision should start with rev-: {r}"
        );
    }

    // ── validate_chain ───────────────────────────────────────────────────────

    #[test]
    fn validate_chain_accepts_valid_filter_input() {
        let chain = Chain {
            name: "input".to_string(),
            chain_type: Some("filter".to_string()),
            hook: Some("input".to_string()),
            priority: Some(0),
            policy: Some("drop".to_string()),
        };
        assert!(validate_chain(&chain).is_ok());
    }

    #[test]
    fn validate_chain_rejects_reserved_pmx_isolation_priority() {
        let chain = Chain {
            name: "input".to_string(),
            chain_type: Some("filter".to_string()),
            hook: Some("input".to_string()),
            priority: Some(ISOLATION_INPUT_PRIORITY),
            policy: Some("drop".to_string()),
        };
        assert!(validate_chain(&chain).is_err());
    }

    #[test]
    fn validate_chain_rejects_mismatched_type_and_hook() {
        let chain = Chain {
            name: "mychain".to_string(),
            chain_type: Some("filter".to_string()),
            hook: None,
            priority: None,
            policy: None,
        };
        assert!(validate_chain(&chain).is_err());
    }

    #[test]
    fn validate_chain_rejects_invalid_chain_type() {
        let chain = Chain {
            name: "mychain".to_string(),
            chain_type: Some("badtype".to_string()),
            hook: Some("input".to_string()),
            priority: Some(0),
            policy: None,
        };
        assert!(validate_chain(&chain).is_err());
    }

    #[test]
    fn validate_chain_rejects_invalid_hook() {
        let chain = Chain {
            name: "mychain".to_string(),
            chain_type: Some("filter".to_string()),
            hook: Some("badhook".to_string()),
            priority: Some(0),
            policy: None,
        };
        assert!(validate_chain(&chain).is_err());
    }

    #[test]
    fn validate_chain_rejects_invalid_policy() {
        let chain = Chain {
            name: "mychain".to_string(),
            chain_type: Some("filter".to_string()),
            hook: Some("output".to_string()),
            priority: Some(0),
            policy: Some("reject".to_string()),
        };
        assert!(validate_chain(&chain).is_err());
    }

    // ── ensure_ruleset_target ────────────────────────────────────────────────

    #[test]
    fn ensure_ruleset_target_rejects_reserved_table() {
        let rs = RuleSet {
            revision: None,
            family: "inet".to_string(),
            table: "pmx-isolation".to_string(),
            chains: vec![],
            rules: vec![],
        };
        assert!(ensure_ruleset_target(&rs).is_err());
    }

    #[test]
    fn ensure_ruleset_target_rejects_unsupported_family() {
        let rs = RuleSet {
            revision: None,
            family: "bridge".to_string(),
            table: "mytable".to_string(),
            chains: vec![],
            rules: vec![],
        };
        assert!(ensure_ruleset_target(&rs).is_err());
    }

    // ── validate_ip_or_cidr ──────────────────────────────────────────────────

    #[test]
    fn validate_ip_or_cidr_accepts_valid_ipv4() {
        assert!(validate_ip_or_cidr("10.0.0.1").is_ok());
        assert!(validate_ip_or_cidr("192.168.1.0/24").is_ok());
    }

    #[test]
    fn validate_ip_or_cidr_accepts_valid_ipv6() {
        assert!(validate_ip_or_cidr("2001:db8::1").is_ok());
        assert!(validate_ip_or_cidr("2001:db8::/32").is_ok());
    }

    #[test]
    fn validate_ip_or_cidr_rejects_bad_input() {
        assert!(validate_ip_or_cidr("not-an-ip").is_err());
        assert!(validate_ip_or_cidr("10.0.0.1/64").is_err());
        assert!(validate_ip_or_cidr("").is_err());
    }

    // ── validate_port_expr ───────────────────────────────────────────────────

    #[test]
    fn validate_port_expr_accepts_single_port() {
        assert_eq!(validate_port_expr("80").unwrap(), "80");
        assert_eq!(validate_port_expr("443").unwrap(), "443");
    }

    #[test]
    fn validate_port_expr_accepts_range() {
        assert_eq!(validate_port_expr("1024-2048").unwrap(), "1024-2048");
    }

    #[test]
    fn validate_port_expr_rejects_zero() {
        assert!(validate_port_expr("0").is_err());
    }

    #[test]
    fn validate_port_expr_rejects_invalid_range() {
        assert!(validate_port_expr("100-50").is_err());
        assert!(validate_port_expr("0-100").is_err());
    }

    // ── validate_ct_states ───────────────────────────────────────────────────

    #[test]
    fn validate_ct_states_accepts_known_states() {
        let states = validate_ct_states("new,established,related").unwrap();
        assert!(states.contains(&"new"));
        assert!(states.contains(&"established"));
        assert!(states.contains(&"related"));
    }

    #[test]
    fn validate_ct_states_rejects_unknown_state() {
        assert!(validate_ct_states("bogus").is_err());
    }

    #[test]
    fn validate_ct_states_deduplicates() {
        let states = validate_ct_states("new,new,established").unwrap();
        assert_eq!(states.iter().filter(|&&s| s == "new").count(), 1);
    }

    // ── render_exprs ─────────────────────────────────────────────────────────

    #[test]
    fn render_exprs_accept_drop_and_accept() {
        let out = render_exprs(&[Expr::Drop]).unwrap();
        assert_eq!(out, "drop");
        let out = render_exprs(&[Expr::Accept]).unwrap();
        assert_eq!(out, "accept");
    }

    #[test]
    fn render_exprs_accept_jump_valid_target() {
        let out = render_exprs(&[Expr::Jump {
            target: "my-chain".to_string(),
        }])
        .unwrap();
        assert_eq!(out, "jump my-chain");
    }

    #[test]
    fn render_exprs_rejects_jump_with_bad_target() {
        let err = render_exprs(&[Expr::Jump {
            target: "bad;target".to_string(),
        }])
        .unwrap_err();
        assert!(err.to_string().contains("invalid jump target"), "{err}");
    }

    // ── diff_line_count ──────────────────────────────────────────────────────

    #[test]
    fn diff_line_count_zero_when_identical() {
        assert_eq!(diff_line_count("a\nb\nc", "a\nb\nc"), 0);
    }

    #[test]
    fn diff_line_count_counts_changed_lines() {
        assert_eq!(diff_line_count("a\nb", "a\nc"), 1);
    }

    #[test]
    fn diff_line_count_counts_added_lines() {
        assert_eq!(diff_line_count("a", "a\nb"), 1);
    }
}
