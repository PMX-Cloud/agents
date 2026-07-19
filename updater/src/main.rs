#![forbid(unsafe_code)]

use pmx_updater::{agent_update, config, envelope, maintenance, os_update};

use anyhow::{bail, Context, Result};
use clap::Parser;
use config::Config;
use maintenance::window::{is_now, read_cache, write_cache, WindowSet};
use pmx_shared::capability::{self, Stability};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, Read};

const AGENT_CLASS: &str = "pmx-updater";

/// Declare all pmx-updater commands in the global capability registry.
/// Called once at boot so the backend can query `*.capabilities`.
fn declare_capabilities() {
    // Maintenance windows
    capability::declare(AGENT_CLASS, "update.maintenance.set", 1, Stability::Stable);
    capability::declare(
        AGENT_CLASS,
        "update.maintenance.is_now",
        1,
        Stability::Stable,
    );

    // OS updates
    capability::declare(AGENT_CLASS, "update.os.scan", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "update.os.dry_run", 1, Stability::Stable);
    capability::declare(
        AGENT_CLASS,
        "update.os.apply.security",
        1,
        Stability::Stable,
    );
    capability::declare(AGENT_CLASS, "update.os.apply.full", 1, Stability::Stable);

    // Agent self-update
    capability::declare(AGENT_CLASS, "update.agent.check", 1, Stability::Stable);
    capability::declare(AGENT_CLASS, "update.agent.apply", 1, Stability::Stable);
}

#[derive(Parser, Debug)]
#[command(name = "pmx-updater")]
struct Args {
    #[arg(long, default_value = "/etc/pmx-cloud/pmx-updater.conf")]
    config: String,
    #[arg(long)]
    preflight: bool,
    #[arg(long)]
    version: bool,
    #[arg(long)]
    finalize_self_swap: Option<String>,
    #[arg(long)]
    self_rollback_if_sentinel_stale: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.version {
        println!("pmx-updater version {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let cfg = Config::load(&args.config)?;

    if let Some(old_version) = args.finalize_self_swap {
        let my_version = env!("CARGO_PKG_VERSION");
        let handle = agent_update::swap::SwapHandle {
            agent: "pmx-updater".to_string(),
            new_version: my_version.to_string(),
            old_version: Some(old_version),
            agents_base: std::path::PathBuf::from(&cfg.files.agents_base),
        };

        agent_update::swap::install_self(&handle)?;

        // Remove sentinel
        let sentinel_path = format!("/run/pmx-cloud/updater.swap.{}", my_version);
        let _ = std::fs::remove_file(&sentinel_path);

        // Validate config as our "health check"
        cfg.validate()?;

        println!("self-swap to {} finalized", my_version);
        return Ok(());
    }

    if args.self_rollback_if_sentinel_stale {
        let my_version = env!("CARGO_PKG_VERSION");
        let sentinel_path = format!("/run/pmx-cloud/updater.swap.{}", my_version);
        if std::path::Path::new(&sentinel_path).exists() {
            println!(
                "sentinel {} is stale, performing self-rollback",
                sentinel_path
            );
            agent_update::swap::rollback_self(&cfg)?;
            // Attempt to remove the stale sentinel
            let _ = std::fs::remove_file(&sentinel_path);
        }
        return Ok(());
    }

    if args.preflight {
        cfg.validate()?;
        println!("preflight: ok");
        return Ok(());
    }

    // Register capabilities before processing commands.
    declare_capabilities();

    let mut stdin = Vec::new();
    io::stdin()
        .read_to_end(&mut stdin)
        .context("read envelope from stdin")?;
    let verified = envelope::read_and_verify_envelope(
        &stdin,
        &cfg.keyset.path,
        &cfg.identity.host_fingerprint_file,
    )?;

    let result = dispatch(
        &cfg,
        &verified.envelope.command,
        &verified.envelope.params,
        verified.signing_key_index,
    )?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn dispatch(
    cfg: &Config,
    command: &str,
    params: &BTreeMap<String, Value>,
    signing_key_index: usize,
) -> Result<Value> {
    match command {
        "update.maintenance.set" => {
            let windows: WindowSet = serde_json::from_value(json!({ "windows": params.get("windows").cloned().unwrap_or(Value::Array(vec![])) }))
                .context("decode maintenance window set")?;
            write_cache(&cfg.files.maintenance_window_cache_path, &windows)?;
            Ok(json!({ "written": true, "count": windows.windows.len() }))
        }
        "update.maintenance.is_now" => {
            let windows = read_cache(&cfg.files.maintenance_window_cache_path)?;
            let status = is_now(&windows, chrono::Utc::now())?;
            Ok(serde_json::to_value(status)?)
        }
        "update.os.scan" => Ok(serde_json::to_value(os_update::apt::scan()?)?),
        "update.os.dry_run" => Ok(serde_json::to_value(os_update::apt::apply(
            os_update::ApplyMode::DryRun,
            vec![],
        )?)?),
        "update.os.apply.security" => {
            check_os_update_allowed(cfg, params, signing_key_index)?;
            Ok(serde_json::to_value(os_update::apt::apply(
                os_update::ApplyMode::Security,
                vec![],
            )?)?)
        }
        "update.os.apply.full" => {
            check_os_update_allowed(cfg, params, signing_key_index)?;
            Ok(serde_json::to_value(os_update::apt::apply(
                os_update::ApplyMode::Full,
                vec![],
            )?)?)
        }
        "update.agent.check" => Ok(serde_json::to_value(agent_update::check(cfg)?)?),
        "update.agent.apply" => {
            let windows =
                maintenance::window::read_cache(&cfg.files.maintenance_window_cache_path)?;
            let override_window = params
                .get("override_window")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            maintenance::check_update_allowed(&windows, override_window, signing_key_index)?;
            Ok(serde_json::to_value(agent_update::apply(cfg)?)?)
        }
        other => bail!("unsupported command {}", other),
    }
}

fn check_os_update_allowed(
    cfg: &Config,
    params: &BTreeMap<String, Value>,
    signing_key_index: usize,
) -> Result<()> {
    let windows = read_cache(&cfg.files.maintenance_window_cache_path)?;
    let override_window = params
        .get("override_window")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    maintenance::check_update_allowed(&windows, override_window, signing_key_index)
}

#[cfg(test)]
mod tests {
    use super::{check_os_update_allowed, declare_capabilities, dispatch, AGENT_CLASS};
    use crate::config::{Config, FilesConfig, IdentityConfig, KeysetConfig};
    use pmx_shared::capability;
    #[allow(unused_imports)]
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::fs;

    fn test_config(cache_path: &str) -> Config {
        Config {
            identity: IdentityConfig {
                host_fingerprint_file: "/tmp/host-fingerprint".to_string(),
                agent_name: "pmx-updater".to_string(),
                agent_arch: "amd64".to_string(),
            },
            keyset: KeysetConfig {
                path: "/tmp/keyset.pub".to_string(),
                release_pubkey: String::new(),
            },
            files: FilesConfig {
                maintenance_window_cache_path: cache_path.to_string(),
                manifest_url: String::new(),
                agents_base: "/opt/pmx-cloud/agents".to_string(),
                staging_dir: "/var/lib/pmx-cloud/updater/staging".to_string(),
            },
        }
    }

    #[test]
    fn maintenance_set_then_check_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_path = dir.path().join("window.json");
        let cfg = test_config(cache_path.to_str().expect("path"));

        let mut set_params = BTreeMap::new();
        set_params.insert(
            "windows".to_string(),
            json!([{ "days": ["Sat"], "start": "02:00", "end": "06:00", "tz": "UTC" }]),
        );
        // signing_key_index=0 (release key) for non-window-gated commands
        let set_result =
            dispatch(&cfg, "update.maintenance.set", &set_params, 0).expect("set result");
        assert_eq!(set_result["written"], json!(true));

        let payload = fs::read_to_string(&cache_path).expect("cache file");
        assert!(payload.contains("Sat"));

        let is_now = dispatch(&cfg, "update.maintenance.is_now", &BTreeMap::new(), 0)
            .expect("is_now result");
        assert!(is_now.get("active").is_some());
    }

    #[test]
    fn apply_security_requires_window_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_path = dir.path().join("missing-window.json");
        let cfg = test_config(cache_path.to_str().expect("path"));
        let err = dispatch(&cfg, "update.os.apply.security", &BTreeMap::new(), 0)
            .expect_err("should fail");
        assert!(err.to_string().contains("read maintenance cache"));
    }

    #[test]
    fn apply_full_requires_window_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_path = dir.path().join("missing-window.json");
        let cfg = test_config(cache_path.to_str().expect("path"));
        let err =
            dispatch(&cfg, "update.os.apply.full", &BTreeMap::new(), 0).expect_err("should fail");
        assert!(err.to_string().contains("read maintenance cache"));
    }

    #[test]
    fn apply_agent_requires_window_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_path = dir.path().join("missing-window.json");
        let cfg = test_config(cache_path.to_str().expect("path"));
        let err =
            dispatch(&cfg, "update.agent.apply", &BTreeMap::new(), 0).expect_err("should fail");
        assert!(err.to_string().contains("read maintenance cache"));
    }

    #[test]
    fn unsupported_command_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_path = dir.path().join("window.json");
        let cfg = test_config(cache_path.to_str().expect("path"));
        let err =
            dispatch(&cfg, "update.nonexistent", &BTreeMap::new(), 0).expect_err("should fail");
        assert!(err.to_string().contains("unsupported command"));
    }

    #[test]
    fn apply_security_outside_window_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_path = dir.path().join("window.json");
        let cfg = test_config(cache_path.to_str().expect("path"));

        // Set a window that is definitely not now (e.g. only Sunday 02:00-06:00 UTC)
        let mut set_params = BTreeMap::new();
        set_params.insert(
            "windows".to_string(),
            json!([{ "days": ["Sun"], "start": "02:00", "end": "06:00", "tz": "UTC" }]),
        );
        let _ = dispatch(&cfg, "update.maintenance.set", &set_params, 0).expect("set result");

        // Try to apply security with job key (index=1) and no override
        let err = dispatch(&cfg, "update.os.apply.security", &BTreeMap::new(), 1)
            .expect_err("should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("outside_maintenance_window")
                || msg.contains("override_requires_release_key"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn apply_security_override_with_release_key_permitted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_path = dir.path().join("window.json");
        let cfg = test_config(cache_path.to_str().expect("path"));

        // Set a restrictive window
        let mut set_params = BTreeMap::new();
        set_params.insert(
            "windows".to_string(),
            json!([{ "days": ["Sun"], "start": "02:00", "end": "06:00", "tz": "UTC" }]),
        );
        let _ = dispatch(&cfg, "update.maintenance.set", &set_params, 0).expect("set result");

        // Override with release key (index=0) should pass authorization without
        // invoking the host package manager from this unit test.
        let mut apply_params = BTreeMap::new();
        apply_params.insert("override_window".to_string(), json!(true));
        check_os_update_allowed(&cfg, &apply_params, 0)
            .expect("override with release key should be permitted");
    }

    #[test]
    fn apply_security_override_with_job_key_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_path = dir.path().join("window.json");
        let cfg = test_config(cache_path.to_str().expect("path"));

        // Set a restrictive window
        let mut set_params = BTreeMap::new();
        set_params.insert(
            "windows".to_string(),
            json!([{ "days": ["Sun"], "start": "02:00", "end": "06:00", "tz": "UTC" }]),
        );
        let _ = dispatch(&cfg, "update.maintenance.set", &set_params, 0).expect("set result");

        // Override with job key (index=1) should be rejected
        let mut apply_params = BTreeMap::new();
        apply_params.insert("override_window".to_string(), json!(true));
        let err =
            dispatch(&cfg, "update.os.apply.security", &apply_params, 1).expect_err("should fail");
        assert!(err.to_string().contains("override_requires_release_key"));
    }

    #[test]
    fn declare_capabilities_registers_all_commands() {
        declare_capabilities();
        // Verify all expected capabilities are declared
        let caps = capability::list();
        let names: Vec<&str> = caps
            .iter()
            .filter(|c| c.agent_class == AGENT_CLASS)
            .map(|c| c.command.as_str())
            .collect();
        assert!(
            names.contains(&"update.maintenance.set"),
            "missing update.maintenance.set"
        );
        assert!(
            names.contains(&"update.maintenance.is_now"),
            "missing update.maintenance.is_now"
        );
        assert!(names.contains(&"update.os.scan"), "missing update.os.scan");
        assert!(
            names.contains(&"update.os.dry_run"),
            "missing update.os.dry_run"
        );
        assert!(
            names.contains(&"update.os.apply.security"),
            "missing update.os.apply.security"
        );
        assert!(
            names.contains(&"update.os.apply.full"),
            "missing update.os.apply.full"
        );
        assert!(
            names.contains(&"update.agent.check"),
            "missing update.agent.check"
        );
        assert!(
            names.contains(&"update.agent.apply"),
            "missing update.agent.apply"
        );
    }
}
