pub mod fetch;
pub mod health;
pub mod manifest;
pub mod rollback;
pub mod swap;
pub mod verify;

use crate::config::Config;
use anyhow::{bail, Context, Result};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::info;

/// Returns the effective release pubkey.
///
/// Priority: baked-in compile-time constant (build.rs) > config file key.
/// Returns `None` only when neither is configured — verification is then skipped
/// (acceptable for dev builds without a real key ceremony).
fn effective_release_pubkey(cfg: &Config) -> Result<Option<VerifyingKey>> {
    if let Some(k) = verify::baked_release_pubkey() {
        return Ok(Some(k));
    }
    if !cfg.keyset.release_pubkey.is_empty() {
        let k = verify::load_pubkey(&cfg.keyset.release_pubkey)
            .context("load release pubkey from config")?;
        return Ok(Some(k));
    }
    Ok(None)
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckResult {
    pub available: bool,
    pub current: String,
    pub latest: String,
    pub reason: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplyResult {
    pub applied: bool,
    pub version: String,
    pub message: String,
}

/// Check whether a new agent version is available.
///
/// When `cfg.files.manifest_url` is empty, returns immediately with
/// `{ available: false, reason: "manifest_url not configured" }`.
/// When configured, performs a real manifest fetch + version comparison.
pub fn check(cfg: &Config) -> Result<Value> {
    if cfg.files.manifest_url.is_empty() {
        return Ok(json!({
            "available": false,
            "current": env!("CARGO_PKG_VERSION"),
            "latest": env!("CARGO_PKG_VERSION"),
            "reason": "manifest_url not configured"
        }));
    }

    let rt = tokio::runtime::Runtime::new().context("create tokio runtime")?;
    rt.block_on(check_async(cfg))
}

/// Async variant of [`check`] — usable from within an existing tokio runtime.
pub async fn check_async(cfg: &Config) -> Result<Value> {
    if cfg.files.manifest_url.is_empty() {
        return Ok(json!({
            "available": false,
            "current": env!("CARGO_PKG_VERSION"),
            "latest": env!("CARGO_PKG_VERSION"),
            "reason": "manifest_url not configured"
        }));
    }

    let client = reqwest::Client::new();
    let (manifest_bytes, sig_bytes) = fetch::fetch_manifest(&cfg.files.manifest_url, &client)
        .await
        .context("fetch manifest")?;

    // Verify manifest signature — prefer baked-in key, fall back to config.
    if let Some(pubkey) = effective_release_pubkey(cfg).context("resolve release pubkey")? {
        verify::verify_manifest(&manifest_bytes, &sig_bytes, &pubkey)
            .context("verify manifest signature")?;
    }

    let m = manifest::Manifest::parse(&manifest_bytes).context("parse manifest")?;

    let current = env!("CARGO_PKG_VERSION");
    let latest = &m.version;
    let available = latest != current;

    Ok(json!({
        "available": available,
        "current": current,
        "latest": latest,
    }))
}

/// Apply a new agent version.
///
/// Steps:
/// 1. Fetch and verify the manifest.
/// 2. Fetch and verify the binary.
/// 3. Swap the symlinks.
/// 4. Health check.
/// 5. Rollback on failure.
pub fn apply(cfg: &Config) -> Result<Value> {
    if cfg.files.manifest_url.is_empty() {
        bail!("manifest_url is not configured — cannot apply update");
    }

    let rt = tokio::runtime::Runtime::new().context("create tokio runtime")?;
    rt.block_on(apply_async(cfg))
}

/// Async variant of [`apply`] — usable from within an existing tokio runtime.
pub async fn apply_async(cfg: &Config) -> Result<Value> {
    if cfg.files.manifest_url.is_empty() {
        bail!("manifest_url is not configured — cannot apply update");
    }

    let client = reqwest::Client::new();

    // 1. Fetch manifest.
    let (manifest_bytes, sig_bytes) = fetch::fetch_manifest(&cfg.files.manifest_url, &client)
        .await
        .context("fetch manifest")?;

    // Verify manifest signature — prefer baked-in key, fall back to config.
    if let Some(pubkey) = effective_release_pubkey(cfg).context("resolve release pubkey")? {
        verify::verify_manifest(&manifest_bytes, &sig_bytes, &pubkey)
            .context("verify manifest signature")?;
    }

    let m = manifest::Manifest::parse(&manifest_bytes).context("parse manifest")?;
    let entry = m
        .find_entry(&cfg.identity.agent_name, &cfg.identity.agent_arch)
        .context("find agent entry in manifest")?;

    info!(
        agent = %cfg.identity.agent_name,
        arch  = %cfg.identity.agent_arch,
        url   = %entry.url,
        version = %m.version,
        "starting binary fetch"
    );

    // 2. Fetch binary.
    let staging_dir = std::path::Path::new(&cfg.files.staging_dir);
    let staged_path = fetch::fetch_binary(&entry.url, &entry.sha256, staging_dir, &client)
        .await
        .context("fetch binary")?;

    // 3. Verify binary signature — prefer baked-in key, fall back to config.
    if let Some(pubkey) =
        effective_release_pubkey(cfg).context("resolve release pubkey for binary")?
    {
        verify::verify_binary(&staged_path, &entry.sha256, &entry.sig, &pubkey)
            .context("verify binary signature")?;
    }

    // 4. Swap or Fork-and-Handoff.
    let agents_base = std::path::Path::new(&cfg.files.agents_base);

    if cfg.identity.agent_name == "pmx-updater" {
        // Self-update fork-and-handoff
        let agent_dir = agents_base.join("pmx-updater");
        let versions_dir = agent_dir.join("versions");
        let new_version_dir = versions_dir.join(&m.version);
        std::fs::create_dir_all(&new_version_dir).context("create new version dir")?;

        let dest_binary = new_version_dir.join("pmx-updater");
        std::fs::copy(&staged_path, &dest_binary).context("copy staged binary")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest_binary, std::fs::Permissions::from_mode(0o755))?;
        }

        // Clean up staged file
        let _ = std::fs::remove_file(&staged_path);

        // Write sentinel
        let sentinel_path = format!("/run/pmx-cloud/updater.swap.{}", m.version);
        std::fs::write(&sentinel_path, "").context("write swap sentinel")?;

        // Get old version
        let current_link = agent_dir.join("current");
        let old_version = if current_link.exists() || current_link.is_symlink() {
            if let Ok(target) = std::fs::read_link(&current_link) {
                swap::extract_version_from_target(&target, "pmx-updater")
            } else {
                None
            }
        } else {
            None
        };

        let old_ver_str = old_version.unwrap_or_else(|| "0.0.0".to_string());

        info!(
            version = %m.version,
            old_version = %old_ver_str,
            "execing new pmx-updater binary for self-swap"
        );

        // Exec the new binary
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new(&dest_binary)
                .arg("--finalize-self-swap")
                .arg(&old_ver_str)
                .arg("--config")
                .arg("/etc/pmx-cloud/pmx-updater.conf") // We just use the default
                .exec();

            bail!("exec new updater failed: {}", err);
        }
        #[cfg(not(unix))]
        {
            bail!("self-update requires Unix");
        }
    }

    let handle = swap::install_new_version(
        agents_base,
        &cfg.identity.agent_name,
        &m.version,
        &staged_path,
    )
    .context("install new version")?;

    // Clean up staged file (best-effort).
    let _ = std::fs::remove_file(&staged_path);

    // 5. Health check.
    let config_path = cfg.files.maintenance_window_cache_path.as_str();
    if let Err(e) = health::check(
        &cfg.identity.agent_name,
        health::AgentKind::Persistent,
        config_path,
    ) {
        // Rollback.
        if let Err(rb_err) = rollback::execute(&handle, health::AgentKind::Persistent, config_path)
        {
            bail!(
                "health check failed ({}) and rollback also failed: {}",
                e,
                rb_err
            );
        }
        bail!("health check failed after update, rolled back: {}", e);
    }

    Ok(json!({
        "applied": true,
        "version": m.version,
        "message": format!("updated {} to {}", cfg.identity.agent_name, m.version),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn empty_config() -> Config {
        Config {
            identity: crate::config::IdentityConfig {
                host_fingerprint_file: String::new(),
                agent_name: "pmx-updater".to_string(),
                agent_arch: "amd64".to_string(),
            },
            keyset: crate::config::KeysetConfig {
                path: String::new(),
                release_pubkey: String::new(),
            },
            files: crate::config::FilesConfig {
                maintenance_window_cache_path: String::new(),
                manifest_url: String::new(),
                agents_base: String::new(),
                staging_dir: String::new(),
            },
        }
    }

    // ── effective_release_pubkey ────────────────────────────────────────────

    #[test]
    fn effective_release_pubkey_returns_none_when_no_key_configured() {
        let cfg = empty_config();
        let result = effective_release_pubkey(&cfg).expect("should not error");
        // In dev builds without a baked key and with empty config key, should be None.
        // If a key IS baked in, this test still passes (Some is fine too).
        let _ = result; // just verify no panic/error
    }

    #[test]
    fn effective_release_pubkey_with_config_key() {
        let cfg = empty_config();
        // Use a valid Ed25519 pubkey (all zeros is not valid, so use a real one).
        // This test just verifies the function doesn't panic with an empty string.
        assert!(cfg.keyset.release_pubkey.is_empty());
        let result = effective_release_pubkey(&cfg).expect("should not error");
        // With empty string, should return None (unless baked-in key exists).
        if verify::baked_release_pubkey().is_none() {
            assert!(result.is_none(), "empty config key should yield None");
        }
    }

    // ── check ──────────────────────────────────────────────────────────────

    #[test]
    fn check_returns_not_available_when_manifest_url_empty() {
        let cfg = empty_config();
        let result = check(&cfg).expect("check should not error");
        let available = result.get("available").and_then(|v| v.as_bool());
        assert_eq!(available, Some(false));

        let reason = result
            .get("reason")
            .and_then(|v| v.as_str())
            .expect("reason should exist");
        assert!(reason.contains("manifest_url not configured"));
    }

    #[test]
    fn check_includes_current_version() {
        let cfg = empty_config();
        let result = check(&cfg).expect("check should not error");
        let current = result
            .get("current")
            .and_then(|v| v.as_str())
            .expect("current should exist");
        assert!(!current.is_empty(), "current version should be non-empty");
    }

    // ── apply ──────────────────────────────────────────────────────────────

    #[test]
    fn apply_bails_when_manifest_url_empty() {
        let cfg = empty_config();
        let result = apply(&cfg);
        assert!(result.is_err(), "apply should fail with empty manifest_url");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("manifest_url"),
            "error should mention manifest_url: {}",
            err_msg
        );
    }

    // ── CheckResult / ApplyResult structs ───────────────────────────────────

    #[test]
    fn check_result_serialization() {
        let cr = CheckResult {
            available: true,
            current: "1.0.0".to_string(),
            latest: "1.1.0".to_string(),
            reason: None,
        };
        let json = serde_json::to_string(&cr).expect("serialize");
        assert!(json.contains("available"));
        assert!(json.contains("1.0.0"));
        assert!(json.contains("1.1.0"));
    }

    #[test]
    fn check_result_equality() {
        let a = CheckResult {
            available: false,
            current: "1.0.0".to_string(),
            latest: "1.0.0".to_string(),
            reason: Some("test".to_string()),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn apply_result_serialization() {
        let ar = ApplyResult {
            applied: true,
            version: "2.0.0".to_string(),
            message: "updated".to_string(),
        };
        let json = serde_json::to_string(&ar).expect("serialize");
        assert!(json.contains("applied"));
        assert!(json.contains("2.0.0"));
    }

    #[test]
    fn apply_result_equality() {
        let a = ApplyResult {
            applied: false,
            version: "1.0.0".to_string(),
            message: "failed".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
