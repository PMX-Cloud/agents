use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub identity: IdentityConfig,
    pub keyset: KeysetConfig,
    pub files: FilesConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    pub host_fingerprint_file: String,
    #[serde(default = "default_agent_name")]
    pub agent_name: String,
    #[serde(default = "default_agent_arch")]
    pub agent_arch: String,
}

fn default_agent_name() -> String {
    "pmx-updater".to_string()
}

fn default_agent_arch() -> String {
    std::env::consts::ARCH.to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeysetConfig {
    pub path: String,
    /// Hex-encoded Ed25519 public key used for manifest and binary signature verification.
    #[serde(default)]
    pub release_pubkey: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FilesConfig {
    pub maintenance_window_cache_path: String,
    #[serde(default)]
    pub manifest_url: String,
    #[serde(default = "default_agents_base")]
    pub agents_base: String,
    #[serde(default = "default_staging_dir")]
    pub staging_dir: String,
}

fn default_agents_base() -> String {
    "/opt/pmx-cloud/agents".to_string()
}

fn default_staging_dir() -> String {
    "/var/lib/pmx-cloud/updater/staging".to_string()
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path).with_context(|| format!("read config {}", path))?;
        let cfg: Self = toml::from_str(&raw).with_context(|| format!("parse config {}", path))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.identity.host_fingerprint_file,
            &self.keyset.path,
            &self.files.maintenance_window_cache_path,
        ] {
            if value.trim().is_empty() {
                bail!("config contains empty required path");
            }
            if !Path::new(value).is_absolute() {
                bail!("config path must be absolute: {}", value);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn parse_config() {
        let raw = r#"
[identity]
host_fingerprint_file = "/etc/pmx-cloud/host-fingerprint"

[keyset]
path = "/etc/pmx-cloud/keyset.pub"

[files]
maintenance_window_cache_path = "/var/lib/pmx-cloud/updater/window.json"
"#;
        let cfg: Config = toml::from_str(raw).expect("parse config");
        cfg.validate().expect("validate config");
    }

    #[test]
    fn validate_rejects_empty_path() {
        let raw = r#"
[identity]
host_fingerprint_file = ""

[keyset]
path = "/etc/pmx-cloud/keyset.pub"

[files]
maintenance_window_cache_path = "/var/lib/pmx-cloud/updater/window.json"
"#;
        let cfg: Config = toml::from_str(raw).expect("parse config");
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("empty required path"));
    }

    #[test]
    fn validate_rejects_relative_path() {
        let raw = r#"
[identity]
host_fingerprint_file = "not-absolute"

[keyset]
path = "/etc/pmx-cloud/keyset.pub"

[files]
maintenance_window_cache_path = "/var/lib/pmx-cloud/updater/window.json"
"#;
        let cfg: Config = toml::from_str(raw).expect("parse config");
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("must be absolute"));
    }

    #[test]
    fn load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.conf");
        let raw = r#"
[identity]
host_fingerprint_file = "/etc/pmx-cloud/host-fingerprint"

[keyset]
path = "/etc/pmx-cloud/keyset.pub"

[files]
maintenance_window_cache_path = "/var/lib/pmx-cloud/updater/window.json"
"#;
        std::fs::write(&path, raw).unwrap();
        let cfg = Config::load(path.to_str().unwrap()).expect("load config from file");
        assert_eq!(
            cfg.identity.host_fingerprint_file,
            "/etc/pmx-cloud/host-fingerprint"
        );
    }

    #[test]
    fn load_nonexistent_file_errors() {
        let err = Config::load("/tmp/no-such-config-file-xyz.conf").unwrap_err();
        assert!(err.to_string().contains("config") || err.to_string().contains("read"));
    }

    #[test]
    fn load_malformed_toml_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.conf");
        std::fs::write(&path, "this is not valid toml [[[[").unwrap();
        let err = Config::load(path.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("parse"));
    }

    #[test]
    fn defaults_fill_correctly() {
        let raw = r#"
[identity]
host_fingerprint_file = "/etc/pmx-cloud/host-fingerprint"

[keyset]
path = "/etc/pmx-cloud/keyset.pub"

[files]
maintenance_window_cache_path = "/var/lib/pmx-cloud/updater/window.json"
"#;
        let cfg: Config = toml::from_str(raw).expect("parse config");
        assert_eq!(cfg.identity.agent_name, "pmx-updater");
        assert_eq!(cfg.files.agents_base, "/opt/pmx-cloud/agents");
        assert_eq!(cfg.files.staging_dir, "/var/lib/pmx-cloud/updater/staging");
        assert_eq!(cfg.keyset.release_pubkey, "");
        assert_eq!(cfg.files.manifest_url, "");
    }
}
