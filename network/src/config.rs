use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub backend: Backend,
    pub identity: Identity,
    pub keyset: Keyset,
    pub wireguard: WireGuard,
    pub nftables: Nftables,
    pub isolation: Isolation,
    #[serde(default)]
    pub state: State,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Backend {
    pub url: String,
    #[serde(default)]
    pub auth_token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Identity {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Keyset {
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WireGuard {
    pub key_file: String,
    pub listen_port_range: [u16; 2],
    pub max_peers_per_host: usize,
    #[serde(default = "default_iface")]
    pub interface: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Nftables {
    pub ruleset_dir: String,
    pub max_rules_per_host: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Isolation {
    pub default_drop_input: bool,
    #[serde(default)]
    pub allow_ssh_from: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct State {
    #[serde(default = "default_state_dir")]
    pub dir: String,
}

impl Default for State {
    fn default() -> Self {
        Self {
            dir: default_state_dir(),
        }
    }
}

fn default_iface() -> String {
    "pmxwg0".to_string()
}

fn default_state_dir() -> String {
    "/var/lib/pmx-cloud/network".to_string()
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path).with_context(|| format!("read config {}", path))?;
        let cfg: Config = toml::from_str(&raw).with_context(|| "parse toml config")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if !self.backend.url.starts_with("wss://") && !self.backend.url.starts_with("ws://") {
            bail!("backend.url must start with wss:// or ws://");
        }
        // mTLS identity (cert/key) is only required when not using token auth.
        // With backend.auth_token set, the wsclient authenticates via Bearer and
        // skips client certs, so empty cert/key is valid (token-only deployment).
        if self.backend.auth_token.trim().is_empty()
            && (self.identity.cert.trim().is_empty() || self.identity.key.trim().is_empty())
        {
            bail!("identity.cert and identity.key are required when backend.auth_token is unset");
        }
        if self.keyset.path.trim().is_empty() {
            bail!("keyset.path is required");
        }
        if self.wireguard.listen_port_range[0] == 0 || self.wireguard.listen_port_range[1] == 0 {
            bail!("wireguard.listen_port_range values must be non-zero");
        }
        if self.wireguard.listen_port_range[0] > self.wireguard.listen_port_range[1] {
            bail!("wireguard.listen_port_range must be [min,max] with min <= max");
        }
        if self.wireguard.max_peers_per_host == 0 {
            bail!("wireguard.max_peers_per_host must be > 0");
        }
        if self.nftables.max_rules_per_host == 0 {
            bail!("nftables.max_rules_per_host must be > 0");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> Config {
        Config {
            backend: Backend {
                url: "wss://example.com/ws".to_string(),
                auth_token: String::new(),
            },
            identity: Identity {
                cert: "cert.pem".to_string(),
                key: "key.pem".to_string(),
            },
            keyset: Keyset {
                path: "/etc/pmx/keyset.json".to_string(),
            },
            wireguard: WireGuard {
                key_file: "/etc/pmx/wg.key".to_string(),
                listen_port_range: [51820, 51830],
                max_peers_per_host: 256,
                interface: "pmxwg0".to_string(),
            },
            nftables: Nftables {
                ruleset_dir: "/etc/nftables.d/pmx".to_string(),
                max_rules_per_host: 10_000,
            },
            isolation: Isolation {
                default_drop_input: true,
                allow_ssh_from: vec![],
            },
            state: State::default(),
        }
    }

    #[test]
    fn reject_non_wss() {
        let mut cfg = valid_config();
        cfg.backend.url = "https://example".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn valid_config_passes_validation() {
        assert!(valid_config().validate().is_ok());
    }

    #[test]
    fn reject_empty_identity_cert() {
        let mut cfg = valid_config();
        cfg.identity.cert = "".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn reject_empty_identity_key() {
        let mut cfg = valid_config();
        cfg.identity.key = "  ".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn reject_empty_keyset_path() {
        let mut cfg = valid_config();
        cfg.keyset.path = "".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn reject_zero_listen_port_range_min() {
        let mut cfg = valid_config();
        cfg.wireguard.listen_port_range = [0, 51830];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn reject_zero_listen_port_range_max() {
        let mut cfg = valid_config();
        cfg.wireguard.listen_port_range = [51820, 0];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn reject_inverted_port_range() {
        let mut cfg = valid_config();
        cfg.wireguard.listen_port_range = [51830, 51820];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn reject_zero_max_peers() {
        let mut cfg = valid_config();
        cfg.wireguard.max_peers_per_host = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn reject_zero_max_rules() {
        let mut cfg = valid_config();
        cfg.nftables.max_rules_per_host = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn state_default_has_expected_dir() {
        let s = State::default();
        assert_eq!(s.dir, "/var/lib/pmx-cloud/network");
    }

    #[test]
    fn load_returns_error_for_missing_file() {
        let err = Config::load("/nonexistent/path/config.toml").unwrap_err();
        assert!(err.to_string().contains("read config"), "{err}");
    }
}
