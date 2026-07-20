use crate::netlink::{is_safe_ifname, Runner};
use anyhow::{bail, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OvsCommand {
    AddBridge { bridge: String },
    DelBridge { bridge: String },
    AddPort { bridge: String, port: String },
    DelPort { bridge: String, port: String },
}

pub async fn install() -> Result<()> {
    bail!("OVS_INSTALL_REQUIRES_HARDWARE_INSTALLER: delegate to pmx-hardware-installer");
}

pub async fn configure(runner: &Runner, commands: &[OvsCommand]) -> Result<()> {
    for cmd in commands {
        match cmd {
            OvsCommand::AddBridge { bridge } => {
                if !is_safe_ifname(bridge) {
                    bail!("invalid ovs bridge name");
                }
                runner
                    .run_expect_ok("ovs-vsctl", &["--may-exist", "add-br", bridge])
                    .await?;
            }
            OvsCommand::DelBridge { bridge } => {
                if !is_safe_ifname(bridge) {
                    bail!("invalid ovs bridge name");
                }
                runner
                    .run_expect_ok("ovs-vsctl", &["--if-exists", "del-br", bridge])
                    .await?;
            }
            OvsCommand::AddPort { bridge, port } => {
                if !is_safe_ifname(bridge) || !is_safe_ifname(port) {
                    bail!("invalid ovs bridge/port name");
                }
                runner
                    .run_expect_ok("ovs-vsctl", &["--may-exist", "add-port", bridge, port])
                    .await?;
            }
            OvsCommand::DelPort { bridge, port } => {
                if !is_safe_ifname(bridge) || !is_safe_ifname(port) {
                    bail!("invalid ovs bridge/port name");
                }
                runner
                    .run_expect_ok("ovs-vsctl", &["--if-exists", "del-port", bridge, port])
                    .await?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── install always delegates ──────────────────────────────────────────────

    #[tokio::test]
    async fn install_always_errors_with_delegation_message() {
        let err = install().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("OVS_INSTALL_REQUIRES_HARDWARE_INSTALLER"),
            "{err}"
        );
    }

    // ── configure: validation for malformed names ────────────────────────────

    #[tokio::test]
    async fn configure_add_bridge_rejects_invalid_name() {
        let runner = Runner::new();
        let cmds = vec![OvsCommand::AddBridge {
            bridge: "br;evil".to_string(),
        }];
        let err = configure(&runner, &cmds).await.unwrap_err();
        assert!(err.to_string().contains("invalid ovs bridge name"), "{err}");
    }

    #[tokio::test]
    async fn configure_del_bridge_rejects_invalid_name() {
        let runner = Runner::new();
        let cmds = vec![OvsCommand::DelBridge {
            bridge: "br|evil".to_string(),
        }];
        let err = configure(&runner, &cmds).await.unwrap_err();
        assert!(err.to_string().contains("invalid ovs bridge name"), "{err}");
    }

    #[tokio::test]
    async fn configure_add_port_rejects_invalid_bridge() {
        let runner = Runner::new();
        let cmds = vec![OvsCommand::AddPort {
            bridge: "br;0".to_string(),
            port: "eth0".to_string(),
        }];
        let err = configure(&runner, &cmds).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid ovs bridge/port name"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn configure_add_port_rejects_invalid_port() {
        let runner = Runner::new();
        let cmds = vec![OvsCommand::AddPort {
            bridge: "br0".to_string(),
            port: "eth|0".to_string(),
        }];
        let err = configure(&runner, &cmds).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid ovs bridge/port name"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn configure_del_port_rejects_invalid_port() {
        let runner = Runner::new();
        let cmds = vec![OvsCommand::DelPort {
            bridge: "br0".to_string(),
            port: "/dev/null".to_string(),
        }];
        let err = configure(&runner, &cmds).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid ovs bridge/port name"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn configure_empty_command_list_succeeds() {
        let runner = Runner::new();
        configure(&runner, &[]).await.unwrap();
    }

    // ── additional edge cases ──────────────────────────────────────────────────

    #[tokio::test]
    async fn configure_add_bridge_rejects_empty_name() {
        let runner = Runner::new();
        let cmds = vec![OvsCommand::AddBridge {
            bridge: "".to_string(),
        }];
        let err = configure(&runner, &cmds).await.unwrap_err();
        assert!(err.to_string().contains("invalid ovs bridge name"), "{err}");
    }

    #[tokio::test]
    async fn configure_add_bridge_rejects_dotdot_name() {
        let runner = Runner::new();
        let cmds = vec![OvsCommand::AddBridge {
            bridge: "br..evil".to_string(),
        }];
        let err = configure(&runner, &cmds).await.unwrap_err();
        assert!(err.to_string().contains("invalid ovs bridge name"), "{err}");
    }

    #[tokio::test]
    async fn configure_del_bridge_rejects_dotdot_name() {
        let runner = Runner::new();
        let cmds = vec![OvsCommand::DelBridge {
            bridge: "br..evil".to_string(),
        }];
        let err = configure(&runner, &cmds).await.unwrap_err();
        assert!(err.to_string().contains("invalid ovs bridge name"), "{err}");
    }

    #[tokio::test]
    async fn configure_add_port_rejects_backtick_bridge() {
        let runner = Runner::new();
        let cmds = vec![OvsCommand::AddPort {
            bridge: "br`id`".to_string(),
            port: "eth0".to_string(),
        }];
        let err = configure(&runner, &cmds).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid ovs bridge/port name"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn configure_del_port_rejects_backtick_port() {
        let runner = Runner::new();
        let cmds = vec![OvsCommand::DelPort {
            bridge: "br0".to_string(),
            port: "eth`whoami`".to_string(),
        }];
        let err = configure(&runner, &cmds).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid ovs bridge/port name"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn configure_add_port_rejects_whitespace_port() {
        let runner = Runner::new();
        let cmds = vec![OvsCommand::AddPort {
            bridge: "br0".to_string(),
            port: "eth 0".to_string(),
        }];
        let err = configure(&runner, &cmds).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid ovs bridge/port name"),
            "{err}"
        );
    }

    // ── serde deserialization ──────────────────────────────────────────────────

    #[test]
    fn deserialize_add_bridge() {
        let json = r#"{"kind":"add_bridge","bridge":"ovs-br0"}"#;
        let cmd: OvsCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, OvsCommand::AddBridge { .. }));
    }

    #[test]
    fn deserialize_del_bridge() {
        let json = r#"{"kind":"del_bridge","bridge":"ovs-br0"}"#;
        let cmd: OvsCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, OvsCommand::DelBridge { .. }));
    }

    #[test]
    fn deserialize_add_port() {
        let json = r#"{"kind":"add_port","bridge":"ovs-br0","port":"eth0"}"#;
        let cmd: OvsCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, OvsCommand::AddPort { .. }));
    }

    #[test]
    fn deserialize_del_port() {
        let json = r#"{"kind":"del_port","bridge":"ovs-br0","port":"eth0"}"#;
        let cmd: OvsCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, OvsCommand::DelPort { .. }));
    }

    #[test]
    fn deserialize_rejects_unknown_kind() {
        let json = r#"{"kind":"explode","bridge":"ovs-br0"}"#;
        assert!(serde_json::from_str::<OvsCommand>(json).is_err());
    }
}
