use crate::netlink::{is_safe_ifname, Runner};
use anyhow::{bail, Result};

pub async fn create(runner: &Runner, bridge: &str) -> Result<()> {
    if !is_safe_ifname(bridge) {
        bail!("invalid bridge name");
    }
    runner
        .run_expect_ok("ip", &["link", "add", "name", bridge, "type", "bridge"])
        .await?;
    runner
        .run_expect_ok("ip", &["link", "set", "dev", bridge, "up"])
        .await?;
    Ok(())
}

pub async fn destroy(runner: &Runner, bridge: &str) -> Result<()> {
    if !is_safe_ifname(bridge) {
        bail!("invalid bridge name");
    }

    let ports = runner
        .run("ip", &["-j", "link", "show", "master", bridge])
        .await?;
    if ports.status == 0 && !ports.stdout.trim().is_empty() && ports.stdout.trim() != "[]" {
        bail!("BRIDGE_IN_USE: {} still has member ports", bridge);
    }

    runner
        .run_expect_ok("ip", &["link", "delete", "dev", bridge, "type", "bridge"])
        .await?;
    Ok(())
}

pub async fn port_add(runner: &Runner, bridge: &str, port: &str) -> Result<()> {
    if !is_safe_ifname(bridge) || !is_safe_ifname(port) {
        bail!("invalid bridge/port name");
    }
    runner
        .run_expect_ok("ip", &["link", "set", "dev", port, "master", bridge])
        .await?;
    runner
        .run_expect_ok("ip", &["link", "set", "dev", port, "up"])
        .await?;
    Ok(())
}

pub async fn port_remove(runner: &Runner, port: &str) -> Result<()> {
    if !is_safe_ifname(port) {
        bail!("invalid port name");
    }
    runner
        .run_expect_ok("ip", &["link", "set", "dev", port, "nomaster"])
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validation: rejects malformed interface names ────────────────────────

    #[tokio::test]
    async fn create_rejects_invalid_bridge_name() {
        let runner = Runner::new();
        // Shell metachar in name — must be rejected before any exec
        let err = create(&runner, "br;0").await.unwrap_err();
        assert!(err.to_string().contains("invalid bridge name"), "{err}");
    }

    #[tokio::test]
    async fn create_rejects_empty_bridge_name() {
        let runner = Runner::new();
        let err = create(&runner, "").await.unwrap_err();
        assert!(err.to_string().contains("invalid bridge name"), "{err}");
    }

    #[tokio::test]
    async fn create_rejects_slash_prefix() {
        let runner = Runner::new();
        let err = create(&runner, "/etc/br0").await.unwrap_err();
        assert!(err.to_string().contains("invalid bridge name"), "{err}");
    }

    #[tokio::test]
    async fn destroy_rejects_invalid_bridge_name() {
        let runner = Runner::new();
        let err = destroy(&runner, "br|evil").await.unwrap_err();
        assert!(err.to_string().contains("invalid bridge name"), "{err}");
    }

    #[tokio::test]
    async fn port_add_rejects_invalid_port_name() {
        let runner = Runner::new();
        let err = port_add(&runner, "br0", "eth;0").await.unwrap_err();
        assert!(
            err.to_string().contains("invalid bridge/port name"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn port_add_rejects_invalid_bridge_name() {
        let runner = Runner::new();
        let err = port_add(&runner, "br;0", "eth0").await.unwrap_err();
        assert!(
            err.to_string().contains("invalid bridge/port name"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn port_remove_rejects_invalid_port_name() {
        let runner = Runner::new();
        let err = port_remove(&runner, "eth|0").await.unwrap_err();
        assert!(err.to_string().contains("invalid port name"), "{err}");
    }

    // ── additional validation edge cases ──────────────────────────────────────

    #[tokio::test]
    async fn create_rejects_dotdot_in_name() {
        let runner = Runner::new();
        let err = create(&runner, "br..evil").await.unwrap_err();
        assert!(err.to_string().contains("invalid bridge name"), "{err}");
    }

    #[tokio::test]
    async fn create_rejects_whitespace_in_name() {
        let runner = Runner::new();
        let err = create(&runner, "br 0").await.unwrap_err();
        assert!(err.to_string().contains("invalid bridge name"), "{err}");
    }

    #[tokio::test]
    async fn destroy_rejects_dotdot_in_name() {
        let runner = Runner::new();
        let err = destroy(&runner, "br..evil").await.unwrap_err();
        assert!(err.to_string().contains("invalid bridge name"), "{err}");
    }

    #[tokio::test]
    async fn port_add_rejects_dotdot_port() {
        let runner = Runner::new();
        let err = port_add(&runner, "br0", "eth..0").await.unwrap_err();
        assert!(
            err.to_string().contains("invalid bridge/port name"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn port_remove_rejects_dotdot_port() {
        let runner = Runner::new();
        let err = port_remove(&runner, "eth..0").await.unwrap_err();
        assert!(err.to_string().contains("invalid port name"), "{err}");
    }

    #[tokio::test]
    async fn create_rejects_backtick_in_name() {
        let runner = Runner::new();
        let err = create(&runner, "br`whoami`").await.unwrap_err();
        assert!(err.to_string().contains("invalid bridge name"), "{err}");
    }

    #[tokio::test]
    async fn port_add_rejects_backtick_in_bridge() {
        let runner = Runner::new();
        let err = port_add(&runner, "br`id`", "eth0").await.unwrap_err();
        assert!(
            err.to_string().contains("invalid bridge/port name"),
            "{err}"
        );
    }
}
