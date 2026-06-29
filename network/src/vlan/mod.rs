use crate::netlink::{is_safe_ifname, Runner};
use anyhow::{bail, Result};

pub async fn create(runner: &Runner, parent: &str, name: &str, vid: u16) -> Result<()> {
    if !is_safe_ifname(parent) || !is_safe_ifname(name) {
        bail!("invalid parent/name");
    }
    if vid == 0 || vid > 4094 {
        bail!("invalid vlan id {}", vid);
    }
    let id = vid.to_string();
    runner
        .run_expect_ok(
            "ip",
            &[
                "link", "add", "link", parent, "name", name, "type", "vlan", "id", &id,
            ],
        )
        .await?;
    runner
        .run_expect_ok("ip", &["link", "set", "dev", name, "up"])
        .await?;
    Ok(())
}

pub async fn destroy(runner: &Runner, name: &str) -> Result<()> {
    if !is_safe_ifname(name) {
        bail!("invalid vlan interface name");
    }
    runner
        .run_expect_ok("ip", &["link", "delete", "dev", name])
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── VLAN ID bounds validation ─────────────────────────────────────────────

    #[tokio::test]
    async fn create_rejects_vid_zero() {
        let runner = Runner::new();
        let err = create(&runner, "eth0", "eth0.0", 0).await.unwrap_err();
        assert!(err.to_string().contains("invalid vlan id"), "{err}");
    }

    #[tokio::test]
    async fn create_rejects_vid_above_4094() {
        let runner = Runner::new();
        let err = create(&runner, "eth0", "eth0.4095", 4095)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid vlan id"), "{err}");
    }

    // ── interface name validation ─────────────────────────────────────────────

    #[tokio::test]
    async fn create_rejects_invalid_parent_name() {
        let runner = Runner::new();
        let err = create(&runner, "eth;0", "eth0.100", 100).await.unwrap_err();
        assert!(err.to_string().contains("invalid parent/name"), "{err}");
    }

    #[tokio::test]
    async fn create_rejects_invalid_vlan_name() {
        let runner = Runner::new();
        let err = create(&runner, "eth0", "eth|100", 100).await.unwrap_err();
        assert!(err.to_string().contains("invalid parent/name"), "{err}");
    }

    #[tokio::test]
    async fn create_rejects_slash_prefix_parent() {
        let runner = Runner::new();
        let err = create(&runner, "/eth0", "eth0.100", 100).await.unwrap_err();
        assert!(err.to_string().contains("invalid parent/name"), "{err}");
    }

    #[tokio::test]
    async fn destroy_rejects_invalid_name() {
        let runner = Runner::new();
        let err = destroy(&runner, "eth;100").await.unwrap_err();
        assert!(
            err.to_string().contains("invalid vlan interface name"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn destroy_rejects_empty_name() {
        let runner = Runner::new();
        let err = destroy(&runner, "").await.unwrap_err();
        assert!(
            err.to_string().contains("invalid vlan interface name"),
            "{err}"
        );
    }

    // ── additional edge cases ──────────────────────────────────────────────────

    #[tokio::test]
    async fn create_rejects_dotdot_parent() {
        let runner = Runner::new();
        let err = create(&runner, "eth..0", "vlan100", 100)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid parent/name"), "{err}");
    }

    #[tokio::test]
    async fn create_rejects_dotdot_vlan_name() {
        let runner = Runner::new();
        let err = create(&runner, "eth0", "vlan..100", 100)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid parent/name"), "{err}");
    }

    #[tokio::test]
    async fn create_rejects_backtick_parent() {
        let runner = Runner::new();
        let err = create(&runner, "eth`id`", "vlan100", 100)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid parent/name"), "{err}");
    }

    #[tokio::test]
    async fn create_rejects_whitespace_parent() {
        let runner = Runner::new();
        let err = create(&runner, "eth 0", "vlan100", 100)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid parent/name"), "{err}");
    }

    #[tokio::test]
    async fn create_accepts_valid_vid_1() {
        let runner = Runner::new();
        // vid=1 is valid but will fail at exec (no real iface) — just test validation passes
        let result = create(&runner, "eth0", "eth0.1", 1).await;
        // Validation passes, but exec fails since there's no real interface
        assert!(
            result.is_err() == false || !result.unwrap_err().to_string().contains("invalid"),
            "vid=1 should pass validation"
        );
    }

    #[tokio::test]
    async fn create_accepts_valid_vid_4094() {
        let runner = Runner::new();
        let result = create(&runner, "eth0", "eth0.4094", 4094).await;
        // Validation passes, but exec fails since there's no real interface
        assert!(
            result.is_err() == false || !result.unwrap_err().to_string().contains("invalid vlan id"),
            "vid=4094 should pass validation"
        );
    }

    #[tokio::test]
    async fn destroy_rejects_backtick_name() {
        let runner = Runner::new();
        let err = destroy(&runner, "eth`id`").await.unwrap_err();
        assert!(
            err.to_string().contains("invalid vlan interface name"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn destroy_rejects_dotdot_name() {
        let runner = Runner::new();
        let err = destroy(&runner, "eth..0").await.unwrap_err();
        assert!(
            err.to_string().contains("invalid vlan interface name"),
            "{err}"
        );
    }
}
