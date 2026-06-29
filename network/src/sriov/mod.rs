use anyhow::{bail, Context, Result};
use std::fs;

pub fn configure_numvfs(pf: &str, num_vfs: u16) -> Result<()> {
    if pf.trim().is_empty() || pf.contains("..") || pf.contains('/') {
        bail!("invalid PF interface name");
    }
    let path = format!("/sys/class/net/{}/device/sriov_numvfs", pf);
    match fs::write(&path, num_vfs.to_string()) {
        Ok(()) => Ok(()),
        Err(e) => {
            if matches!(e.kind(), std::io::ErrorKind::PermissionDenied) {
                bail!("KERNEL_REFUSED: cannot write {}", path);
            }
            Err(e).with_context(|| format!("configure sriov vf count at {}", path))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── PF name validation (does NOT write to filesystem) ────────────────────

    #[test]
    fn rejects_empty_pf_name() {
        let err = configure_numvfs("", 4).unwrap_err();
        assert!(
            err.to_string().contains("invalid PF interface name"),
            "{err}"
        );
    }

    #[test]
    fn rejects_whitespace_only_pf_name() {
        let err = configure_numvfs("   ", 4).unwrap_err();
        assert!(
            err.to_string().contains("invalid PF interface name"),
            "{err}"
        );
    }

    #[test]
    fn rejects_path_traversal_in_pf_name() {
        let err = configure_numvfs("../../etc/passwd", 4).unwrap_err();
        assert!(
            err.to_string().contains("invalid PF interface name"),
            "{err}"
        );
    }

    #[test]
    fn rejects_slash_in_pf_name() {
        let err = configure_numvfs("eth/0", 4).unwrap_err();
        assert!(
            err.to_string().contains("invalid PF interface name"),
            "{err}"
        );
    }

    #[test]
    fn rejects_dotdot_in_pf_name() {
        let err = configure_numvfs("eth..0", 4).unwrap_err();
        assert!(
            err.to_string().contains("invalid PF interface name"),
            "{err}"
        );
    }

    #[test]
    fn valid_pf_name_passes_validation_step() {
        // We expect the call to fail at the fs::write level (not in validation)
        // because /sys/class/net/eth99_test_fake does not exist. The error must
        // NOT be "invalid PF interface name".
        let err = configure_numvfs("eth99_test_fake", 4).unwrap_err();
        assert!(
            !err.to_string().contains("invalid PF interface name"),
            "should not fail at name validation: {err}"
        );
    }
}
