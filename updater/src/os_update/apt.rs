use crate::os_update::{ApplyMode, ApplyResult, PackageInfo, ScanResult};
use anyhow::Result;

pub fn scan() -> Result<ScanResult> {
    Ok(ScanResult { packages: Vec::new() })
}

pub fn apply(mode: ApplyMode, packages: Vec<PackageInfo>) -> Result<ApplyResult> {
    let mode = match mode {
        ApplyMode::Security => "security",
        ApplyMode::Full => "full",
        ApplyMode::DryRun => "dry_run",
    };
    Ok(ApplyResult {
        mode: mode.to_string(),
        reboot_required: false,
        packages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_returns_empty_packages() {
        let result = scan().expect("scan should succeed");
        assert!(result.packages.is_empty(), "scan should return empty packages list");
    }

    #[test]
    fn apply_security_mode() {
        let result = apply(ApplyMode::Security, vec![]).expect("apply security should succeed");
        assert_eq!(result.mode, "security");
        assert!(!result.reboot_required);
        assert!(result.packages.is_empty());
    }

    #[test]
    fn apply_full_mode() {
        let result = apply(ApplyMode::Full, vec![]).expect("apply full should succeed");
        assert_eq!(result.mode, "full");
        assert!(!result.reboot_required);
    }

    #[test]
    fn apply_dry_run_mode() {
        let result = apply(ApplyMode::DryRun, vec![]).expect("apply dry_run should succeed");
        assert_eq!(result.mode, "dry_run");
        assert!(!result.reboot_required);
    }

    #[test]
    fn apply_preserves_packages() {
        let pkgs = vec![
            PackageInfo {
                name: "libc6".to_string(),
                installed_version: "2.38".to_string(),
                candidate_version: "2.39".to_string(),
                security: true,
            },
            PackageInfo {
                name: "curl".to_string(),
                installed_version: "8.3.0".to_string(),
                candidate_version: "8.4.0".to_string(),
                security: false,
            },
        ];
        let result = apply(ApplyMode::Security, pkgs.clone()).expect("apply should succeed");
        assert_eq!(result.packages.len(), 2);
        assert_eq!(result.packages[0].name, "libc6");
        assert_eq!(result.packages[1].name, "curl");
    }
}
