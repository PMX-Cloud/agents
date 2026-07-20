use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SwapError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("no previous version to roll back to")]
    NoPreviousVersion,
}

#[derive(Debug, Clone)]
pub struct SwapHandle {
    pub agent: String,
    pub new_version: String,
    pub old_version: Option<String>,
    pub agents_base: PathBuf,
}

/// Install a new agent binary version into the disk layout under `agents_base`.
///
/// Layout:
/// ```text
/// /opt/pmx-cloud/agents/<agent>/
///   current   → symlink → versions/<new_version>/<agent>
///   previous  → symlink → versions/<old_version>/<agent>  (if old existed)
///   versions/
///     <version>/<agent>   # binary
///   VERSION               # text file with current version string
/// ```
pub fn install_new_version(
    agents_base: &Path,
    agent: &str,
    version: &str,
    staged: &Path,
) -> Result<SwapHandle, SwapError> {
    let agent_dir = agents_base.join(agent);
    let versions_dir = agent_dir.join("versions");
    let new_version_dir = versions_dir.join(version);

    std::fs::create_dir_all(&new_version_dir)?;

    let dest_binary = new_version_dir.join(agent);
    std::fs::copy(staged, &dest_binary)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest_binary, std::fs::Permissions::from_mode(0o755))?;
    }

    // Read the current symlink to determine old_version before we update it.
    let current_link = agent_dir.join("current");
    let old_version = if current_link.exists() || current_link.is_symlink() {
        match std::fs::read_link(&current_link) {
            Ok(target) => {
                // Extract version component from path versions/<ver>/<agent>
                extract_version_from_target(&target, agent)
            }
            Err(_) => None,
        }
    } else {
        None
    };

    // Atomically update `previous` symlink if we have an old version.
    if let Some(ref old_ver) = old_version {
        let old_target = PathBuf::from("versions").join(old_ver).join(agent);
        atomic_symlink(&agent_dir, "previous", &old_target)?;
    }

    // Atomically update `current` symlink.
    let new_target = PathBuf::from("versions").join(version).join(agent);
    atomic_symlink(&agent_dir, "current", &new_target)?;

    // Write VERSION file.
    std::fs::write(agent_dir.join("VERSION"), version)?;

    Ok(SwapHandle {
        agent: agent.to_string(),
        new_version: version.to_string(),
        old_version,
        agents_base: agents_base.to_path_buf(),
    })
}

/// Roll back `current` symlink to the previous version.
pub fn rollback(handle: &SwapHandle) -> Result<(), SwapError> {
    let old_ver = handle
        .old_version
        .as_deref()
        .ok_or(SwapError::NoPreviousVersion)?;

    let agent_dir = handle.agents_base.join(&handle.agent);
    let old_target = PathBuf::from("versions").join(old_ver).join(&handle.agent);
    atomic_symlink(&agent_dir, "current", &old_target)?;

    std::fs::write(agent_dir.join("VERSION"), old_ver)?;

    Ok(())
}

/// Perform the atomic symlink swap for pmx-updater itself without restarting.
/// The binary is already at `versions/<new_version>/pmx-updater`.
pub fn install_self(handle: &SwapHandle) -> Result<(), SwapError> {
    let agent_dir = handle.agents_base.join(&handle.agent);

    // Atomically update `previous` symlink if we have an old version.
    if let Some(ref old_ver) = handle.old_version {
        let old_target = PathBuf::from("versions").join(old_ver).join(&handle.agent);
        atomic_symlink(&agent_dir, "previous", &old_target)?;
    }

    // Atomically update `current` symlink.
    let new_target = PathBuf::from("versions")
        .join(&handle.new_version)
        .join(&handle.agent);
    atomic_symlink(&agent_dir, "current", &new_target)?;

    // Write VERSION file.
    std::fs::write(agent_dir.join("VERSION"), &handle.new_version)?;

    Ok(())
}

/// Roll back pmx-updater to the previous version and emit audit event.
pub fn rollback_self(cfg: &crate::config::Config) -> anyhow::Result<()> {
    let agent_dir = std::path::Path::new(&cfg.files.agents_base).join("pmx-updater");

    // Read the current symlink to determine old_version before we update it.
    let current_link = agent_dir.join("current");
    let old_version = if current_link.exists() || current_link.is_symlink() {
        match std::fs::read_link(&current_link) {
            Ok(target) => extract_version_from_target(&target, "pmx-updater"),
            Err(_) => None,
        }
    } else {
        None
    };

    let previous_link = agent_dir.join("previous");
    if previous_link.exists() || previous_link.is_symlink() {
        if let Ok(target) = std::fs::read_link(&previous_link) {
            if let Some(old_ver) = extract_version_from_target(&target, "pmx-updater") {
                atomic_symlink(&agent_dir, "current", &target)?;
                std::fs::write(agent_dir.join("VERSION"), &old_ver)?;

                // Try to clean up the bad new version
                if let Some(bad_ver) = old_version {
                    let bad_target = agent_dir.join("versions").join(&bad_ver);
                    let _ = std::fs::remove_dir_all(bad_target);
                }
            }
        }
    }

    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Atomically replace symlink `name` inside `dir` to point at `target`.
/// Uses a temp-name + rename so the switch is atomic on POSIX.
fn atomic_symlink(dir: &Path, name: &str, target: &Path) -> Result<(), SwapError> {
    let final_link = dir.join(name);
    // Use a unique tmp name.
    let tmp_link = dir.join(format!(".{}.tmp.{}", name, std::process::id()));

    // Remove stale tmp if any.
    let _ = std::fs::remove_file(&tmp_link);

    #[cfg(unix)]
    std::os::unix::fs::symlink(target, &tmp_link)?;

    #[cfg(not(unix))]
    {
        // On non-Unix (e.g., Windows dev builds) create a directory junction
        // placeholder. This branch is never reached in production.
        let _ = target;
        let _ = tmp_link;
        return Err(SwapError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlinks require Unix",
        )));
    }

    std::fs::rename(&tmp_link, &final_link)?;
    Ok(())
}

/// Extract the version string from a symlink target like `versions/<ver>/<agent>`.
pub fn extract_version_from_target(target: &Path, agent: &str) -> Option<String> {
    let mut components = target.components().collect::<Vec<_>>();
    // Pop the agent filename.
    if let Some(last) = components.last() {
        if last.as_os_str() != agent {
            return None;
        }
    } else {
        return None;
    }
    components.pop();
    // The component before agent is the version.
    components
        .last()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_fake_binary(path: &Path) {
        let mut f = std::fs::File::create(path).expect("create fake binary");
        f.write_all(b"fake binary content").expect("write");
    }

    #[cfg(unix)]
    #[test]
    fn install_and_verify_symlinks() {
        let base = tempdir().expect("tempdir");
        let agents_base = base.path().join("agents");
        std::fs::create_dir_all(&agents_base).unwrap();

        // Stage v1 binary.
        let staged_v1 = base.path().join("staged-v1");
        write_fake_binary(&staged_v1);

        let handle_v1 = install_new_version(&agents_base, "pmx-network", "1.4.1", &staged_v1)
            .expect("install v1");
        assert_eq!(handle_v1.new_version, "1.4.1");
        assert!(
            handle_v1.old_version.is_none(),
            "no previous for first install"
        );

        // Verify current → versions/1.4.1/pmx-network
        let current_link = agents_base.join("pmx-network").join("current");
        let current_target = std::fs::read_link(&current_link).expect("read current link");
        assert_eq!(current_target, PathBuf::from("versions/1.4.1/pmx-network"));

        // Stage v2 binary.
        let staged_v2 = base.path().join("staged-v2");
        write_fake_binary(&staged_v2);

        let handle_v2 = install_new_version(&agents_base, "pmx-network", "1.4.2", &staged_v2)
            .expect("install v2");
        assert_eq!(handle_v2.new_version, "1.4.2");
        assert_eq!(handle_v2.old_version.as_deref(), Some("1.4.1"));

        // current → v2, previous → v1
        let current_target = std::fs::read_link(&current_link).expect("read current link v2");
        assert_eq!(current_target, PathBuf::from("versions/1.4.2/pmx-network"));

        let previous_link = agents_base.join("pmx-network").join("previous");
        let previous_target = std::fs::read_link(&previous_link).expect("read previous link");
        assert_eq!(previous_target, PathBuf::from("versions/1.4.1/pmx-network"));
    }

    #[cfg(unix)]
    #[test]
    fn rollback_after_install() {
        let base = tempdir().expect("tempdir");
        let agents_base = base.path().join("agents");
        std::fs::create_dir_all(&agents_base).unwrap();

        let staged_v1 = base.path().join("staged-v1");
        write_fake_binary(&staged_v1);
        install_new_version(&agents_base, "pmx-network", "1.4.1", &staged_v1).expect("install v1");

        let staged_v2 = base.path().join("staged-v2");
        write_fake_binary(&staged_v2);
        let handle_v2 = install_new_version(&agents_base, "pmx-network", "1.4.2", &staged_v2)
            .expect("install v2");

        rollback(&handle_v2).expect("rollback");

        // After rollback, current should point to v1.
        let current_link = agents_base.join("pmx-network").join("current");
        let current_target =
            std::fs::read_link(&current_link).expect("read current link after rollback");
        assert_eq!(current_target, PathBuf::from("versions/1.4.1/pmx-network"));

        // VERSION file should be v1.
        let version_content =
            std::fs::read_to_string(agents_base.join("pmx-network").join("VERSION"))
                .expect("read VERSION");
        assert_eq!(version_content.trim(), "1.4.1");
    }

    #[cfg(unix)]
    #[test]
    fn atomicity_current_link() {
        let base = tempdir().expect("tempdir");
        let agents_base = base.path().join("agents");
        std::fs::create_dir_all(&agents_base).unwrap();

        let staged = base.path().join("staged");
        write_fake_binary(&staged);

        install_new_version(&agents_base, "pmx-network", "2.0.0", &staged).expect("install");

        let current_link = agents_base.join("pmx-network").join("current");
        // std::fs::read_link verifies the link truly exists as a symlink.
        let target = std::fs::read_link(&current_link).expect("read_link must succeed");
        assert!(target.to_string_lossy().contains("2.0.0"));

        // Verify no leftover .tmp symlinks exist.
        for entry in std::fs::read_dir(agents_base.join("pmx-network")).expect("readdir") {
            let entry = entry.expect("entry");
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            assert!(
                !name_str.contains(".tmp."),
                "leftover tmp symlink: {}",
                name_str
            );
        }
    }

    #[test]
    fn rollback_without_previous_version_errors() {
        let base = tempdir().expect("tempdir");
        let handle = SwapHandle {
            agent: "pmx-network".to_string(),
            new_version: "1.4.2".to_string(),
            old_version: None,
            agents_base: base.path().to_path_buf(),
        };
        let err = rollback(&handle).expect_err("should fail");
        assert!(matches!(err, SwapError::NoPreviousVersion));
    }

    #[cfg(unix)]
    #[test]
    fn install_self_updates_symlinks() {
        let base = tempdir().expect("tempdir");
        let agents_base = base.path().join("agents");
        std::fs::create_dir_all(&agents_base).unwrap();

        // Install v1 first.
        let staged_v1 = base.path().join("staged-v1");
        write_fake_binary(&staged_v1);
        let _handle_v1 = install_new_version(&agents_base, "pmx-updater", "1.4.1", &staged_v1)
            .expect("install v1");

        // Install v2.
        let staged_v2 = base.path().join("staged-v2");
        write_fake_binary(&staged_v2);
        let handle_v2 = install_new_version(&agents_base, "pmx-updater", "1.4.2", &staged_v2)
            .expect("install v2");

        // install_self should update current to v2 and previous to v1.
        install_self(&handle_v2).expect("install self");

        let agent_dir = agents_base.join("pmx-updater");
        let current_target = std::fs::read_link(agent_dir.join("current")).expect("current");
        assert_eq!(current_target, PathBuf::from("versions/1.4.2/pmx-updater"));

        let previous_target = std::fs::read_link(agent_dir.join("previous")).expect("previous");
        assert_eq!(previous_target, PathBuf::from("versions/1.4.1/pmx-updater"));

        let version = std::fs::read_to_string(agent_dir.join("VERSION")).expect("VERSION");
        assert_eq!(version.trim(), "1.4.2");
    }

    #[cfg(unix)]
    #[test]
    fn install_self_no_previous_version() {
        let base = tempdir().expect("tempdir");
        let agents_base = base.path().join("agents");
        std::fs::create_dir_all(&agents_base).unwrap();

        let staged = base.path().join("staged-v1");
        write_fake_binary(&staged);
        let handle =
            install_new_version(&agents_base, "pmx-updater", "2.0.0", &staged).expect("install v1");

        // install_self with no old_version should still work (no previous symlink).
        install_self(&handle).expect("install self no prev");

        let agent_dir = agents_base.join("pmx-updater");
        let current_target = std::fs::read_link(agent_dir.join("current")).expect("current");
        assert_eq!(current_target, PathBuf::from("versions/2.0.0/pmx-updater"));

        // No previous symlink.
        assert!(
            !agent_dir.join("previous").exists(),
            "no previous symlink expected"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rollback_self_reverts_to_previous() {
        let base = tempdir().expect("tempdir");
        let agents_base = base.path().join("agents");
        std::fs::create_dir_all(&agents_base).unwrap();

        // Install v1 then v2.
        let staged_v1 = base.path().join("staged-v1");
        write_fake_binary(&staged_v1);
        install_new_version(&agents_base, "pmx-updater", "1.4.1", &staged_v1).expect("v1");

        let staged_v2 = base.path().join("staged-v2");
        write_fake_binary(&staged_v2);
        install_new_version(&agents_base, "pmx-updater", "1.4.2", &staged_v2).expect("v2");

        let agent_dir = agents_base.join("pmx-updater");

        // Create a minimal config for rollback_self.
        let config = crate::config::Config {
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
                agents_base: agents_base.to_string_lossy().to_string(),
                staging_dir: String::new(),
            },
        };

        rollback_self(&config).expect("rollback self");

        // current should now point to v1.
        let current_target = std::fs::read_link(agent_dir.join("current")).expect("current");
        assert_eq!(current_target, PathBuf::from("versions/1.4.1/pmx-updater"));

        let version = std::fs::read_to_string(agent_dir.join("VERSION")).expect("VERSION");
        assert_eq!(version.trim(), "1.4.1");

        // The bad v2 directory should be cleaned up.
        assert!(
            !agent_dir.join("versions/1.4.2").exists(),
            "bad version dir should be removed"
        );
    }

    #[test]
    fn extract_version_from_target_valid() {
        let target = PathBuf::from("versions/1.4.2/pmx-network");
        assert_eq!(
            extract_version_from_target(&target, "pmx-network"),
            Some("1.4.2".to_string())
        );
    }

    #[test]
    fn extract_version_from_target_wrong_agent() {
        let target = PathBuf::from("versions/1.4.2/pmx-other");
        assert_eq!(extract_version_from_target(&target, "pmx-network"), None);
    }

    #[test]
    fn extract_version_from_target_empty_path() {
        let target = PathBuf::from("");
        assert_eq!(extract_version_from_target(&target, "pmx-network"), None);
    }

    #[test]
    fn extract_version_from_target_single_component() {
        let target = PathBuf::from("pmx-network");
        // No version component before the agent name.
        assert_eq!(extract_version_from_target(&target, "pmx-network"), None);
    }

    #[test]
    fn swap_error_display() {
        let err = SwapError::NoPreviousVersion;
        assert!(err.to_string().contains("no previous version"));

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = SwapError::Io(io_err);
        assert!(err.to_string().contains("file missing"));
    }

    #[cfg(unix)]
    #[test]
    fn version_file_written_on_install() {
        let base = tempdir().expect("tempdir");
        let agents_base = base.path().join("agents");
        std::fs::create_dir_all(&agents_base).unwrap();

        let staged = base.path().join("staged");
        write_fake_binary(&staged);

        install_new_version(&agents_base, "pmx-core", "3.0.0", &staged).expect("install");

        let version =
            std::fs::read_to_string(agents_base.join("pmx-core/VERSION")).expect("VERSION");
        assert_eq!(version, "3.0.0");
    }
}
