use crate::os_update::{ApplyMode, ApplyResult, PackageInfo, ScanResult};
use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

const APT_GET_BIN: &str = "/usr/bin/apt-get";
const REBOOT_REQUIRED_PATH: &str = "/var/run/reboot-required";

#[derive(Debug, Clone)]
struct CommandOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

trait CommandRunner {
    fn run(&self, arguments: &[String]) -> Result<CommandOutput>;
}

struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, arguments: &[String]) -> Result<CommandOutput> {
        let output = Command::new(APT_GET_BIN)
            .args(arguments)
            .env("DEBIAN_FRONTEND", "noninteractive")
            .env("LC_ALL", "C")
            .output()
            .with_context(|| format!("execute {}", APT_GET_BIN))?;

        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

pub fn scan() -> Result<ScanResult> {
    scan_with_runner(&SystemCommandRunner)
}

pub fn apply(mode: ApplyMode, _packages: Vec<PackageInfo>) -> Result<ApplyResult> {
    apply_with_runner(&SystemCommandRunner, mode)
}

fn scan_with_runner(runner: &dyn CommandRunner) -> Result<ScanResult> {
    refresh_package_indexes(runner)?;
    Ok(ScanResult {
        packages: plan_upgrades(runner)?,
    })
}

fn apply_with_runner(runner: &dyn CommandRunner, mode: ApplyMode) -> Result<ApplyResult> {
    if mode == ApplyMode::DryRun {
        return Ok(ApplyResult {
            mode: "dry_run".to_string(),
            reboot_required: false,
            packages: plan_upgrades(runner)?,
        });
    }

    refresh_package_indexes(runner)?;
    let planned = plan_upgrades(runner)?;
    let selected = match mode {
        ApplyMode::Security => planned
            .into_iter()
            .filter(|package| package.security)
            .collect::<Vec<_>>(),
        ApplyMode::Full => planned,
        ApplyMode::DryRun => unreachable!("dry-run returned before package application"),
    };

    if !selected.is_empty() {
        apply_packages(runner, mode, &selected)?;
    }

    Ok(ApplyResult {
        mode: match mode {
            ApplyMode::Security => "security",
            ApplyMode::Full => "full",
            ApplyMode::DryRun => unreachable!("dry-run returned before result construction"),
        }
        .to_string(),
        reboot_required: reboot_required_at(Path::new(REBOOT_REQUIRED_PATH)),
        packages: selected,
    })
}

fn refresh_package_indexes(runner: &dyn CommandRunner) -> Result<()> {
    run_checked(
        runner,
        strings(&["-q", "-o", "Dpkg::Lock::Timeout=60", "update"]),
        "refresh package indexes",
    )?;
    Ok(())
}

fn plan_upgrades(runner: &dyn CommandRunner) -> Result<Vec<PackageInfo>> {
    let output = run_checked(
        runner,
        strings(&[
            "-s",
            "-V",
            "-o",
            "Dpkg::Lock::Timeout=60",
            "upgrade",
            "--with-new-pkgs",
        ]),
        "simulate package upgrade",
    )?;

    Ok(output
        .stdout
        .lines()
        .filter_map(parse_install_line)
        .collect())
}

fn apply_packages(
    runner: &dyn CommandRunner,
    mode: ApplyMode,
    packages: &[PackageInfo],
) -> Result<()> {
    let mut arguments = strings(&[
        "-q",
        "-y",
        "-V",
        "-o",
        "Dpkg::Lock::Timeout=60",
        "-o",
        "Dpkg::Options::=--force-confold",
        "--no-remove",
    ]);

    match mode {
        ApplyMode::Security => {
            arguments.extend(strings(&["--only-upgrade", "install"]));
            arguments.extend(packages.iter().map(|package| package.name.clone()));
        }
        ApplyMode::Full => {
            arguments.extend(strings(&["upgrade", "--with-new-pkgs"]));
        }
        ApplyMode::DryRun => bail!("dry-run must not execute package changes"),
    }

    run_checked(runner, arguments, "apply package upgrades")?;
    Ok(())
}

fn run_checked(
    runner: &dyn CommandRunner,
    arguments: Vec<String>,
    operation: &str,
) -> Result<CommandOutput> {
    let output = runner.run(&arguments)?;
    if output.success {
        return Ok(output);
    }

    let detail = if output.stderr.trim().is_empty() {
        output.stdout.trim()
    } else {
        output.stderr.trim()
    };
    bail!("{} failed: {}", operation, truncate(detail, 4096))
}

fn parse_install_line(line: &str) -> Option<PackageInfo> {
    let rest = line.trim().strip_prefix("Inst ")?;
    let name = rest.split_whitespace().next()?.trim();
    if name.is_empty() {
        return None;
    }

    let installed_version = rest
        .find('[')
        .and_then(|start| {
            rest[start + 1..]
                .find(']')
                .map(|end| rest[start + 1..start + 1 + end].trim().to_string())
        })
        .unwrap_or_default();
    let candidate_start = rest.find('(')? + 1;
    let candidate_tail = rest[candidate_start..].trim();
    let candidate_version = candidate_tail.split_whitespace().next()?.trim();
    if candidate_version.is_empty() {
        return None;
    }

    let source = candidate_tail[candidate_version.len()..].to_ascii_lowercase();
    let security = source.contains("-security")
        || source.contains("debian-security")
        || source.contains("security/")
        || source.contains("ubuntu-esm");

    Some(PackageInfo {
        name: name.to_string(),
        installed_version,
        candidate_version: candidate_version.to_string(),
        security,
    })
}

fn reboot_required_at(path: &Path) -> bool {
    path.is_file()
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn truncate(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct FakeRunner {
        outputs: RefCell<VecDeque<CommandOutput>>,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl FakeRunner {
        fn new(outputs: Vec<CommandOutput>) -> Self {
            Self {
                outputs: RefCell::new(outputs.into()),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, arguments: &[String]) -> Result<CommandOutput> {
            self.calls.borrow_mut().push(arguments.to_vec());
            self.outputs
                .borrow_mut()
                .pop_front()
                .context("fake runner has no queued output")
        }
    }

    fn ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            success: true,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    fn upgrade_plan() -> &'static str {
        "Inst openssl [3.0.11-1] (3.0.11-1+deb12u2 Debian-Security:12/stable-security [amd64])\n\
         Inst curl [8.3.0-1] (8.4.0-1 Debian:12/stable [amd64])\n"
    }

    #[test]
    fn scan_refreshes_indexes_and_returns_real_simulated_packages() {
        let runner = FakeRunner::new(vec![ok("indexes refreshed"), ok(upgrade_plan())]);

        let result = scan_with_runner(&runner).expect("scan");

        assert_eq!(result.packages.len(), 2);
        assert_eq!(result.packages[0].name, "openssl");
        assert!(result.packages[0].security);
        assert!(!result.packages[1].security);
        assert_eq!(runner.calls.borrow().len(), 2);
        assert!(runner.calls.borrow()[0].contains(&"update".to_string()));
        assert!(runner.calls.borrow()[1].contains(&"-s".to_string()));
    }

    #[test]
    fn dry_run_never_executes_an_apply_command() {
        let runner = FakeRunner::new(vec![ok(upgrade_plan())]);

        let result = apply_with_runner(&runner, ApplyMode::DryRun).expect("dry-run");

        assert_eq!(result.mode, "dry_run");
        assert_eq!(result.packages.len(), 2);
        assert_eq!(runner.calls.borrow().len(), 1);
        assert!(runner.calls.borrow()[0].contains(&"-s".to_string()));
    }

    #[test]
    fn security_apply_selects_only_security_origin_packages() {
        let runner = FakeRunner::new(vec![
            ok("indexes refreshed"),
            ok(upgrade_plan()),
            ok("applied"),
        ]);

        let result = apply_with_runner(&runner, ApplyMode::Security).expect("security apply");

        assert_eq!(result.packages.len(), 1);
        assert_eq!(result.packages[0].name, "openssl");
        let apply_call = &runner.calls.borrow()[2];
        assert!(apply_call.contains(&"--only-upgrade".to_string()));
        assert!(apply_call.contains(&"openssl".to_string()));
        assert!(!apply_call.contains(&"curl".to_string()));
    }

    #[test]
    fn full_apply_uses_non_removing_upgrade_mode() {
        let runner = FakeRunner::new(vec![
            ok("indexes refreshed"),
            ok(upgrade_plan()),
            ok("applied"),
        ]);

        let result = apply_with_runner(&runner, ApplyMode::Full).expect("full apply");

        assert_eq!(result.packages.len(), 2);
        let apply_call = &runner.calls.borrow()[2];
        assert!(apply_call.contains(&"--no-remove".to_string()));
        assert!(apply_call.contains(&"--with-new-pkgs".to_string()));
        assert!(apply_call.contains(&"upgrade".to_string()));
    }

    #[test]
    fn apt_failure_is_returned_instead_of_false_success() {
        let runner = FakeRunner::new(vec![CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: "repository signature verification failed".to_string(),
        }]);

        let error = scan_with_runner(&runner).expect_err("scan must fail");

        assert!(error
            .to_string()
            .contains("repository signature verification failed"));
    }

    #[test]
    fn malformed_simulation_lines_are_ignored() {
        assert!(parse_install_line("Conf openssl").is_none());
        assert!(parse_install_line("Inst").is_none());
        assert!(parse_install_line("Inst openssl without-version").is_none());
    }

    #[test]
    fn reboot_marker_is_reported_from_the_filesystem() {
        let directory = tempfile::tempdir().expect("tempdir");
        let marker = directory.path().join("reboot-required");
        assert!(!reboot_required_at(&marker));
        std::fs::write(&marker, "linux-image").expect("write marker");
        assert!(reboot_required_at(&marker));
    }
}
