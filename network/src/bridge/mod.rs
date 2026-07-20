use crate::netlink::CommandRunner;
use crate::persistence::{IfupdownStore, InterfaceKind, InterfaceSpec, MutationResult};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;

pub async fn create<R: CommandRunner>(
    runner: &R,
    store: &IfupdownStore,
    bridge: &str,
    ports: &[String],
    address: Option<String>,
    stp: bool,
) -> Result<MutationResult> {
    let spec = InterfaceSpec {
        name: bridge.to_string(),
        address,
        kind: InterfaceKind::Bridge {
            ports: ports.to_vec(),
            stp,
        },
    };
    store.assert_not_management_interface(&ports.iter().map(String::as_str).collect::<Vec<_>>())?;
    if interface_exists(runner, bridge).await? {
        bail!("INTERFACE_ALREADY_EXISTS: {}", bridge);
    }

    let snapshot = store.write_new(&spec)?;
    if let Err(error) = apply_runtime(runner, &spec).await {
        let runtime_rollback = rollback_created_bridge(runner, bridge).await;
        let config_rollback = store.rollback(snapshot);
        if runtime_rollback.is_err() || config_rollback.is_err() {
            bail!(
                "ROLLBACK_FAILED: bridge apply error: {}; runtime rollback: {}; config rollback: {}",
                error,
                format_result(runtime_rollback),
                format_result(config_rollback)
            );
        }
        return Err(error.context("bridge runtime apply failed; persisted config rolled back"));
    }

    store.mutation_result(&spec, true)
}

pub async fn destroy<R: CommandRunner>(
    runner: &R,
    store: &IfupdownStore,
    bridge: &str,
) -> Result<MutationResult> {
    let spec = store.load(bridge)?;
    if !matches!(spec.kind, InterfaceKind::Bridge { .. }) {
        bail!("INTERFACE_KIND_MISMATCH: {} is not a bridge", bridge);
    }
    store.assert_not_management_interface(&[bridge])?;

    let ports = runner
        .run("ip", &["-j", "link", "show", "master", bridge])
        .await?;
    if ports.status != 0 {
        bail!("bridge read-back failed: {}", ports.stderr);
    }
    if !parse_link_array(&ports.stdout)?.is_empty() {
        bail!("BRIDGE_IN_USE: {} still has member ports", bridge);
    }

    let snapshot = store.remove(bridge)?;
    if let Err(error) = runner
        .run_expect_ok("ip", &["link", "delete", "dev", bridge, "type", "bridge"])
        .await
    {
        store
            .rollback(snapshot)
            .context("restore bridge persistence after delete failure")?;
        return Err(error.context("bridge runtime delete failed; persisted config restored"));
    }
    let exists = match interface_exists(runner, bridge).await {
        Ok(exists) => exists,
        Err(error) => {
            store
                .rollback(snapshot)
                .context("restore bridge persistence after delete read-back failure")?;
            return Err(error.context(
                "bridge delete read-back failed; persisted config restored but runtime state is unknown",
            ));
        }
    };
    if exists {
        store
            .rollback(snapshot)
            .context("restore bridge persistence after failed delete read-back")?;
        bail!("bridge delete read-back still found {}", bridge);
    }

    store.mutation_result(&spec, false)
}

pub async fn port_add<R: CommandRunner>(
    runner: &R,
    store: &IfupdownStore,
    bridge: &str,
    port: &str,
) -> Result<MutationResult> {
    store.assert_not_management_interface(&[port])?;
    let mut spec = store.load(bridge)?;
    let ports = match &mut spec.kind {
        InterfaceKind::Bridge { ports, .. } => ports,
        _ => bail!("INTERFACE_KIND_MISMATCH: {} is not a bridge", bridge),
    };
    if ports.iter().any(|current| current == port) {
        bail!("BRIDGE_PORT_ALREADY_ATTACHED: {}", port);
    }
    if let Some(master) = read_port_master(runner, port).await? {
        bail!("BRIDGE_PORT_IN_USE: {} is attached to {}", port, master);
    }
    ports.push(port.to_string());
    let snapshot = store.replace(&spec)?;
    let applied = async {
        runner
            .run_expect_ok("ip", &["link", "set", "dev", port, "master", bridge])
            .await?;
        runner
            .run_expect_ok("ip", &["link", "set", "dev", port, "up"])
            .await?;
        verify_port_master(runner, port, Some(bridge)).await
    }
    .await;
    if let Err(error) = applied {
        let runtime_rollback = runner
            .run("ip", &["link", "set", "dev", port, "nomaster"])
            .await;
        let runtime_rollback = match runtime_rollback {
            Ok(result) if result.status == 0 => verify_port_master(runner, port, None).await,
            Ok(result) => Err(anyhow::anyhow!(
                "ip rollback failed with status {}: {}",
                result.status,
                result.stderr
            )),
            Err(error) => Err(error),
        };
        let config_rollback = store.rollback(snapshot);
        if runtime_rollback.is_err() || config_rollback.is_err() {
            bail!(
                "ROLLBACK_FAILED: bridge port-add error: {}; runtime rollback: {}; config rollback: {}",
                error,
                format_result(runtime_rollback),
                format_result(config_rollback)
            );
        }
        return Err(error.context("bridge port add failed; runtime and config rolled back"));
    }
    store.mutation_result(&spec, true)
}

pub async fn port_remove<R: CommandRunner>(
    runner: &R,
    store: &IfupdownStore,
    bridge: &str,
    port: &str,
) -> Result<MutationResult> {
    store.assert_not_management_interface(&[port])?;
    let mut spec = store.load(bridge)?;
    let ports = match &mut spec.kind {
        InterfaceKind::Bridge { ports, .. } => ports,
        _ => bail!("INTERFACE_KIND_MISMATCH: {} is not a bridge", bridge),
    };
    if !ports.iter().any(|current| current == port) {
        bail!("BRIDGE_PORT_NOT_ATTACHED: {}", port);
    }
    let runtime_master = read_port_master(runner, port).await?;
    if runtime_master.as_deref() != Some(bridge) {
        bail!(
            "BRIDGE_PORT_STATE_MISMATCH: {} is attached to {} instead of {}",
            port,
            runtime_master.as_deref().unwrap_or("no bridge"),
            bridge
        );
    }
    ports.retain(|current| current != port);
    let snapshot = store.replace(&spec)?;
    let applied = async {
        runner
            .run_expect_ok("ip", &["link", "set", "dev", port, "nomaster"])
            .await?;
        verify_port_master(runner, port, None).await
    }
    .await;
    if let Err(error) = applied {
        let runtime_rollback = runner
            .run("ip", &["link", "set", "dev", port, "master", bridge])
            .await;
        let runtime_rollback = match runtime_rollback {
            Ok(result) if result.status == 0 => {
                verify_port_master(runner, port, Some(bridge)).await
            }
            Ok(result) => Err(anyhow::anyhow!(
                "ip rollback failed with status {}: {}",
                result.status,
                result.stderr
            )),
            Err(error) => Err(error),
        };
        let config_rollback = store.rollback(snapshot);
        if runtime_rollback.is_err() || config_rollback.is_err() {
            bail!(
                "ROLLBACK_FAILED: bridge port-remove error: {}; runtime rollback: {}; config rollback: {}",
                error,
                format_result(runtime_rollback),
                format_result(config_rollback)
            );
        }
        return Err(error.context("bridge port remove failed; runtime and config rolled back"));
    }
    store.mutation_result(&spec, true)
}

async fn apply_runtime<R: CommandRunner>(runner: &R, spec: &InterfaceSpec) -> Result<()> {
    let (ports, stp) = match &spec.kind {
        InterfaceKind::Bridge { ports, stp } => (ports, *stp),
        _ => bail!("interface spec is not a bridge"),
    };
    runner
        .run_expect_ok("ip", &["link", "add", "name", &spec.name, "type", "bridge"])
        .await?;
    runner
        .run_expect_ok(
            "ip",
            &[
                "link",
                "set",
                "dev",
                &spec.name,
                "type",
                "bridge",
                "stp_state",
                if stp { "1" } else { "0" },
            ],
        )
        .await?;
    for port in ports {
        runner
            .run_expect_ok("ip", &["link", "set", "dev", port, "master", &spec.name])
            .await?;
        runner
            .run_expect_ok("ip", &["link", "set", "dev", port, "up"])
            .await?;
    }
    if let Some(address) = spec.address.as_deref() {
        runner
            .run_expect_ok("ip", &["address", "add", address, "dev", &spec.name])
            .await?;
    }
    runner
        .run_expect_ok("ip", &["link", "set", "dev", &spec.name, "up"])
        .await?;
    verify_bridge(runner, spec).await
}

async fn verify_bridge<R: CommandRunner>(runner: &R, spec: &InterfaceSpec) -> Result<()> {
    let link = runner
        .run("ip", &["-d", "-j", "link", "show", "dev", &spec.name])
        .await?;
    if link.status != 0 {
        bail!("bridge read-back failed: {}", link.stderr);
    }
    let rows = parse_link_array(&link.stdout)?;
    let row = rows
        .first()
        .context("bridge read-back returned no interface")?;
    let kind = row
        .pointer("/linkinfo/info_kind")
        .and_then(Value::as_str)
        .unwrap_or("");
    let up = row
        .get("flags")
        .and_then(Value::as_array)
        .is_some_and(|flags| flags.iter().any(|flag| flag.as_str() == Some("UP")));
    if kind != "bridge" || !up {
        bail!("bridge read-back did not confirm an active bridge");
    }

    if let InterfaceKind::Bridge { ports, .. } = &spec.kind {
        let members = runner
            .run("ip", &["-j", "link", "show", "master", &spec.name])
            .await?;
        if members.status != 0 {
            bail!("bridge port read-back failed: {}", members.stderr);
        }
        let names: BTreeSet<String> = parse_link_array(&members.stdout)?
            .into_iter()
            .filter_map(|row| {
                row.get("ifname")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect();
        if ports.iter().any(|port| !names.contains(port)) {
            bail!("bridge port read-back did not confirm every requested port");
        }
    }
    verify_address(runner, &spec.name, spec.address.as_deref()).await
}

async fn verify_address<R: CommandRunner>(
    runner: &R,
    iface: &str,
    expected: Option<&str>,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let (address, prefix) = expected.split_once('/').context("invalid expected CIDR")?;
    let result = runner
        .run("ip", &["-j", "address", "show", "dev", iface])
        .await?;
    if result.status != 0 {
        bail!("interface address read-back failed: {}", result.stderr);
    }
    let found = parse_link_array(&result.stdout)?.iter().any(|row| {
        row.get("addr_info")
            .and_then(Value::as_array)
            .is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry.get("local").and_then(Value::as_str) == Some(address)
                        && entry
                            .get("prefixlen")
                            .and_then(Value::as_u64)
                            .map(|value| value.to_string())
                            == Some(prefix.to_string())
                })
            })
    });
    if !found {
        bail!("interface address read-back did not confirm {}", expected);
    }
    Ok(())
}

async fn verify_port_master<R: CommandRunner>(
    runner: &R,
    port: &str,
    expected: Option<&str>,
) -> Result<()> {
    let master = read_port_master(runner, port).await?;
    if master.as_deref() != expected {
        bail!("bridge port read-back master mismatch");
    }
    Ok(())
}

async fn read_port_master<R: CommandRunner>(runner: &R, port: &str) -> Result<Option<String>> {
    let result = runner
        .run("ip", &["-j", "link", "show", "dev", port])
        .await?;
    if result.status != 0 {
        bail!("bridge port read-back failed: {}", result.stderr);
    }
    let rows = parse_link_array(&result.stdout)?;
    let master = rows
        .first()
        .and_then(|row| row.get("master"))
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(master)
}

async fn interface_exists<R: CommandRunner>(runner: &R, name: &str) -> Result<bool> {
    let result = runner
        .run("ip", &["-d", "-j", "link", "show", "dev", name])
        .await?;
    Ok(result.status == 0)
}

async fn rollback_created_bridge<R: CommandRunner>(runner: &R, name: &str) -> Result<()> {
    let result = runner
        .run("ip", &["link", "delete", "dev", name, "type", "bridge"])
        .await?;
    let exists = interface_exists(runner, name).await?;
    if exists {
        bail!(
            "bridge rollback delete failed with status {}: {}",
            result.status,
            result.stderr
        );
    }
    Ok(())
}

fn format_result(result: Result<()>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(error) => error.to_string(),
    }
}

fn parse_link_array(value: &str) -> Result<Vec<Value>> {
    serde_json::from_str(value).context("parse ip JSON read-back")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Persistence;
    use crate::netlink::CommandResult;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    type CommandCall = (String, Vec<String>);

    #[derive(Clone, Default)]
    struct ScriptedRunner {
        responses: Arc<Mutex<VecDeque<CommandResult>>>,
        calls: Arc<Mutex<Vec<CommandCall>>>,
    }

    impl ScriptedRunner {
        fn with(responses: Vec<CommandResult>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into())),
                calls: Arc::default(),
            }
        }
    }

    #[async_trait]
    impl CommandRunner for ScriptedRunner {
        async fn run(&self, bin: &str, args: &[&str]) -> Result<CommandResult> {
            self.calls.lock().unwrap().push((
                bin.to_string(),
                args.iter().map(|value| (*value).to_string()).collect(),
            ));
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("no scripted response"))
        }
    }

    fn output(status: i32, stdout: &str) -> CommandResult {
        CommandResult {
            stdout: stdout.to_string(),
            stderr: if status == 0 {
                String::new()
            } else {
                "failed".to_string()
            },
            status,
        }
    }

    fn fixture() -> (TempDir, IfupdownStore) {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("interfaces.d");
        let main = temp.path().join("interfaces");
        let route = temp.path().join("route");
        let ipv6_route = temp.path().join("ipv6_route");
        fs::create_dir(&directory).unwrap();
        fs::write(&main, format!("source {}/*\n", directory.display())).unwrap();
        fs::write(
            &route,
            "Iface Destination Gateway Flags\neth0 00000000 0 0003\n",
        )
        .unwrap();
        fs::write(&ipv6_route, "").unwrap();
        let store = IfupdownStore::open(&Persistence {
            backend: "ifupdown".to_string(),
            ifupdown_interfaces_file: main.display().to_string(),
            ifupdown_interfaces_dir: directory.display().to_string(),
            route_file: route.display().to_string(),
            ipv6_route_file: ipv6_route.display().to_string(),
        })
        .unwrap();
        (temp, store)
    }

    #[tokio::test]
    async fn create_persists_applies_and_reads_back_bridge() {
        let (_temp, store) = fixture();
        let runner = ScriptedRunner::with(vec![
            output(1, ""),
            output(0, ""),
            output(0, ""),
            output(0, ""),
            output(
                0,
                r#"[{"ifname":"vmbr10","flags":["UP"],"linkinfo":{"info_kind":"bridge"}}]"#,
            ),
            output(0, "[]"),
        ]);

        let result = create(&runner, &store, "vmbr10", &[], None, false)
            .await
            .unwrap();
        assert!(result.persisted && result.active);
        assert_eq!(store.load("vmbr10").unwrap().kind_name(), "bridge");
    }

    #[tokio::test]
    async fn create_rolls_back_config_and_runtime_when_apply_fails() {
        let (_temp, store) = fixture();
        let runner = ScriptedRunner::with(vec![
            output(1, ""),
            output(0, ""),
            output(1, ""),
            output(0, ""),
            output(1, ""),
        ]);

        let error = create(&runner, &store, "vmbr11", &[], None, false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("persisted config rolled back"));
        assert!(store.load("vmbr11").is_err());
        assert!(runner
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|(_, args)| { args == &["link", "delete", "dev", "vmbr11", "type", "bridge"] }));
    }

    #[tokio::test]
    async fn create_refuses_a_default_route_port_before_mutation() {
        let (_temp, store) = fixture();
        let runner = ScriptedRunner::default();
        let error = create(
            &runner,
            &store,
            "vmbr12",
            &["eth0".to_string()],
            None,
            false,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("MANAGEMENT_INTERFACE_PROTECTED"));
        assert!(runner.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn port_add_refuses_a_port_owned_by_another_runtime_bridge() {
        let (_temp, store) = fixture();
        store
            .write_new(&InterfaceSpec {
                name: "vmbr12".to_string(),
                address: None,
                kind: InterfaceKind::Bridge {
                    ports: vec![],
                    stp: false,
                },
            })
            .unwrap();
        let runner =
            ScriptedRunner::with(vec![output(0, r#"[{"ifname":"eth1","master":"vmbr99"}]"#)]);

        let error = port_add(&runner, &store, "vmbr12", "eth1")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("BRIDGE_PORT_IN_USE"));
        let spec = store.load("vmbr12").unwrap();
        assert_eq!(
            spec.kind,
            InterfaceKind::Bridge {
                ports: vec![],
                stp: false
            }
        );
    }

    #[tokio::test]
    async fn port_remove_refuses_runtime_state_drift_before_config_mutation() {
        let (_temp, store) = fixture();
        store
            .write_new(&InterfaceSpec {
                name: "vmbr12".to_string(),
                address: None,
                kind: InterfaceKind::Bridge {
                    ports: vec!["eth1".to_string()],
                    stp: false,
                },
            })
            .unwrap();
        let runner =
            ScriptedRunner::with(vec![output(0, r#"[{"ifname":"eth1","master":"vmbr99"}]"#)]);

        let error = port_remove(&runner, &store, "vmbr12", "eth1")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("BRIDGE_PORT_STATE_MISMATCH"));
        let spec = store.load("vmbr12").unwrap();
        assert_eq!(
            spec.kind,
            InterfaceKind::Bridge {
                ports: vec!["eth1".to_string()],
                stp: false
            }
        );
    }
}
