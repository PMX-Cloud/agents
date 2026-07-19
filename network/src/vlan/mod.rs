use crate::netlink::CommandRunner;
use crate::persistence::{IfupdownStore, InterfaceKind, InterfaceSpec, MutationResult};
use anyhow::{bail, Context, Result};
use serde_json::Value;

pub async fn create<R: CommandRunner>(
    runner: &R,
    store: &IfupdownStore,
    parent: &str,
    name: &str,
    vid: u16,
    address: Option<String>,
) -> Result<MutationResult> {
    let spec = InterfaceSpec {
        name: name.to_string(),
        address,
        kind: InterfaceKind::Vlan {
            parent: parent.to_string(),
            vid,
        },
    };
    if interface_exists(runner, name).await? {
        bail!("INTERFACE_ALREADY_EXISTS: {}", name);
    }

    let snapshot = store.write_new(&spec)?;
    if let Err(error) = apply_runtime(runner, &spec).await {
        let runtime_rollback = rollback_created_vlan(runner, name).await;
        let config_rollback = store.rollback(snapshot);
        if runtime_rollback.is_err() || config_rollback.is_err() {
            bail!(
                "ROLLBACK_FAILED: VLAN apply error: {}; runtime rollback: {}; config rollback: {}",
                error,
                format_result(runtime_rollback),
                format_result(config_rollback)
            );
        }
        return Err(error.context("VLAN runtime apply failed; persisted config rolled back"));
    }
    store.mutation_result(&spec, true)
}

pub async fn destroy<R: CommandRunner>(
    runner: &R,
    store: &IfupdownStore,
    name: &str,
) -> Result<MutationResult> {
    let spec = store.load(name)?;
    if !matches!(spec.kind, InterfaceKind::Vlan { .. }) {
        bail!("INTERFACE_KIND_MISMATCH: {} is not a VLAN", name);
    }
    store.assert_not_management_interface(&[name])?;

    let snapshot = store.remove(name)?;
    if let Err(error) = runner
        .run_expect_ok("ip", &["link", "delete", "dev", name])
        .await
    {
        store
            .rollback(snapshot)
            .context("restore VLAN persistence after delete failure")?;
        return Err(error.context("VLAN runtime delete failed; persisted config restored"));
    }
    let exists = match interface_exists(runner, name).await {
        Ok(exists) => exists,
        Err(error) => {
            store
                .rollback(snapshot)
                .context("restore VLAN persistence after delete read-back failure")?;
            return Err(error.context(
                "VLAN delete read-back failed; persisted config restored but runtime state is unknown",
            ));
        }
    };
    if exists {
        store
            .rollback(snapshot)
            .context("restore VLAN persistence after failed delete read-back")?;
        bail!("VLAN delete read-back still found {}", name);
    }
    store.mutation_result(&spec, false)
}

async fn apply_runtime<R: CommandRunner>(runner: &R, spec: &InterfaceSpec) -> Result<()> {
    let (parent, vid) = match &spec.kind {
        InterfaceKind::Vlan { parent, vid } => (parent, *vid),
        _ => bail!("interface spec is not a VLAN"),
    };
    let id = vid.to_string();
    runner
        .run_expect_ok(
            "ip",
            &[
                "link", "add", "link", parent, "name", &spec.name, "type", "vlan", "id", &id,
            ],
        )
        .await?;
    if let Some(address) = spec.address.as_deref() {
        runner
            .run_expect_ok("ip", &["address", "add", address, "dev", &spec.name])
            .await?;
    }
    runner
        .run_expect_ok("ip", &["link", "set", "dev", &spec.name, "up"])
        .await?;
    verify_vlan(runner, spec).await
}

async fn verify_vlan<R: CommandRunner>(runner: &R, spec: &InterfaceSpec) -> Result<()> {
    let result = runner
        .run("ip", &["-d", "-j", "link", "show", "dev", &spec.name])
        .await?;
    if result.status != 0 {
        bail!("VLAN read-back failed: {}", result.stderr);
    }
    let rows: Vec<Value> = serde_json::from_str(&result.stdout).context("parse VLAN read-back")?;
    let row = rows
        .first()
        .context("VLAN read-back returned no interface")?;
    let kind = row
        .pointer("/linkinfo/info_kind")
        .and_then(Value::as_str)
        .unwrap_or("");
    let actual_vid = row
        .pointer("/linkinfo/info_data/id")
        .and_then(Value::as_u64);
    let expected_vid = match spec.kind {
        InterfaceKind::Vlan { vid, .. } => u64::from(vid),
        _ => 0,
    };
    let up = row
        .get("flags")
        .and_then(Value::as_array)
        .is_some_and(|flags| flags.iter().any(|flag| flag.as_str() == Some("UP")));
    if kind != "vlan" || actual_vid != Some(expected_vid) || !up {
        bail!("VLAN read-back did not confirm the requested active VLAN");
    }

    if let Some(expected) = spec.address.as_deref() {
        let (address, prefix) = expected.split_once('/').context("invalid expected CIDR")?;
        let address_result = runner
            .run("ip", &["-j", "address", "show", "dev", &spec.name])
            .await?;
        if address_result.status != 0 {
            bail!("VLAN address read-back failed: {}", address_result.stderr);
        }
        let rows: Vec<Value> =
            serde_json::from_str(&address_result.stdout).context("parse VLAN address read-back")?;
        let found = rows.iter().any(|row| {
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
            bail!("VLAN address read-back did not confirm {}", expected);
        }
    }
    Ok(())
}

async fn interface_exists<R: CommandRunner>(runner: &R, name: &str) -> Result<bool> {
    let result = runner
        .run("ip", &["-d", "-j", "link", "show", "dev", name])
        .await?;
    Ok(result.status == 0)
}

async fn rollback_created_vlan<R: CommandRunner>(runner: &R, name: &str) -> Result<()> {
    let result = runner.run("ip", &["link", "delete", "dev", name]).await?;
    let exists = interface_exists(runner, name).await?;
    if exists {
        bail!(
            "VLAN rollback delete failed with status {}: {}",
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

    #[derive(Clone, Default)]
    struct ScriptedRunner {
        responses: Arc<Mutex<VecDeque<CommandResult>>>,
    }

    #[async_trait]
    impl CommandRunner for ScriptedRunner {
        async fn run(&self, _bin: &str, _args: &[&str]) -> Result<CommandResult> {
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
    async fn creates_persists_and_reads_back_vlan() {
        let (_temp, store) = fixture();
        let runner = ScriptedRunner {
            responses: Arc::new(Mutex::new(
                vec![
                    output(1, ""),
                    output(0, ""),
                    output(0, ""),
                    output(
                        0,
                        r#"[{"ifname":"vlan100","flags":["UP"],"linkinfo":{"info_kind":"vlan","info_data":{"id":100}}}]"#,
                    ),
                ]
                .into(),
            )),
        };
        let result = create(&runner, &store, "vmbr0", "vlan100", 100, None)
            .await
            .unwrap();
        assert!(result.persisted && result.active);
        assert_eq!(store.load("vlan100").unwrap().kind_name(), "vlan");
    }

    #[tokio::test]
    async fn rolls_back_persistence_when_vlan_apply_fails() {
        let (_temp, store) = fixture();
        let runner = ScriptedRunner {
            responses: Arc::new(Mutex::new(
                vec![output(1, ""), output(1, ""), output(0, ""), output(1, "")].into(),
            )),
        };
        let error = create(&runner, &store, "vmbr0", "vlan101", 101, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("persisted config rolled back"));
        assert!(store.load("vlan101").is_err());
    }
}
