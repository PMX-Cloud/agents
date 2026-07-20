use crate::config::Persistence;
use crate::netlink::is_safe_ifname;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MANAGED_MARKER: &str = "# Managed by PMX-Cloud. Do not edit.";
const SPEC_PREFIX: &str = "# pmx-cloud-spec: ";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InterfaceKind {
    Bridge { ports: Vec<String>, stp: bool },
    Vlan { parent: String, vid: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceSpec {
    pub name: String,
    pub address: Option<String>,
    pub kind: InterfaceKind,
}

impl InterfaceSpec {
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            InterfaceKind::Bridge { .. } => "bridge",
            InterfaceKind::Vlan { .. } => "vlan",
        }
    }
}

#[derive(Debug)]
pub struct ConfigSnapshot {
    path: PathBuf,
    previous: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationResult {
    pub ok: bool,
    pub backend: &'static str,
    pub config_path: String,
    pub interface: String,
    pub kind: &'static str,
    pub persisted: bool,
    pub active: bool,
    pub rolled_back: bool,
}

#[derive(Debug, Clone)]
pub struct IfupdownStore {
    main_file: PathBuf,
    config_dir: PathBuf,
    route_file: PathBuf,
    ipv6_route_file: PathBuf,
}

impl IfupdownStore {
    pub fn open(config: &Persistence) -> Result<Self> {
        if !matches!(config.backend.as_str(), "auto" | "ifupdown") {
            bail!("NETWORK_PERSISTENCE_UNSUPPORTED: only ifupdown is implemented");
        }

        let store = Self {
            main_file: PathBuf::from(&config.ifupdown_interfaces_file),
            config_dir: PathBuf::from(&config.ifupdown_interfaces_dir),
            route_file: PathBuf::from(&config.route_file),
            ipv6_route_file: PathBuf::from(&config.ipv6_route_file),
        };
        store.verify_backend()?;
        Ok(store)
    }

    fn verify_backend(&self) -> Result<()> {
        let main = read_bounded(&self.main_file)
            .with_context(|| "NETWORK_PERSISTENCE_UNSUPPORTED: read ifupdown main config")?;
        let main = String::from_utf8(main)
            .with_context(|| "NETWORK_PERSISTENCE_UNSUPPORTED: ifupdown config is not UTF-8")?;
        let expected_source = format!("{}/*", self.config_dir.display());
        let expected_directory = self.config_dir.display().to_string();
        let included = main.lines().any(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            let fields: Vec<&str> = line.split_whitespace().collect();
            matches!(fields.as_slice(), ["source", path] if *path == expected_source)
                || matches!(fields.as_slice(), ["source-directory", path] if *path == expected_directory)
        });
        if !included {
            bail!(
                "NETWORK_PERSISTENCE_UNSUPPORTED: {} does not include {}",
                self.main_file.display(),
                self.config_dir.display()
            );
        }

        let metadata = fs::symlink_metadata(&self.config_dir).with_context(|| {
            format!(
                "NETWORK_PERSISTENCE_UNSUPPORTED: inspect {}",
                self.config_dir.display()
            )
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("NETWORK_PERSISTENCE_UNSUPPORTED: config directory is not a real directory");
        }
        Ok(())
    }

    pub fn write_new(&self, spec: &InterfaceSpec) -> Result<ConfigSnapshot> {
        self.write(spec, false)
    }

    pub fn replace(&self, spec: &InterfaceSpec) -> Result<ConfigSnapshot> {
        self.write(spec, true)
    }

    fn write(&self, spec: &InterfaceSpec, replace: bool) -> Result<ConfigSnapshot> {
        validate_spec(spec)?;
        self.assert_no_foreign_definition(&spec.name)?;
        let path = self.path_for(&spec.name)?;
        let previous = if path.exists() {
            let bytes = read_bounded(&path)?;
            assert_managed(&bytes, &path)?;
            if !replace {
                bail!("INTERFACE_ALREADY_MANAGED: {}", spec.name);
            }
            Some(bytes)
        } else {
            None
        };
        atomic_write(&path, render(spec)?.as_bytes())?;
        Ok(ConfigSnapshot { path, previous })
    }

    pub fn remove(&self, name: &str) -> Result<ConfigSnapshot> {
        validate_ifname(name, "interface")?;
        let path = self.path_for(name)?;
        let previous =
            read_bounded(&path).with_context(|| format!("INTERFACE_NOT_MANAGED: {}", name))?;
        assert_managed(&previous, &path)?;
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
        sync_directory(&self.config_dir)?;
        Ok(ConfigSnapshot {
            path,
            previous: Some(previous),
        })
    }

    pub fn rollback(&self, snapshot: ConfigSnapshot) -> Result<()> {
        match snapshot.previous {
            Some(previous) => atomic_write(&snapshot.path, &previous),
            None => {
                if snapshot.path.exists() {
                    fs::remove_file(&snapshot.path)
                        .with_context(|| format!("remove {}", snapshot.path.display()))?;
                    sync_directory(&self.config_dir)?;
                }
                Ok(())
            }
        }
    }

    pub fn load(&self, name: &str) -> Result<InterfaceSpec> {
        validate_ifname(name, "interface")?;
        let path = self.path_for(name)?;
        let bytes =
            read_bounded(&path).with_context(|| format!("INTERFACE_NOT_MANAGED: {}", name))?;
        assert_managed(&bytes, &path)?;
        let content = String::from_utf8(bytes).context("managed interface config is not UTF-8")?;
        let encoded = content
            .lines()
            .find_map(|line| line.strip_prefix(SPEC_PREFIX))
            .ok_or_else(|| anyhow::anyhow!("managed interface config has no PMX spec"))?;
        let spec: InterfaceSpec =
            serde_json::from_str(encoded).context("parse managed interface spec")?;
        validate_spec(&spec)?;
        if spec.name != name {
            bail!("managed interface spec name does not match file name");
        }
        Ok(spec)
    }

    pub fn assert_not_management_interface(&self, names: &[&str]) -> Result<()> {
        let protected = default_route_interfaces(&self.route_file)?;
        let mut protected = protected;
        protected.extend(default_ipv6_route_interfaces(&self.ipv6_route_file)?);
        if let Some(name) = names.iter().find(|name| protected.contains(**name)) {
            bail!(
                "MANAGEMENT_INTERFACE_PROTECTED: {} owns a default route",
                name
            );
        }
        Ok(())
    }

    pub fn mutation_result(&self, spec: &InterfaceSpec, active: bool) -> Result<MutationResult> {
        Ok(MutationResult {
            ok: true,
            backend: "ifupdown",
            config_path: self.path_for(&spec.name)?.display().to_string(),
            interface: spec.name.clone(),
            kind: spec.kind_name(),
            persisted: true,
            active,
            rolled_back: false,
        })
    }

    fn assert_no_foreign_definition(&self, name: &str) -> Result<()> {
        if contains_iface_definition(&read_bounded(&self.main_file)?, name)? {
            bail!(
                "INTERFACE_CONFIG_CONFLICT: {} is defined in the main config",
                name
            );
        }
        let own_path = self.path_for(name)?;
        for entry in fs::read_dir(&self.config_dir)
            .with_context(|| format!("read {}", self.config_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path == own_path || !entry.file_type()?.is_file() {
                continue;
            }
            if contains_iface_definition(&read_bounded(&path)?, name)? {
                bail!(
                    "INTERFACE_CONFIG_CONFLICT: {} is defined in {}",
                    name,
                    path.display()
                );
            }
        }
        Ok(())
    }

    fn path_for(&self, name: &str) -> Result<PathBuf> {
        validate_ifname(name, "interface")?;
        Ok(self.config_dir.join(format!("pmx-cloud-{}", name)))
    }
}

pub fn validate_spec(spec: &InterfaceSpec) -> Result<()> {
    validate_ifname(&spec.name, "interface")?;
    if let Some(address) = spec.address.as_deref() {
        validate_cidr(address)?;
    }
    match &spec.kind {
        InterfaceKind::Bridge { ports, .. } => {
            if ports.len() > 32 {
                bail!("bridge port count exceeds 32");
            }
            let mut unique = BTreeSet::new();
            for port in ports {
                validate_ifname(port, "bridge port")?;
                if port == &spec.name {
                    bail!("bridge cannot contain itself as a port");
                }
                if !unique.insert(port) {
                    bail!("bridge ports must be unique");
                }
            }
        }
        InterfaceKind::Vlan { parent, vid } => {
            validate_ifname(parent, "VLAN parent")?;
            if parent == &spec.name {
                bail!("VLAN parent must differ from its interface name");
            }
            if *vid == 0 || *vid > 4094 {
                bail!("VLAN ID must be between 1 and 4094");
            }
        }
    }
    Ok(())
}

pub fn render(spec: &InterfaceSpec) -> Result<String> {
    validate_spec(spec)?;
    let encoded = serde_json::to_string(spec).context("encode managed interface spec")?;
    let method = if spec.address.is_some() {
        "static"
    } else {
        "manual"
    };
    let mut output = format!(
        "{}\n{}{}\nauto {}\niface {} inet {}\n",
        MANAGED_MARKER, SPEC_PREFIX, encoded, spec.name, spec.name, method
    );
    if let Some(address) = spec.address.as_deref() {
        output.push_str(&format!("    address {}\n", address));
    }
    match &spec.kind {
        InterfaceKind::Bridge { ports, stp } => {
            output.push_str(&format!(
                "    bridge-ports {}\n    bridge-stp {}\n    bridge-fd 0\n",
                if ports.is_empty() {
                    "none".to_string()
                } else {
                    ports.join(" ")
                },
                if *stp { "on" } else { "off" }
            ));
        }
        InterfaceKind::Vlan { parent, .. } => {
            output.push_str(&format!("    vlan-raw-device {}\n", parent));
        }
    }
    Ok(output)
}

fn validate_ifname(value: &str, field: &str) -> Result<()> {
    // Linux IFNAMSIZ is 16 bytes including the terminating NUL.
    if !is_safe_ifname(value) || value.len() > 15 {
        bail!("invalid {} name", field);
    }
    Ok(())
}

fn validate_cidr(value: &str) -> Result<()> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("interface address must include a CIDR prefix"))?;
    let address: IpAddr = address.parse().context("invalid interface IP address")?;
    let prefix: u8 = prefix.parse().context("invalid interface CIDR prefix")?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        bail!("invalid interface CIDR prefix");
    }
    Ok(())
}

fn contains_iface_definition(content: &[u8], name: &str) -> Result<bool> {
    let content = std::str::from_utf8(content).context("network config is not UTF-8")?;
    Ok(content.lines().any(|line| {
        let fields: Vec<&str> = line
            .split('#')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        matches!(fields.as_slice(), ["iface", candidate, ..] if *candidate == name)
    }))
}

fn assert_managed(content: &[u8], path: &Path) -> Result<()> {
    let content = std::str::from_utf8(content).context("interface config is not UTF-8")?;
    if !content
        .lines()
        .next()
        .is_some_and(|line| line == MANAGED_MARKER)
    {
        bail!(
            "INTERFACE_CONFIG_CONFLICT: {} is not PMX-managed",
            path.display()
        );
    }
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{} must be a regular non-symlink file", path.display());
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        bail!("{} exceeds the configuration size limit", path.display());
    }
    fs::read(path).with_context(|| format!("read {}", path.display()))
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("configuration path has no parent"))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("configuration file name is invalid"))?;
    let temp = parent.join(format!(".{}.tmp-{}", file_name, std::process::id()));
    if temp.exists() {
        fs::remove_file(&temp).with_context(|| format!("remove stale {}", temp.display()))?;
    }
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .with_context(|| format!("create {}", temp.display()))?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o644))?;
        fs::rename(&temp, path)
            .with_context(|| format!("rename {} to {}", temp.display(), path.display()))?;
        sync_directory(parent)
    })();
    if result.is_err() && temp.exists() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("sync {}", path.display()))
}

fn default_route_interfaces(path: &Path) -> Result<BTreeSet<String>> {
    let content = read_bounded(path)?;
    let content = std::str::from_utf8(&content).context("route table is not UTF-8")?;
    let mut interfaces = BTreeSet::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[1] != "00000000" {
            continue;
        }
        let flags = u16::from_str_radix(fields[3], 16).unwrap_or(0);
        if flags & 0x1 != 0 && is_safe_ifname(fields[0]) {
            interfaces.insert(fields[0].to_string());
        }
    }
    Ok(interfaces)
}

fn default_ipv6_route_interfaces(path: &Path) -> Result<BTreeSet<String>> {
    let content = read_bounded(path)?;
    let content = std::str::from_utf8(&content).context("IPv6 route table is not UTF-8")?;
    let mut interfaces = BTreeSet::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 || fields[0] != "00000000000000000000000000000000" || fields[1] != "00"
        {
            continue;
        }
        let iface = fields[9];
        if is_safe_ifname(iface) {
            interfaces.insert(iface.to_string());
        }
    }
    Ok(interfaces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, Persistence) {
        let temp = TempDir::new().unwrap();
        let main = temp.path().join("interfaces");
        let dir = temp.path().join("interfaces.d");
        let route = temp.path().join("route");
        let ipv6_route = temp.path().join("ipv6_route");
        fs::create_dir(&dir).unwrap();
        fs::write(
            &main,
            format!(
                "auto lo\niface lo inet loopback\nsource {}/*\n",
                dir.display()
            ),
        )
        .unwrap();
        fs::write(
            &ipv6_route,
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000064 00000000 00000000 00000003 eth1\n",
        )
        .unwrap();
        fs::write(
            &route,
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\n",
        )
        .unwrap();
        let config = Persistence {
            backend: "ifupdown".to_string(),
            ifupdown_interfaces_file: main.display().to_string(),
            ifupdown_interfaces_dir: dir.display().to_string(),
            route_file: route.display().to_string(),
            ipv6_route_file: ipv6_route.display().to_string(),
        };
        (temp, config)
    }

    fn bridge_spec() -> InterfaceSpec {
        InterfaceSpec {
            name: "vmbr10".to_string(),
            address: Some("10.10.10.1/24".to_string()),
            kind: InterfaceKind::Bridge {
                ports: vec!["eno1".to_string()],
                stp: false,
            },
        }
    }

    #[test]
    fn renders_and_round_trips_a_managed_bridge() {
        let (_temp, config) = fixture();
        let store = IfupdownStore::open(&config).unwrap();
        let spec = bridge_spec();
        let snapshot = store.write_new(&spec).unwrap();
        assert_eq!(store.load("vmbr10").unwrap(), spec);
        let rendered = fs::read_to_string(store.path_for("vmbr10").unwrap()).unwrap();
        assert!(rendered.contains("iface vmbr10 inet static"));
        assert!(rendered.contains("bridge-ports eno1"));
        store.rollback(snapshot).unwrap();
        assert!(!store.path_for("vmbr10").unwrap().exists());
    }

    #[test]
    fn refuses_foreign_definitions_and_non_included_directories() {
        let (temp, mut config) = fixture();
        fs::write(
            temp.path().join("interfaces.d/foreign"),
            "auto vmbr10\niface vmbr10 inet manual\n",
        )
        .unwrap();
        let store = IfupdownStore::open(&config).unwrap();
        let error = store.write_new(&bridge_spec()).unwrap_err();
        assert!(error.to_string().contains("INTERFACE_CONFIG_CONFLICT"));

        config.ifupdown_interfaces_dir = temp.path().join("not-included").display().to_string();
        fs::create_dir(&config.ifupdown_interfaces_dir).unwrap();
        assert!(IfupdownStore::open(&config).is_err());
    }

    #[test]
    fn protects_default_route_interfaces() {
        let (_temp, config) = fixture();
        let store = IfupdownStore::open(&config).unwrap();
        let error = store
            .assert_not_management_interface(&["eno1", "eth0"])
            .unwrap_err();
        assert!(error.to_string().contains("MANAGEMENT_INTERFACE_PROTECTED"));
        assert!(store.assert_not_management_interface(&["eth1"]).is_err());
        store.assert_not_management_interface(&["eno1"]).unwrap();
    }

    #[test]
    fn validates_kernel_names_vlan_bounds_and_cidr() {
        let mut spec = bridge_spec();
        spec.name = "this-interface-is-too-long".to_string();
        assert!(validate_spec(&spec).is_err());

        spec = InterfaceSpec {
            name: "vlan100".to_string(),
            address: Some("10.0.0.1/99".to_string()),
            kind: InterfaceKind::Vlan {
                parent: "vmbr0".to_string(),
                vid: 100,
            },
        };
        assert!(validate_spec(&spec).is_err());
        spec.address = Some("10.0.0.1/24".to_string());
        assert!(validate_spec(&spec).is_ok());
    }

    #[test]
    fn remove_and_rollback_restore_the_exact_managed_file() {
        let (_temp, config) = fixture();
        let store = IfupdownStore::open(&config).unwrap();
        let spec = bridge_spec();
        store.write_new(&spec).unwrap();
        let before = fs::read(store.path_for("vmbr10").unwrap()).unwrap();
        let snapshot = store.remove("vmbr10").unwrap();
        assert!(!store.path_for("vmbr10").unwrap().exists());
        store.rollback(snapshot).unwrap();
        assert_eq!(fs::read(store.path_for("vmbr10").unwrap()).unwrap(), before);
    }
}
