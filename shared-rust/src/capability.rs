//! Capability registry for Rust agents.
//!
//! Mirrors the Go `agents/shared/capability` package so that every agent
//! (regardless of language) can declare its command set at boot and respond
//! to `*.capabilities` queries from the backend.
//!
//! # Example
//!
//! ```
//! use pmx_shared::capability::{Registry, Stability, declare};
//!
//! declare("pmx-network", "network.bridge.create", 1, Stability::Stable);
//! declare("pmx-network", "network.vlan.delete", 1, Stability::Beta);
//!
//! let caps = Registry::global().list();
//! assert_eq!(caps.len(), 2);
//! assert!(Registry::global().has("network.bridge.create"));
//! ```

use std::fmt;
use std::sync::{LazyLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// How mature a capability is. Mirrors Go `capability.Stability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stability {
    Stable,
    Beta,
    Deprecated,
}

impl fmt::Display for Stability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Stability {
    /// Convert to the string representation used in JSON / CBOR payloads.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Deprecated => "deprecated",
        }
    }
}

/// A single command that an agent class supports. Mirrors Go `capability.Capability`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub command: String,
    pub version: u32,
    pub stability: Stability,
    pub agent_class: String,
}

impl Capability {
    pub fn new(agent_class: &str, command: &str, version: u32, stability: Stability) -> Self {
        Self {
            command: command.to_owned(),
            version,
            stability,
            agent_class: agent_class.to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Thread-safe store of [`Capability`] values.
///
/// The global instance is the primary entry point; per-agent registries can be
/// created with [`Registry::new`] for testing.
pub struct Registry {
    inner: RwLock<RegistryInner>,
}

#[derive(Default)]
struct RegistryInner {
    store: std::collections::BTreeMap<String, Capability>,
}

impl Registry {
    /// Create a new empty registry (useful for tests).
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(RegistryInner::default()),
        }
    }

    /// Access the process-global registry.
    pub fn global() -> &'static Self {
        static GLOBAL: LazyLock<Registry> = LazyLock::new(Registry::new);
        &GLOBAL
    }

    /// Register a capability.
    ///
    /// # Panics
    ///
    /// Panics if the same command is declared with a different `agent_class`
    /// (programming error — two different agents claiming the same command).
    /// Idempotent when called with the same value.
    pub fn declare(&self, cap: Capability) {
        let mut guard = self.write();
        if let Some(existing) = guard.store.get(&cap.command) {
            if existing.agent_class != cap.agent_class {
                panic!(
                    "capability: command {:?} already declared by agent class {:?}; \
                     cannot re-declare for {:?}",
                    cap.command, existing.agent_class, cap.agent_class
                );
            }
        }
        guard.store.insert(cap.command.clone(), cap);
    }

    /// Return a sorted (by command name) snapshot of all registered capabilities.
    pub fn list(&self) -> Vec<Capability> {
        let guard = self.read();
        guard.store.values().cloned().collect()
    }

    /// Report whether a command (case-sensitive) is registered.
    pub fn has(&self, command: &str) -> bool {
        let guard = self.read();
        guard.store.contains_key(command)
    }

    /// Report whether the given `agent_class` has registered the command.
    pub fn has_from(&self, agent_class: &str, command: &str) -> bool {
        let guard = self.read();
        guard
            .store
            .get(command)
            .is_some_and(|c| c.agent_class == agent_class)
    }

    // -- helpers to avoid repeating .inner.read/write everywhere -------

    fn read(&self) -> RwLockReadGuard<'_, RegistryInner> {
        self.inner.read().expect("capability registry lock poisoned")
    }

    fn write(&self) -> RwLockWriteGuard<'_, RegistryInner> {
        self.inner.write().expect("capability registry lock poisoned")
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Convenience free functions (mirror Go package-level `Declare` / `List`)
// ---------------------------------------------------------------------------

/// Shorthand for `Registry::global().declare(…)`.
pub fn declare(agent_class: &str, command: &str, version: u32, stability: Stability) {
    Registry::global().declare(Capability::new(agent_class, command, version, stability));
}

/// Shorthand for `Registry::global().list()`.
pub fn list() -> Vec<Capability> {
    Registry::global().list()
}

/// Shorthand for `Registry::global().has(command)`.
pub fn has(command: &str) -> bool {
    Registry::global().has(command)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declare_and_list() {
        let reg = Registry::new();
        reg.declare(Capability::new("pmx-test", "test.ping", 1, Stability::Stable));
        reg.declare(Capability::new("pmx-test", "test.pong", 2, Stability::Beta));

        let caps = reg.list();
        assert_eq!(caps.len(), 2);
        // BTreeMap → sorted by command
        assert_eq!(caps[0].command, "test.ping");
        assert_eq!(caps[1].command, "test.pong");
    }

    #[test]
    fn declare_idempotent() {
        let reg = Registry::new();
        reg.declare(Capability::new("pmx-test", "test.ping", 1, Stability::Stable));
        reg.declare(Capability::new("pmx-test", "test.ping", 1, Stability::Stable));
        assert_eq!(reg.list().len(), 1);
    }

    #[test]
    #[should_panic(expected = "already declared by agent class")]
    fn declare_conflict_panics() {
        let reg = Registry::new();
        reg.declare(Capability::new("pmx-test", "test.ping", 1, Stability::Stable));
        reg.declare(Capability::new("pmx-other", "test.ping", 1, Stability::Stable));
    }

    #[test]
    fn has_and_has_from() {
        let reg = Registry::new();
        reg.declare(Capability::new("pmx-test", "test.ping", 1, Stability::Stable));

        assert!(reg.has("test.ping"));
        assert!(!reg.has("test.missing"));
        assert!(reg.has_from("pmx-test", "test.ping"));
        assert!(!reg.has_from("pmx-other", "test.ping"));
    }

    #[test]
    fn stability_as_str() {
        assert_eq!(Stability::Stable.as_str(), "stable");
        assert_eq!(Stability::Beta.as_str(), "beta");
        assert_eq!(Stability::Deprecated.as_str(), "deprecated");
    }

    #[test]
    fn global_registry_works() {
        // The global registry is shared across the process, but we can still
        // test basic operations. We use a unique command prefix to avoid
        // colliding with other tests.
        let prefix = "capability_test_global_";
        let cmd = format!("{prefix}ping");

        Registry::global().declare(Capability::new("pmx-test", &cmd, 1, Stability::Stable));
        assert!(Registry::global().has(&cmd));
        assert!(Registry::global().has_from("pmx-test", &cmd));
    }

    #[test]
    fn free_function_declare() {
        let prefix = "capability_test_fn_";
        let cmd = format!("{prefix}echo");

        declare("pmx-test", &cmd, 1, Stability::Beta);
        assert!(has(&cmd));
    }
}