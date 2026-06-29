//! pmx-updater library — exposed for integration testing.
//!
//! Production entry-point is `main.rs`; this module only re-exports
//! the internal modules so that `tests/*.rs` can reach them.

#![forbid(unsafe_code)]

pub mod agent_update;
pub mod config;
pub mod envelope;
pub mod maintenance;
pub mod os_update;