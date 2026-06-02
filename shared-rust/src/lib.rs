//! PMX-Cloud shared agent library (Rust).
//!
//! Implements the same wire contracts as the Go `agents/shared` package.
//! An envelope signed by Go must verify here and vice versa.

pub mod audit;
pub mod capability;
pub mod envelope;
pub mod keyset;
pub mod replay;
pub mod wsclient;
