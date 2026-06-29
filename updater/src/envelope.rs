use anyhow::{Context, Result, bail};
use pmx_shared::envelope::Envelope;
use pmx_shared::keyset::KeySet;
use pmx_shared::replay::ReplayCache;
use std::fs;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

pub const AGENT_CLASS: &str = "pmx-updater";

/// Process-wide replay cache so that duplicate job IDs are rejected across
/// successive `read_and_verify_envelope` calls.  Capacity 8 entries, 2 h TTL
/// mirrors the Go-side defaults.  Wrapped in a Mutex so that mutations
/// (remembering seen job IDs) persist across calls.
static REPLAY: OnceLock<Mutex<ReplayCache>> = OnceLock::new();

fn replay_cache() -> &'static Mutex<ReplayCache> {
    REPLAY.get_or_init(|| Mutex::new(ReplayCache::new(8, Duration::from_secs(2 * 60 * 60))))
}

/// Result of envelope verification, including which key signed it.
///
/// Key index 0 = release key (Key 1, offline-custody YubiKey).
/// Key index ≥1 = job envelope key (Key 2, AWS KMS).
#[derive(Debug)]
pub struct VerifiedEnvelope {
    pub envelope: Envelope,
    /// Index into the keyset file of the key that verified the signature.
    /// 0 = release key, ≥1 = job key.
    pub signing_key_index: usize,
}

pub fn read_and_verify_envelope(
    stdin: &[u8],
    keyset_path: &str,
    host_fingerprint_path: &str,
) -> Result<VerifiedEnvelope> {
    if stdin.is_empty() {
        bail!("empty envelope on stdin");
    }

    let env = Envelope::from_cbor(stdin).map_err(anyhow::Error::msg)?;
    let keyset_raw = fs::read_to_string(keyset_path)
        .with_context(|| format!("read keyset {}", keyset_path))?;
    let keyset = KeySet::parse(&keyset_raw).map_err(anyhow::Error::msg)?;
    let host_fingerprint = fs::read_to_string(host_fingerprint_path)
        .with_context(|| format!("read host fingerprint {}", host_fingerprint_path))?
        .trim()
        .to_string();
    if host_fingerprint.is_empty() {
        bail!("host fingerprint file is empty");
    }

    // Lock the process-wide singleton so replays are caught across calls.
    let mut replay = replay_cache().lock().expect("replay cache mutex poisoned");
    let key_index = env
        .verify_identifying(&keyset.active_keys(), AGENT_CLASS, &host_fingerprint, &mut replay)
        .map_err(anyhow::Error::msg)?;

    Ok(VerifiedEnvelope {
        envelope: env,
        signing_key_index: key_index,
    })
}
