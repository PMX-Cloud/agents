// build.rs — bake the release pubkey hex into the pmx-updater binary.
//
// The 32-byte Ed25519 release public key is provided at build time via the
// RELEASE_PUBKEY_HEX environment variable (64 hex chars). The release workflow
// extracts it from Infra/agents/keys/release-pubkey.pem and exports it for the
// `cargo build --release` step (and Infra/agents/scripts/build-release.sh does
// the same for local verified builds).
//
// When the env var is absent or not a 64-char hex string — local dev builds and
// `cargo test`, which never set it — RELEASE_PUBKEY_HEX is emitted empty and the
// binary skips baked-key verification, falling back to the config-supplied key.
// This mirrors the Go agents, which only receive the pubkey via release-time
// ldflags and never bake it during `go test`.

fn main() {
    println!("cargo:rerun-if-env-changed=RELEASE_PUBKEY_HEX");
    println!("cargo:rerun-if-changed=build.rs");

    let hex = std::env::var("RELEASE_PUBKEY_HEX")
        .ok()
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_default();

    if hex.is_empty() {
        println!("cargo:warning=RELEASE_PUBKEY_HEX not set — baked-key verification disabled (dev/test build)");
    }

    println!("cargo:rustc-env=RELEASE_PUBKEY_HEX={hex}");
}
