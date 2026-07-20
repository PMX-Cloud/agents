//! Outbound-only WebSocket client — mirrors agents/shared/wsclient/client.go.
//!
//! Used by `pmx-network` and `pmx-updater` (the two Rust agents).

use crate::envelope::Envelope;
use crate::keyset::KeySet;
use crate::replay::ReplayCache;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tokio_tungstenite::{connect_async_tls_with_config, Connector};
use tracing::{error, info, warn};

pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
pub const DEFAULT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(45);
pub const BACKOFF_MIN: Duration = Duration::from_secs(5);
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
pub const PROTOCOL_VERSION: &str = "pmx-agent-v1";

/// Implemented by each domain agent to handle inbound commands.
#[async_trait::async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn on_envelope(&self, env: Envelope) -> Result<Option<Vec<u8>>, String>;
    async fn on_connect(&self) -> Result<(), String>;
}

/// Configuration for the WebSocket client.
pub struct Config {
    /// Must start with `wss://`.
    pub backend_url: String,
    pub agent_class: String,
    pub auth_token: Option<String>,
    pub cert_path: String,
    pub key_path: String,
    pub keyset: Arc<KeySet>,
    pub replay: ReplayCache,
    pub host_fingerprint: String,
    pub heartbeat_interval: Duration,
    pub handler: Arc<dyn Handler>,
}

/// Run the WebSocket client, reconnecting with exponential backoff.
/// Blocks until the provided `shutdown` future resolves.
pub async fn run(cfg: Config, mut shutdown: impl std::future::Future<Output = ()> + Unpin) {
    let mut backoff = BACKOFF_MIN;
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("wsclient: shutdown signal received");
                return;
            }
            result = run_once(&cfg) => {
                match result {
                    Ok(_) => info!("wsclient: connection closed cleanly"),
                    Err(e) => warn!("wsclient: connection error: {}", e),
                }
            }
        }

        info!("wsclient: reconnecting in {:?}", backoff);
        sleep(backoff).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

async fn run_once(cfg: &Config) -> Result<(), String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::header::{HeaderValue, AUTHORIZATION};

    let url = build_backend_url(&cfg.backend_url, &cfg.agent_class);
    let mut request = url
        .clone()
        .into_client_request()
        .map_err(|e| format!("build request: {}", e))?;
    request.headers_mut().insert(
        "X-Agent-Class",
        HeaderValue::from_str(&cfg.agent_class)
            .map_err(|e| format!("agent class header: {}", e))?,
    );
    if let Some(token) = cfg
        .auth_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        request.headers_mut().insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token))
                .map_err(|e| format!("authorization header: {}", e))?,
        );
        request.headers_mut().insert(
            "X-License-Key",
            HeaderValue::from_str(token).map_err(|e| format!("license header: {}", e))?,
        );
    }

    let tls_connector = build_tls_connector(cfg)?;
    let (ws_stream, _) = connect_async_tls_with_config(request, None, false, tls_connector)
        .await
        .map_err(|e| format!("dial: {}", e))?;

    info!("wsclient: connected to {}", url);
    let hostname = get_hostname();
    let register_payload = serde_json::json!({
        "version": PROTOCOL_VERSION,
        "type": "agent.register",
        "timestamp": chrono::Utc::now().timestamp_millis(),
        "payload": {
            "hostname": hostname,
            "agentVersion": "unknown",
            "agentClass": cfg.agent_class,
            "hostFingerprint": cfg.host_fingerprint,
            "capabilities": [],
        },
    });

    cfg.handler
        .on_connect()
        .await
        .map_err(|e| format!("on_connect: {}", e))?;

    let (mut write, mut read) = ws_stream.split();
    write
        .send(tokio_tungstenite::tungstenite::Message::Text(
            register_payload.to_string(),
        ))
        .await
        .map_err(|e| format!("register send: {}", e))?;
    let interval = cfg.heartbeat_interval;

    let mut heartbeat = tokio::time::interval(interval);

    let mut replay = cfg.replay.clone();

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let payload = serde_json::json!({
                    "version": PROTOCOL_VERSION,
                    "type": "agent.heartbeat",
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                    "payload": {
                        "agentClass": cfg.agent_class,
                    }
                });
                let msg = tokio_tungstenite::tungstenite::Message::Text(
                    payload.to_string(),
                );
                write.send(msg).await.map_err(|e| format!("heartbeat send: {}", e))?;
            }
            msg = read.next() => {
                match msg {
                    None => return Ok(()),
                    Some(Err(e)) => return Err(format!("read: {}", e)),
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data))) => {
                        match Envelope::from_cbor(&data) {
                            Err(e) => {
                                warn!("wsclient: reject: not a valid envelope: {}", e);
                                continue;
                            }
                            Ok(env) => {
                                let keys = cfg.keyset.active_keys();
                                if let Err(e) = env.verify(&keys, &cfg.agent_class, &cfg.host_fingerprint, &mut replay) {
                                    warn!("wsclient: reject: {}", e);
                                    continue;
                                }
                                // Backpressure: await handler before reading next frame.
                                match cfg.handler.on_envelope(env).await {
                                    Ok(Some(result)) => {
                                        let msg = tokio_tungstenite::tungstenite::Message::Binary(result);
                                        write.send(msg).await.map_err(|e| format!("send result: {}", e))?;
                                    }
                                    Ok(None) => {}
                                    Err(e) => error!("wsclient: handler error: {}", e),
                                }
                            }
                        }
                    }
                    Some(Ok(_)) => {
                        // Non-binary frames (text, ping, pong) are ignored.
                    }
                }
            }
        }
    }
}

fn build_backend_url(backend_url: &str, agent_class: &str) -> String {
    let trimmed = backend_url.trim_end_matches('/');
    if trimmed.ends_with(&format!("/{}", agent_class)) {
        return trimmed.to_string();
    }
    if let Some(short_class) = agent_class.strip_prefix("pmx-") {
        if trimmed.ends_with(&format!("/{}", short_class)) {
            return trimmed.to_string();
        }
    }
    format!("{}/{}", trimmed, agent_class)
}

fn build_tls_connector(cfg: &Config) -> Result<Option<Connector>, String> {
    let cert = cfg.cert_path.trim();
    let key = cfg.key_path.trim();

    if cert.is_empty() && key.is_empty() {
        return Ok(None);
    }
    if cert.is_empty() || key.is_empty() {
        return Err("mTLS identity requires both cert_path and key_path".to_string());
    }

    // Trust the host's native root CA store (same trust anchors native-tls used).
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs()
        .map_err(|e| format!("load native root certs: {}", e))?;
    for ca in native {
        roots
            .add(ca)
            .map_err(|e| format!("add native root cert: {}", e))?;
    }

    // Present the client cert chain + private key for mTLS.
    let cert_chain = load_cert_chain(cert)?;
    let key_der = load_private_key(key)?;

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key_der)
        .map_err(|e| format!("build rustls client config: {}", e))?;

    Ok(Some(Connector::Rustls(Arc::new(config))))
}

/// Load a PEM certificate chain (leaf + any intermediates) as DER.
fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = fs::read(path).map_err(|e| format!("read cert_path {}: {}", path, e))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs from {}: {}", path, e))
}

/// Load a PEM private key (PKCS#8, PKCS#1, or SEC1) as DER.
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let data = fs::read(path).map_err(|e| format!("read key_path {}: {}", path, e))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("parse private key from {}: {}", path, e))?
        .ok_or_else(|| format!("no private key found in {}", path))
}

fn get_hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unknown-host".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn backend_url_accepts_short_class_suffix() {
        let built = build_backend_url("wss://api.example/ws/agent/network", "pmx-network");
        assert_eq!(built, "wss://api.example/ws/agent/network");
    }

    #[test]
    fn backend_url_appends_agent_class_when_base_is_provided() {
        let built = build_backend_url("wss://api.example/ws/agent", "pmx-network");
        assert_eq!(built, "wss://api.example/ws/agent/pmx-network");
    }

    #[test]
    fn tls_connector_requires_both_identity_paths() {
        let cfg = Config {
            backend_url: "wss://api.example/ws/agent/network".to_string(),
            agent_class: "pmx-network".to_string(),
            auth_token: None,
            cert_path: "/tmp/cert.pem".to_string(),
            key_path: "".to_string(),
            keyset: test_keyset(),
            replay: ReplayCache::new(8, Duration::from_secs(60)),
            host_fingerprint: "abc".to_string(),
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            handler: Arc::new(NoopHandler {}),
        };
        let result = build_tls_connector(&cfg);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        };
        assert!(err.contains("both cert_path and key_path"));
    }

    struct NoopHandler;
    #[async_trait::async_trait]
    impl Handler for NoopHandler {
        async fn on_envelope(&self, _env: Envelope) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
        async fn on_connect(&self) -> Result<(), String> {
            Ok(())
        }
    }

    fn test_keyset() -> Arc<KeySet> {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey_hex = hex::encode(signing.verifying_key().to_bytes());
        Arc::new(KeySet::parse(&pubkey_hex).expect("parse test keyset"))
    }
}
