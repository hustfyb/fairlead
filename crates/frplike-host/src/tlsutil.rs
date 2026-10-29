//! TLS material for the agent tunnel listener.

use std::io::BufReader;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use frplike_proto::ALPN;
use sha2::{Digest, Sha256};

use crate::config::HostConfig;

pub struct ServerTls {
    pub config: Arc<rustls::ServerConfig>,
    /// SHA-256 of the leaf certificate, lowercase hex. Agents using pin mode
    /// compare against this.
    pub fingerprint: String,
    pub source: &'static str,
}

pub fn build(cfg: &HostConfig) -> anyhow::Result<ServerTls> {
    let (certs, key, fingerprint, source) = match (&cfg.tls.cert, &cfg.tls.key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read(cert_path)
                .with_context(|| format!("read tls.cert {}", cert_path.display()))?;
            let key_pem =
                std::fs::read(key_path).with_context(|| format!("read tls.key {}", key_path.display()))?;
            let certs = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_slice()))
                .collect::<Result<Vec<_>, _>>()
                .context("parse tls.cert")?;
            if certs.is_empty() {
                return Err(anyhow!("tls.cert contains no certificates"));
            }
            let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_slice()))
                .context("parse tls.key")?
                .ok_or_else(|| anyhow!("tls.key contains no private key"))?;
            let fp = fingerprint(&certs[0]);
            (certs, key, fp, "file")
        }
        (None, None) if cfg.tls.dev_self_signed => {
            let mut names = vec!["localhost".to_string()];
            for s in &cfg.server.allowed_suffixes {
                names.push(s.clone());
                names.push(format!("*.{s}"));
            }
            let generated = rcgen::generate_simple_self_signed(names).context("generate dev certificate")?;
            let der = generated.cert.der().clone();
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()),
            );
            let fp = fingerprint(&der);
            (vec![der], key, fp, "dev-self-signed")
        }
        _ => {
            return Err(anyhow!(
                "tls.cert and tls.key must both be set, or set tls.dev_self_signed = true for development"
            ))
        }
    };

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build rustls server config")?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(ServerTls { config: Arc::new(config), fingerprint, source })
}

fn fingerprint(cert: &rustls::pki_types::CertificateDer<'_>) -> String {
    let mut h = Sha256::new();
    h.update(cert.as_ref());
    hex::encode(h.finalize())
}
