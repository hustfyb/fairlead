//! TLS client configuration: system roots, certificate pinning, or insecure.

use std::sync::Arc;

use anyhow::{anyhow, Context};
use fairlead_proto::ALPN;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::config::{AgentConfig, TlsMode};

pub struct ClientTls {
    pub config: Arc<rustls::ClientConfig>,
    pub server_name: ServerName<'static>,
}

pub fn build(cfg: &AgentConfig, host: &str) -> anyhow::Result<ClientTls> {
    let server_name = match &cfg.tls.server_name {
        Some(name) => ServerName::try_from(name.clone()).map_err(|e| anyhow!("bad tls.server_name: {e}"))?,
        None => ServerName::try_from(host.to_string()).map_err(|e| anyhow!("bad server host {host}: {e}"))?,
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("rustls versions")?;

    let mut config = match cfg.tls.mode {
        TlsMode::System => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        TlsMode::Pin => {
            let pin = parse_pin(cfg.tls.pin_sha256.as_deref().unwrap_or_default())?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pin, provider }))
                .with_no_client_auth()
        }
        TlsMode::Insecure => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify { provider }))
            .with_no_client_auth(),
    };
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(ClientTls { config: Arc::new(config), server_name })
}

fn parse_pin(raw: &str) -> anyhow::Result<[u8; 32]> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();
    let bytes = hex::decode(&cleaned).context("tls.pin_sha256 must be hex")?;
    anyhow::ensure!(bytes.len() == 32, "tls.pin_sha256 must be a sha256 (32 bytes)");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut h = Sha256::new();
        h.update(end_entity.as_ref());
        let got = h.finalize();
        if got.as_slice() == self.pin.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct NoVerify {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
