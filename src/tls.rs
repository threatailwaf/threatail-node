// Dynamic TLS (rustls): certificates are swapped ON THE FLY without a restart.
// On every TLS handshake the resolver reads the SNI and fetches the certificate from a shared
// store (ArcSwap). Policy from the control plane delivers PEM data, which updates the store.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::pki_types::pem::PemObject;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;

/// Certificate store keyed by domain, replaced atomically.
pub type CertStore = Arc<ArcSwap<HashMap<String, Arc<CertifiedKey>>>>;

/// Store of prebuilt per-SNI ServerConfigs, each with the right client verifier.
/// Domains using mTLS get a config with WebPkiClientVerifier(domain CA); others share the default.
pub type ConfigStore = Arc<ArcSwap<HashMap<String, Arc<ServerConfig>>>>;

pub fn empty_config_store() -> ConfigStore {
    Arc::new(ArcSwap::from_pointee(HashMap::new()))
}

/// Build a ServerConfig for a domain that validates the client certificate against
/// the supplied CA (full cryptographic chain validation via rustls/webpki).
#[allow(dead_code)]
pub fn mtls_server_config(
    cert: Arc<CertifiedKey>,
    ca_pem: &str,
    http2: bool,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::server::WebPkiClientVerifier;
    use rustls::RootCertStore;
    // load the CA into the trust root store for client certificates
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(c?)?;
    }
    // The client certificate is REQUESTED but not required at handshake time (allow_unauthenticated):
    // this lets clients without a certificate (browsers, /web) connect, while the requirement is
    // enforced at the HTTP layer by path prefix (site.mtls_locations). A presented but
    // INVALID certificate (not from this CA) still aborts the handshake, so security is preserved.
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .map_err(|e| format!("verifier: {:?}", e))?;
    let resolver = Arc::new(SingleResolver { ck: cert });
    let mut cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    cfg.session_storage = rustls::server::ServerSessionMemoryCache::new(8192);
    Ok(Arc::new(cfg))
}

/// Resolver that always returns a single certificate, used by per-domain configs.
#[derive(Debug)]
#[allow(dead_code)]
struct SingleResolver { ck: Arc<CertifiedKey> }
impl ResolvesServerCert for SingleResolver {
    fn resolve(&self, _hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.ck.clone())
    }
}

/// Resolver that reads the certificate from CertStore by SNI on every handshake.
#[derive(Debug)]
pub struct DynResolver {
    store: CertStore,
}

impl DynResolver {
    pub fn new(store: CertStore) -> Self {
        DynResolver { store }
    }
}

impl ResolvesServerCert for DynResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let map = self.store.load();
        if map.is_empty() {
            return None; // no certificates at all — refuse
        }
        // exact SNI match (case-normalised)
        if let Some(sni) = hello.server_name() {
            let key = sni.to_ascii_lowercase();
            if let Some(ck) = map.get(&key) {
                return Some(ck.clone());
            }
            // wildcard certificate: the key "*.domain.com" covers "foo.domain.com"
            if let Some(dot) = key.find('.') {
                let wildcard = format!("*{}", &key[dot..]);
                if let Some(ck) = map.get(&wildcard) {
                    return Some(ck.clone());
                }
            }
        }
        // fallback: no SNI or no match, so serve any available certificate
        // rather than killing the handshake outright; the client decides based on the name.
        map.values().next().cloned()
    }
}

/// An empty certificate store.
pub fn empty_store() -> CertStore {
    Arc::new(ArcSwap::from_pointee(HashMap::new()))
}

/// Build a ServerConfig with the dynamic resolver; always succeeds, even with no certificates at startup.
pub fn dynamic_server_config(store: CertStore, http2: bool) -> Arc<ServerConfig> {
    let resolver = Arc::new(DynResolver::new(store));
    // the default config has no client authentication. Domains using mTLS get
    // their own per-SNI configs (mtls_server_config), selected in serve_https.
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    // ALPN: h2 (preferred) plus http/1.1 when HTTP/2 is enabled, otherwise 1.1 only
    cfg.alpn_protocols = if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    // session resumption lets a repeat connection skip the full handshake, which matters for
    // mobile clients that reconnect often. In-memory cache of 8192 sessions.
    cfg.session_storage = rustls::server::ServerSessionMemoryCache::new(8192);
    Arc::new(cfg)
}

/// Build a CertifiedKey from PEM strings (certificate + key), for applying policy.
pub fn certified_key_from_pem(
    cert_pem: &str,
    key_pem: &str,
) -> Result<Arc<CertifiedKey>, Box<dyn std::error::Error + Send + Sync>> {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err("no certificates in PEM".into());
    }
    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

// ---- Insecure verifier: does NOT validate the backend certificate ----
// Used ONLY when proxying to trusted internal origins
// (self-signed, or addressed by IP). Never use it for public backends.
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

#[derive(Debug)]
pub struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
