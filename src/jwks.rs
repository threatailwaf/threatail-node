// jwks.rs — JWKS cache and asymmetric JWT signature verification (RS*/ES*) for apisec.
//
// The keys are public, so they are cached in a shared map (url -> key set) and refreshed by a
// background task (see main.rs). Verification is synchronous CPU work via ring; network access
// happens only in the refresher. HS* is not here — it lives in apisec.rs (site secret, no network).

use std::sync::{Arc, OnceLock};
use serde::Deserialize;

/// A single JWKS key. Unset fields are empty strings (base64url without padding).
#[derive(Clone, Debug, Deserialize, Default)]
pub struct Jwk {
    #[serde(default)] pub kid: String,
    #[serde(default)] pub kty: String, // "RSA" | "EC"
    #[serde(default)] #[allow(dead_code)] pub alg: String,
    #[serde(default)] #[allow(dead_code)] pub crv: String, // EC: "P-256" | "P-384"
    #[serde(default)] pub n: String,   // RSA modulus
    #[serde(default)] pub e: String,   // RSA exponent
    #[serde(default)] pub x: String,   // EC x
    #[serde(default)] pub y: String,   // EC y
}

#[derive(Clone, Debug, Default)]
pub struct JwksSet {
    pub keys: Vec<Jwk>,
}

impl JwksSet {
    /// Find a key by kid. If kid is empty and the set holds exactly one key, use that key.
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        if kid.is_empty() {
            return if self.keys.len() == 1 { self.keys.first() } else { None };
        }
        self.keys.iter().find(|k| k.kid == kid)
    }
}

#[derive(Deserialize)]
struct JwksDoc {
    #[serde(default)]
    keys: Vec<Jwk>,
}

fn cache() -> &'static dashmap::DashMap<String, Arc<JwksSet>> {
    static C: OnceLock<dashmap::DashMap<String, Arc<JwksSet>>> = OnceLock::new();
    C.get_or_init(dashmap::DashMap::new)
}

/// Get the cached key set for a URL, or None if it has not been fetched yet.
pub fn get(url: &str) -> Option<Arc<JwksSet>> {
    if url.is_empty() {
        return None;
    }
    cache().get(url).map(|v| v.clone())
}

fn store(url: &str, set: JwksSet) {
    cache().insert(url.to_string(), Arc::new(set));
}

/// Fetch or refresh JWKS from a URL. https only, and the host must resolve to a public address (anti-SSRF).
/// The client is supplied by the caller (redirects disabled, timeout set). true = refreshed.
pub async fn refresh(url: &str, client: &reqwest::Client) -> bool {
    if !url.starts_with("https://") {
        tracing::warn!("jwks: пропуск {} — требуется https", url);
        return false;
    }
    if !host_resolves_public(url).await {
        tracing::warn!("jwks: пропуск {} — хост резолвится во внутренний адрес (SSRF-guard)", url);
        return false;
    }
    match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<JwksDoc>().await {
            Ok(doc) if !doc.keys.is_empty() => {
                let n = doc.keys.len();
                store(url, JwksSet { keys: doc.keys });
                tracing::info!("jwks: обновлено {} ({} ключей)", url, n);
                true
            }
            _ => {
                tracing::warn!("jwks: {} — пустой/некорректный набор ключей", url);
                false
            }
        },
        Ok(resp) => {
            tracing::warn!("jwks: {} — HTTP {}", url, resp.status());
            false
        }
        Err(e) => {
            tracing::warn!("jwks: {} — {}", url, e);
            false
        }
    }
}

/// Anti-SSRF: the URL host must resolve to public addresses ONLY.
async fn host_resolves_public(url: &str) -> bool {
    let rest = match url.strip_prefix("https://") {
        Some(r) => r,
        None => return false,
    };
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = hostport.rsplit('@').next().unwrap_or(hostport);
    let (host, port) = if let Some(r6) = hostport.strip_prefix('[') {
        let h = r6.split(']').next().unwrap_or("").to_string();
        let p = r6.rsplit(']').next().and_then(|s| s.strip_prefix(':')).and_then(|s| s.parse::<u16>().ok());
        (h, p.unwrap_or(443))
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(443))
    } else {
        (hostport.to_string(), 443)
    };
    if host.is_empty() {
        return false;
    }
    let ok = match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            !addrs.is_empty() && addrs.iter().all(|a| ip_public(&a.ip()))
        }
        Err(_) => false,
    };
    ok
}

fn ip_public(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()   // 169.254/16 (metadata)
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 0)
        }
        std::net::IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || ((v6.segments()[0] & 0xfe00) == 0xfc00)  // fc00::/7 ULA
                || ((v6.segments()[0] & 0xffc0) == 0xfe80))  // fe80::/10 link-local
        }
    }
}

/// Verify an asymmetric signature (RS256/384/512, ES256/384) via ring.
pub fn verify_asym(alg: &str, jwk: &Jwk, msg: &[u8], sig: &[u8]) -> Result<(), &'static str> {
    use ring::signature;
    match alg {
        "rs256" | "rs384" | "rs512" => {
            if !jwk.kty.eq_ignore_ascii_case("RSA") {
                return Err("jwks: kty != RSA для RS-алгоритма");
            }
            let n = crate::apisec::b64url_decode(&jwk.n).ok_or("jwks: плохой modulus")?;
            let e = crate::apisec::b64url_decode(&jwk.e).ok_or("jwks: плохой exponent")?;
            let pk = signature::RsaPublicKeyComponents { n: &n, e: &e };
            let r = match alg {
                "rs256" => pk.verify(&signature::RSA_PKCS1_2048_8192_SHA256, msg, sig),
                "rs384" => pk.verify(&signature::RSA_PKCS1_2048_8192_SHA384, msg, sig),
                _ => pk.verify(&signature::RSA_PKCS1_2048_8192_SHA512, msg, sig),
            };
            r.map_err(|_| "rsa signature verify failed")
        }
        "es256" | "es384" => {
            if !jwk.kty.eq_ignore_ascii_case("EC") {
                return Err("jwks: kty != EC для ES-алгоритма");
            }
            // coordinate size for the curve; a JWT ES signature is fixed-width r||s
            let coord: usize = if alg == "es256" { 32 } else { 48 };
            let x = crate::apisec::b64url_decode(&jwk.x).ok_or("jwks: плохой x")?;
            let y = crate::apisec::b64url_decode(&jwk.y).ok_or("jwks: плохой y")?;
            let xp = left_pad(&x, coord).ok_or("jwks: x длиннее кривой")?;
            let yp = left_pad(&y, coord).ok_or("jwks: y длиннее кривой")?;
            let mut point = Vec::with_capacity(1 + 2 * coord);
            point.push(0x04); // uncompressed
            point.extend_from_slice(&xp);
            point.extend_from_slice(&yp);
            let r = if alg == "es256" {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &point).verify(msg, sig)
            } else {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &point).verify(msg, sig)
            };
            r.map_err(|_| "ecdsa signature verify failed")
        }
        _ => Err("unsupported asym alg"),
    }
}

/// Left-pad with zeros to the required length, or None if already longer.
fn left_pad(b: &[u8], want: usize) -> Option<Vec<u8>> {
    if b.len() > want {
        // tolerate a leading zero byte, which some encoders add
        if b.len() == want + 1 && b[0] == 0 {
            return Some(b[1..].to_vec());
        }
        return None;
    }
    let mut out = vec![0u8; want - b.len()];
    out.extend_from_slice(b);
    Some(out)
}
