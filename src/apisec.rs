// apisec.rs — API protection, Phase 1 (OWASP API Security Top 10).
//
// Contains TWO inline gates that behave like the node's other gates:
//   1) Structural JWT validation (partially covers API2: Broken Authentication)
//        - protected paths require Authorization: Bearer <token>
//        - rejects alg = none, empty, or outside the allow-list (guards against the alg=none bypass)
//        - checks exp (expired) and nbf (not yet valid), with configurable leeway
//        - the SIGNATURE is checked when api_jwt_verify_sig=true (HS/RS/ES); otherwise structure and claims only.
//   2) JSON body hygiene (partially covers API4: Unrestricted Resource Consumption)
//        - a body with a JSON content type must be valid JSON
//        - limits on nesting depth, key count, array length and string length
//          (protects against JSON bombs and parser blow-up on the backend)
//
// Each gate can run in log-only (detect) or block mode, like the other hard gates.
// Stateless and key-free. Signature verification (HS256/RS256-JWKS) is a separate phase.

use serde_json::Value;

// ─────────────────────────── site configuration ───────────────────────────

#[derive(Clone, Debug)]
pub struct ApiSecCfg {
    // JWT
    pub jwt_enabled: bool,
    pub jwt_paths: Vec<String>,     // protected path prefixes (empty means presence is not enforced)
    pub jwt_algs: Vec<String>,      // allow-list of algs (lower case), e.g. ["hs256","rs256"]
    pub jwt_require: bool,          // require a token on jwt_paths
    pub jwt_leeway_secs: i64,       // permitted clock leeway for exp/nbf
    pub jwt_logonly: bool,          // true = detect only, never block
    // JWT signature verification (phase 1.5). OFF by default, so production is unaffected.
    pub jwt_verify_sig: bool,       // enable signature verification (otherwise structure and claims only)
    pub jwt_secret: String,         // HS256/384/512: the site's shared secret (empty disables HS)
    pub jwt_jwks_url: String,       // RS*/ES*: JWKS URL (https); keys are fetched by the background refresher
    // JSON hygiene
    pub json_enabled: bool,
    pub json_max_depth: usize,      // 0 = no limit
    pub json_max_keys: usize,       // total number of object keys, 0 = no limit
    pub json_max_array: usize,      // max length of any array, 0 = no limit
    pub json_max_str: usize,        // max length of any string, 0 = no limit
    pub json_require_valid: bool,   // invalid JSON under a JSON content type counts as a violation
    pub json_logonly: bool,
}

impl Default for ApiSecCfg {
    fn default() -> Self {
        ApiSecCfg {
            jwt_enabled: false,
            jwt_paths: Vec::new(),
            jwt_algs: vec!["hs256".into(), "rs256".into(), "es256".into()],
            jwt_require: false,
            jwt_leeway_secs: 60,
            jwt_logonly: true,
            jwt_verify_sig: false,
            jwt_secret: String::new(),
            jwt_jwks_url: String::new(),
            json_enabled: false,
            json_max_depth: 32,
            json_max_keys: 5000,
            json_max_array: 10000,
            json_max_str: 1_048_576,
            json_require_valid: false,
            json_logonly: true,
        }
    }
}

impl ApiSecCfg {
    /// Read the configuration from the site's JSON blob (as delivered by the cloud).
    /// Every field is optional; absence means the default.
    pub fn from_config(c: &Value) -> Self {
        let d = ApiSecCfg::default();
        let s = |k: &str, def: &Vec<String>| -> Vec<String> {
            c.get(k)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_else(|| def.clone())
        };
        let b = |k: &str, def: bool| c.get(k).and_then(|v| v.as_bool()).unwrap_or(def);
        let u = |k: &str, def: usize| c.get(k).and_then(|v| v.as_u64()).map(|x| x as usize).unwrap_or(def);
        let i = |k: &str, def: i64| c.get(k).and_then(|v| v.as_i64()).unwrap_or(def);
        let sc = |k: &str| c.get(k).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();

        let mut algs = s("api_jwt_algs", &d.jwt_algs);
        for a in algs.iter_mut() {
            *a = a.to_ascii_lowercase();
        }
        if algs.is_empty() {
            algs = d.jwt_algs.clone();
        }

        ApiSecCfg {
            jwt_enabled: b("api_jwt_enabled", d.jwt_enabled),
            jwt_paths: s("api_jwt_paths", &d.jwt_paths),
            jwt_algs: algs,
            jwt_require: b("api_jwt_require", d.jwt_require),
            jwt_leeway_secs: i("api_jwt_leeway", d.jwt_leeway_secs).max(0),
            jwt_logonly: b("api_jwt_logonly", d.jwt_logonly),
            jwt_verify_sig: b("api_jwt_verify_sig", d.jwt_verify_sig),
            jwt_secret: sc("api_jwt_secret"),
            jwt_jwks_url: sc("api_jwt_jwks_url"),
            json_enabled: b("api_json_enabled", d.json_enabled),
            json_max_depth: u("api_json_max_depth", d.json_max_depth),
            json_max_keys: u("api_json_max_keys", d.json_max_keys),
            json_max_array: u("api_json_max_array", d.json_max_array),
            json_max_str: u("api_json_max_str", d.json_max_str),
            json_require_valid: b("api_json_require_valid", d.json_require_valid),
            json_logonly: b("api_json_logonly", d.json_logonly),
        }
    }

    #[inline]
    pub fn any_enabled(&self) -> bool {
        self.jwt_enabled || self.json_enabled
    }
}

// ─────────────────────────── gate result ───────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sev {
    Block,
    Detect,
}

#[derive(Clone, Debug)]
pub struct ApiHit {
    pub sig: &'static str, // signature label: "api_jwt" | "api_json"
    pub sev: Sev,          // Block | Detect (log-only)
    pub reason: String,    // human-readable reason for the log or event
}

impl ApiHit {
    fn new(sig: &'static str, logonly: bool, reason: impl Into<String>) -> Self {
        ApiHit {
            sig,
            sev: if logonly { Sev::Detect } else { Sev::Block },
            reason: reason.into(),
        }
    }
}

// ─────────────────────────── public entry point ───────────────────────────

/// Run both gates over the request. Returns the first violation, or None.
/// Called from central.rs AFTER the cheap gates (method, size) and BEFORE proxying.
pub fn check(
    path: &str,
    _method: &str,
    auth_header: Option<&str>,
    content_type: &str,
    body: &[u8],
    cfg: &ApiSecCfg,
    jwks: Option<&crate::jwks::JwksSet>,
) -> Option<ApiHit> {
    if cfg.jwt_enabled {
        if let Some(hit) = check_jwt(path, auth_header, cfg, jwks) {
            return Some(hit);
        }
    }
    if cfg.json_enabled {
        if let Some(hit) = check_json(content_type, body, cfg) {
            return Some(hit);
        }
    }
    None
}

// ─────────────────────────── JWT (structural) ───────────────────────────

fn path_protected(path: &str, paths: &[String]) -> bool {
    paths.iter().any(|p| !p.is_empty() && path.starts_with(p.as_str()))
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn check_jwt(path: &str, auth_header: Option<&str>, cfg: &ApiSecCfg, jwks: Option<&crate::jwks::JwksSet>) -> Option<ApiHit> {
    let protected = path_protected(path, &cfg.jwt_paths);
    // If the path is not in the protected list, the JWT gate leaves it alone.
    if !cfg.jwt_paths.is_empty() && !protected {
        return None;
    }

    // Extract the Bearer token.
    let token = auth_header
        .map(|h| h.trim())
        .and_then(|h| {
            if h.len() >= 7 && h[..7].eq_ignore_ascii_case("bearer ") {
                Some(h[7..].trim())
            } else {
                None
            }
        });

    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            if cfg.jwt_require && protected {
                return Some(ApiHit::new("api_jwt", cfg.jwt_logonly, "missing bearer token"));
            }
            return None; // no token is required, so there is nothing to check
        }
    };

    // A JWT is header.payload.signature; structural checking needs at least 2 segments.
    let mut parts = token.split('.');
    let h_b64 = parts.next().unwrap_or("");
    let p_b64 = parts.next().unwrap_or("");
    let s_b64 = parts.next().unwrap_or("");
    let extra = parts.next();
    if h_b64.is_empty() || p_b64.is_empty() || s_b64.is_empty() || extra.is_some() {
        return Some(ApiHit::new("api_jwt", cfg.jwt_logonly, "malformed jwt"));
    }

    // Header -> alg.
    let header = match b64url_json(h_b64) {
        Some(v) => v,
        None => return Some(ApiHit::new("api_jwt", cfg.jwt_logonly, "bad jwt header")),
    };
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if alg.is_empty() || alg == "none" {
        return Some(ApiHit::new("api_jwt", cfg.jwt_logonly, "alg=none rejected"));
    }
    if !cfg.jwt_algs.is_empty() && !cfg.jwt_algs.iter().any(|a| a == &alg) {
        return Some(ApiHit::new("api_jwt", cfg.jwt_logonly, "alg not allowed"));
    }

    // Payload → exp / nbf.
    let payload = match b64url_json(p_b64) {
        Some(v) => v,
        None => return Some(ApiHit::new("api_jwt", cfg.jwt_logonly, "bad jwt payload")),
    };
    let now = now_secs();
    let leeway = cfg.jwt_leeway_secs;
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        if now > exp + leeway {
            return Some(ApiHit::new("api_jwt", cfg.jwt_logonly, "token expired"));
        }
    }
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64()) {
        if now + leeway < nbf {
            return Some(ApiHit::new("api_jwt", cfg.jwt_logonly, "token not yet valid"));
        }
    }

    // ── phase 1.5: SIGNATURE verification (only when explicitly enabled) ──
    // Production is untouched while api_jwt_verify_sig=false. On failure we honour
    // jwt_logonly, so operators can roll out in detect before enforcing.
    if cfg.jwt_verify_sig {
        let signing_input = format!("{}.{}", h_b64, p_b64);
        let sig = match b64url_decode(s_b64) {
            Some(s) => s,
            None => return Some(ApiHit::new("api_jwt", cfg.jwt_logonly, "bad signature encoding")),
        };
        let kid = header.get("kid").and_then(|v| v.as_str()).unwrap_or("");
        if let Err(reason) = verify_jwt_sig(&alg, signing_input.as_bytes(), &sig, kid, cfg, jwks) {
            return Some(ApiHit::new("api_jwt", cfg.jwt_logonly, reason));
        }
    }
    None
}

/// Verify a JWT signature. HS256/384/512 uses HMAC with the site secret (constant-time).
/// RS*/ES* uses the JWKS public key (by kid) via ring. Returns Err(reason) on failure.
fn verify_jwt_sig(
    alg: &str,
    signing_input: &[u8],
    sig: &[u8],
    kid: &str,
    cfg: &ApiSecCfg,
    jwks: Option<&crate::jwks::JwksSet>,
) -> Result<(), &'static str> {
    match alg {
        "hs256" | "hs384" | "hs512" => {
            if cfg.jwt_secret.is_empty() {
                return Err("hs signature: секрет сайта не задан");
            }
            hmac_verify(alg, cfg.jwt_secret.as_bytes(), signing_input, sig)
        }
        "rs256" | "rs384" | "rs512" | "es256" | "es384" => {
            let set = jwks.ok_or("jwks: ключи ещё не загружены")?;
            let jwk = set.find(kid).ok_or("jwks: ключ по kid не найден")?;
            crate::jwks::verify_asym(alg, jwk, signing_input, sig)
        }
        _ => Err("unsupported alg for signature verify"),
    }
}

/// HMAC verification (constant-time via verify_slice) for HS256/384/512.
fn hmac_verify(alg: &str, key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), &'static str> {
    use hmac::Mac;
    use hmac::KeyInit;
    match alg {
        "hs256" => {
            let mut m = <hmac::Hmac<sha2::Sha256>>::new_from_slice(key).map_err(|_| "hmac key")?;
            m.update(msg);
            m.verify_slice(sig).map_err(|_| "hmac verify failed")
        }
        "hs384" => {
            let mut m = <hmac::Hmac<sha2::Sha384>>::new_from_slice(key).map_err(|_| "hmac key")?;
            m.update(msg);
            m.verify_slice(sig).map_err(|_| "hmac verify failed")
        }
        "hs512" => {
            let mut m = <hmac::Hmac<sha2::Sha512>>::new_from_slice(key).map_err(|_| "hmac key")?;
            m.update(msg);
            m.verify_slice(sig).map_err(|_| "hmac verify failed")
        }
        _ => Err("unsupported hs alg"),
    }
}

/// base64url (unpadded) -> serde_json::Value
fn b64url_json(seg: &str) -> Option<Value> {
    let bytes = b64url_decode(seg)?;
    serde_json::from_slice::<Value>(&bytes).ok()
}

/// Minimal base64url decoder (the -_ alphabet, no '='), with no external crates.
pub(crate) fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4 + 3);
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    for &c in input.as_bytes() {
        if c == b'=' {
            break;
        }
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

// ─────────────────────────── JSON hygiene ───────────────────────────

fn is_json_ct(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.contains("application/json") || ct.contains("+json")
}

/// Whether the body looks like JSON (the first non-whitespace byte is `{` or `[`).
/// This prevents bypassing body validation by declaring a non-JSON Content-Type.
pub fn looks_json(body: &[u8]) -> bool {
    for &b in body {
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            b'{' | b'[' => return true,
            _ => return false,
        }
    }
    false
}

fn check_json(content_type: &str, body: &[u8], cfg: &ApiSecCfg) -> Option<ApiHit> {
    // Content-Type is not trusted: validate when the CT is JSON OR the body looks like JSON.
    if body.is_empty() || (!is_json_ct(content_type) && !looks_json(body)) {
        return None;
    }
    let parsed = serde_json::from_slice::<Value>(body);
    let val = match parsed {
        Ok(v) => v,
        Err(_) => {
            if cfg.json_require_valid {
                return Some(ApiHit::new("api_json", cfg.json_logonly, "invalid json body"));
            }
            return None; // not our concern when validity is not required
        }
    };
    let mut keys = 0usize;
    if let Some(reason) = walk_json(&val, 1, cfg, &mut keys) {
        return Some(ApiHit::new("api_json", cfg.json_logonly, reason));
    }
    None
}

/// Recursive walk with limits. Returns Some(reason) on violation.
fn walk_json(v: &Value, depth: usize, cfg: &ApiSecCfg, keys: &mut usize) -> Option<String> {
    if cfg.json_max_depth != 0 && depth > cfg.json_max_depth {
        return Some(format!("json too deep (> {})", cfg.json_max_depth));
    }
    match v {
        Value::Object(map) => {
            *keys += map.len();
            if cfg.json_max_keys != 0 && *keys > cfg.json_max_keys {
                return Some(format!("too many json keys (> {})", cfg.json_max_keys));
            }
            for (_k, child) in map.iter() {
                if let Some(r) = walk_json(child, depth + 1, cfg, keys) {
                    return Some(r);
                }
            }
        }
        Value::Array(arr) => {
            if cfg.json_max_array != 0 && arr.len() > cfg.json_max_array {
                return Some(format!("json array too long (> {})", cfg.json_max_array));
            }
            for child in arr.iter() {
                if let Some(r) = walk_json(child, depth + 1, cfg, keys) {
                    return Some(r);
                }
            }
        }
        Value::String(s)
            if cfg.json_max_str != 0 && s.len() > cfg.json_max_str => {
                return Some(format!("json string too long (> {})", cfg.json_max_str));
            }
        _ => {}
    }
    None
}

// ─────────────────────────── tests ───────────────────────────

#[cfg(test)]
mod tests {
    // Tests build configs field by field on purpose: it reads closer to the
    // scenario under test than a struct literal with ..Default::default().
    #![allow(clippy::field_reassign_with_default)]
    use super::*;

    fn cfg_jwt() -> ApiSecCfg {
        let mut c = ApiSecCfg::default();
        c.jwt_enabled = true;
        c.jwt_paths = vec!["/api/".into()];
        c.jwt_require = true;
        c.jwt_logonly = false;
        c
    }

    // helper: assemble a token from header/payload JSON (the signature is fake).
    fn mk(header: &str, payload: &str) -> String {
        fn enc(s: &str) -> String {
            // hand-rolled unpadded base64url
            const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let b = s.as_bytes();
            let mut out = String::new();
            let mut i = 0;
            while i < b.len() {
                let b0 = b[i];
                let b1 = if i + 1 < b.len() { b[i + 1] } else { 0 };
                let b2 = if i + 2 < b.len() { b[i + 2] } else { 0 };
                out.push(T[(b0 >> 2) as usize] as char);
                out.push(T[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
                if i + 1 < b.len() {
                    out.push(T[(((b1 & 15) << 2) | (b2 >> 6)) as usize] as char);
                }
                if i + 2 < b.len() {
                    out.push(T[(b2 & 63) as usize] as char);
                }
                i += 3;
            }
            out
        }
        format!("{}.{}.{}", enc(header), enc(payload), "sig")
    }

    #[test]
    fn missing_token_on_protected_path_blocks() {
        let c = cfg_jwt();
        let hit = check_jwt("/api/users", None, &c, None).unwrap();
        assert_eq!(hit.sev, Sev::Block);
    }

    #[test]
    fn unprotected_path_ignored() {
        let c = cfg_jwt();
        assert!(check_jwt("/public/page", None, &c, None).is_none());
    }

    #[test]
    fn alg_none_rejected() {
        let c = cfg_jwt();
        let tok = mk(r#"{"alg":"none","typ":"JWT"}"#, r#"{"sub":"1"}"#);
        let auth = format!("Bearer {}", tok);
        let hit = check_jwt("/api/x", Some(&auth), &c, None).unwrap();
        assert!(hit.reason.contains("alg=none"));
    }

    #[test]
    fn expired_token_rejected() {
        let c = cfg_jwt();
        let tok = mk(r#"{"alg":"HS256"}"#, r#"{"exp":100}"#); // 1970, so long expired
        let auth = format!("Bearer {}", tok);
        let hit = check_jwt("/api/x", Some(&auth), &c, None).unwrap();
        assert!(hit.reason.contains("expired"));
    }

    #[test]
    fn valid_looking_token_passes_structural() {
        let c = cfg_jwt();
        let far = now_secs() + 3600;
        let tok = mk(r#"{"alg":"HS256"}"#, &format!(r#"{{"exp":{}}}"#, far));
        let auth = format!("Bearer {}", tok);
        assert!(check_jwt("/api/x", Some(&auth), &c, None).is_none());
    }

    #[test]
    fn json_depth_limit() {
        let mut c = ApiSecCfg::default();
        c.json_enabled = true;
        c.json_max_depth = 3;
        c.json_logonly = false;
        let body = br#"{"a":{"b":{"c":{"d":1}}}}"#;
        let hit = check_json("application/json", body, &c).unwrap();
        assert!(hit.reason.contains("deep"));
    }

    #[test]
    fn json_array_limit() {
        let mut c = ApiSecCfg::default();
        c.json_enabled = true;
        c.json_max_array = 2;
        c.json_logonly = false;
        let body = br#"[1,2,3,4]"#;
        let hit = check_json("application/json", body, &c).unwrap();
        assert!(hit.reason.contains("array"));
    }

    #[test]
    fn valid_json_passes() {
        let mut c = ApiSecCfg::default();
        c.json_enabled = true;
        let body = br#"{"a":[1,2,3],"b":"ok"}"#;
        assert!(check_json("application/json", body, &c).is_none());
    }

    #[test]
    fn invalid_json_ignored_unless_required() {
        let mut c = ApiSecCfg::default();
        c.json_enabled = true;
        let body = br#"{not json"#;
        assert!(check_json("application/json", body, &c).is_none());
        c.json_require_valid = true;
        assert!(check_json("application/json", body, &c).is_some());
    }
}
