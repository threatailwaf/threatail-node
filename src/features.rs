// Single feature extractor for the supervised ML model (LightGBM).
// STRICTLY mirrors ml/FEATURES.md and ml/features.py. Any divergence
// breaks inference. FEATURE_VERSION must match the Python side.

pub const FEATURE_VERSION: u32 = 5; // v5: adds expand_base64, reusing the tested implementation from verdict
pub const N_FEATURES: usize = 36;

/// Context features (fingerprint/header) are computed on the node at request time and stored
/// alongside the sample, since they cannot be reconstructed from path/query/body. In stage 1 they are NOT part of
/// extract()/N_FEATURES and do not affect inference; they merely accumulate in the dataset. Stage 2 (a version bump)
/// will concatenate them with the content features. The order MUST match CONTEXT_NAMES in features.py.
pub const N_CONTEXT: usize = 6;
#[allow(dead_code)] // used in stage 2, and keeps name parity with features.py
pub const CONTEXT_NAMES: [&str; N_CONTEXT] = [
    "ctx_ja3_present", "ctx_tls_ua_mismatch", "ctx_ua_empty",
    "ctx_ua_tool", "ctx_no_browser_headers", "ctx_no_referer",
];

/// Pack stateless fingerprint/header signals into a context vector (bool -> f32).
/// The signals themselves come from the pipeline (bot::header_signals plus ja3/grease from the connection).
pub fn context(ja3_present: bool, tls_ua_mismatch: bool, ua_empty: bool,
               ua_tool: bool, no_browser_headers: bool, no_referer: bool) -> [f32; N_CONTEXT] {
    [
        ja3_present as u8 as f32,
        tls_ua_mismatch as u8 as f32,
        ua_empty as u8 as f32,
        ua_tool as u8 as f32,
        no_browser_headers as u8 as f32,
        no_referer as u8 as f32,
    ]
}

// Keyword dictionaries (lower case, substring match).
const KW_SQL: &[&str] = &[
    "union", "select", "insert", "update", "delete", "drop", "from", "where",
    "or 1=1", "sleep(", "benchmark(", "'--", "' or ", "waitfor", "xp_",
    "information_schema",
];
const KW_XSS: &[&str] = &[
    "<script", "javascript:", "onerror", "onload", "onmouseover", "<svg",
    "<img", "document.cookie", "alert(", "eval(", "fromcharcode",
];
const KW_PATH: &[&str] = &[
    "../", "..\\", "%2e%2e", "/etc/passwd", "/proc/", "php://", "file://",
    "/windows/win.ini", "/.git", "/.env",
];
const KW_CMD: &[&str] = &[
    ";cat ", ";ls ", ";id", "|cat ", "`", "$(", "&&", "wget ", "curl ",
    "nc ", "/bin/sh", "/bin/bash", "${jndi:",
];

/// Single-pass percent decoding. Malformed sequences are left as they are.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let h = hex_val(b[i + 1]);
            let l = hex_val(b[i + 2]);
            if let (Some(h), Some(l)) = (h, l) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        if b[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(b[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ─── v4: payload normalisation before feature extraction (anti encoding-bypass) ───
// STRICTLY mirrors features.py (_recursive_percent_decode / _html_decode / normalize).
// Parity is verified by golden.json (features_match_python_golden).

/// Percent-decode until stable (double or triple encoding), at most 3 passes.
fn recursive_percent_decode(s: &str) -> String {
    let mut cur = s.to_string();
    for _ in 0..3 {
        let d = percent_decode(&cur);
        if d == cur { break; }
        cur = d;
    }
    cur
}

/// A minimal fixed table of named entities (the same set as in features.py).
const HTML_ENT: &[(&str, char)] = &[
    ("lt", '<'), ("gt", '>'), ("amp", '&'), ("quot", '"'), ("apos", '\''),
];

/// Decodes &lt;/&gt;/&amp;/&quot;/&apos; and numeric &#DDD; / &#xHH;. Everything else is left as is.
/// Code point range follows char::from_u32 (<=0x10FFFF, no surrogates), matching Python.
fn html_decode(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let cs: Vec<char> = s.chars().collect();
    let n = cs.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < n {
        if cs[i] == '&' {
            let end = (i + 12).min(n);
            let mut semi = None;
            let mut j = i + 1;
            while j < end {
                if cs[j] == ';' { semi = Some(j); break; }
                j += 1;
            }
            if let Some(semi) = semi {
                let ent: String = cs[i + 1..semi].iter().collect();
                let mut dec: Option<char> = None;
                if let Some(num) = ent.strip_prefix('#') {
                    let cp: Option<u32> = if num.starts_with('x') || num.starts_with('X') {
                        let hx = &num[1..];
                        if !hx.is_empty() && hx.chars().all(|c| c.is_ascii_hexdigit()) {
                            u32::from_str_radix(hx, 16).ok()
                        } else {
                            None
                        }
                    } else if !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) {
                        num.parse::<u32>().ok()
                    } else {
                        None
                    };
                    if let Some(cp) = cp {
                        if cp <= 0x10FFFF && !(0xD800..=0xDFFF).contains(&cp) {
                            dec = char::from_u32(cp);
                        }
                    }
                } else if let Some(&(_, ch)) = HTML_ENT.iter().find(|(k, _)| *k == ent) {
                    dec = Some(ch);
                }
                if let Some(d) = dec {
                    out.push(d);
                    i = semi + 1;
                    continue;
                }
            }
        }
        out.push(cs[i]);
        i += 1;
    }
    out
}

/// Unwrap encodings before feature extraction: percent (recursive) -> HTML -> percent.
fn normalize(s: &str) -> String {
    let s = recursive_percent_decode(s);
    let s = html_decode(&s);
    let s = recursive_percent_decode(&s);
    // v5: expand long base64 tokens (the decoded text is APPENDED) using the same tested implementation
    // as the signature engine (verdict::expand_base64), so the node behaves consistently.
    crate::verdict::expand_base64(&s)
}

fn count_substr(hay: &str, needle: &str) -> u32 {
    if needle.is_empty() { return 0; }
    let mut n = 0u32;
    let mut start = 0;
    while let Some(pos) = hay[start..].find(needle) {
        n += 1;
        start += pos + needle.len();
        if start >= hay.len() { break; }
    }
    n
}

fn kw_hits(low: &str, dict: &[&str]) -> u32 {
    dict.iter().map(|k| count_substr(low, k)).sum()
}

fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    let mut total = 0u32;
    for b in s.bytes() {
        freq[b as usize] += 1;
        total += 1;
    }
    let total_f = total as f32;
    let mut e = 0.0f32;
    for &f in freq.iter() {
        if f > 0 {
            let p = f as f32 / total_f;
            e -= p * p.log2();
        }
    }
    e
}

/// Extract the feature vector from the request parts.
/// path/query/body must be RAW (before decoding); decoding happens inside.
/// special, digits, alpha and upper counts per character (ASCII classes).
fn char_stats(s: &str) -> (u32, u32, u32, u32) {
    let (mut special, mut digits, mut alpha, mut upper) = (0u32, 0u32, 0u32, 0u32);
    for c in s.chars() {
        if c.is_ascii_digit() {
            digits += 1;
        } else if c.is_ascii_alphabetic() {
            alpha += 1;
            if c.is_ascii_uppercase() { upper += 1; }
        } else if !(c == ' ' || c == '_' || c == '-' || c == '.' || c == '/') {
            special += 1;
        }
    }
    (special, digits, alpha, upper)
}

/// 8 signal features for a decoded part, plus the keyword sum (for kw_total).
/// Order: kw_sql, kw_xss, kw_path, kw_cmd, ratio_special, entropy, n_angle, n_quote.
fn part_features(s: &str) -> ([f32; 8], f32) {
    let low = s.to_ascii_lowercase();
    let kw_sql = kw_hits(&low, KW_SQL) as f32;
    let kw_xss = kw_hits(&low, KW_XSS) as f32;
    let kw_path = kw_hits(&low, KW_PATH) as f32;
    let kw_cmd = kw_hits(&low, KW_CMD) as f32;
    let (sp, _dg, _al, _up) = char_stats(s);
    let tc = (s.chars().count().max(1)) as f32;
    let ratio_special = sp as f32 / tc;
    let entropy = shannon_entropy(s);
    let cnt = |ch: char| s.matches(ch).count() as f32;
    let n_angle = cnt('<') + cnt('>');
    let n_quote = cnt('\'') + cnt('"');
    (
        [kw_sql, kw_xss, kw_path, kw_cmd, ratio_special, entropy, n_angle, n_quote],
        kw_sql + kw_xss + kw_path + kw_cmd,
    )
}

/// Extract the v2 (per-part) feature vector from the request parts.
/// path/query/body must be RAW (before decoding); decoding happens inside.
pub fn extract(path: &str, query: &str, body: &str) -> [f32; N_FEATURES] {
    let dpath = normalize(path);
    let dquery = normalize(query);
    let dbody = normalize(body);
    let payload = format!("{} {} {}", dpath, dquery, dbody);

    let count_params = |s: &str| -> u32 {
        s.split('&').filter(|p| !p.is_empty()).count() as u32
    };
    let n_params = (count_params(&dquery) + count_params(&dbody)) as f32;
    let n_segments = dpath.split('/').filter(|x| !x.is_empty()).count() as f32;

    let (sp, dg, al, up) = char_stats(&payload);
    let tc = (payload.chars().count().max(1)) as f32;
    let ratio_special_total = sp as f32 / tc;
    let ratio_digits_total = dg as f32 / tc;
    let ratio_upper_total = if al > 0 { up as f32 / al as f32 } else { 0.0 };
    let entropy_total = shannon_entropy(&payload);

    let (pf_path, kwp) = part_features(&dpath);
    let (pf_query, kwq) = part_features(&dquery);
    let (pf_body, kwb) = part_features(&dbody);
    let kw_total = kwp + kwq + kwb;

    // v3: injection detector (siginj) verdicts over the whole payload, as 0/1
    let det_sqli = if crate::siginj::is_sqli(&payload).is_some() { 1.0 } else { 0.0 };
    let det_xss = if crate::siginj::is_xss(&payload).is_some() { 1.0 } else { 0.0 };

    [
        // global features (10)
        dpath.chars().count() as f32, dquery.chars().count() as f32, dbody.chars().count() as f32,
        n_params, n_segments, kw_total, entropy_total,
        ratio_special_total, ratio_digits_total, ratio_upper_total,
        // path (8)
        pf_path[0], pf_path[1], pf_path[2], pf_path[3], pf_path[4], pf_path[5], pf_path[6], pf_path[7],
        // query (8)
        pf_query[0], pf_query[1], pf_query[2], pf_query[3], pf_query[4], pf_query[5], pf_query[6], pf_query[7],
        // body (8)
        pf_body[0], pf_body[1], pf_body[2], pf_body[3], pf_body[4], pf_body[5], pf_body[6], pf_body[7],
        // siginj (2)
        det_sqli, det_xss,
    ]
}

/// Best-guess attack family from the feature vector, used to annotate an ML detection when
/// signature-based attack::classify() returns nothing (ML caught something obfuscated or novel). This is an ESTIMATE from the same
/// features the model sees. Indices follow the extract() layout: kw_* and det_*.
/// Confidence gate: a family is reported only with a clear signal AND a margin over the runner-up;
/// otherwise "structural" (the model reacted to shape or entropy rather than a known pattern).
/// Called ONLY when ML fired, so "structural" is more honest than an empty string.
pub fn dominant_family(f: &[f32; N_FEATURES]) -> &'static str {
    let sql  = f[10] + f[18] + f[26] + 3.0 * f[34]; // kw_sql(path|query|body) plus a strong det_sqli
    let xss  = f[11] + f[19] + f[27] + 3.0 * f[35]; // kw_xss + det_xss
    let lfi  = f[12] + f[20] + f[28];               // kw_path = traversal/LFI
    let cmdi = f[13] + f[21] + f[29];               // kw_cmd = command injection/RCE
    // the top and runner-up among keyword families
    let (mut best_v, mut best_n, mut second_v) = (0.0f32, "", 0.0f32);
    for (v, name) in [(sql, "sqli"), (xss, "xss"), (lfi, "lfi"), (cmdi, "cmdi")] {
        if v > best_v { second_v = best_v; best_v = v; best_n = name; }
        else if v > second_v { second_v = v; }
    }
    // confidence: requires a clear signal (at least one hit or detection) AND a margin of 0.5 over the runner-up,
    // otherwise we do not invent a class; it is a structural detection.
    if best_v >= 1.0 && best_v >= second_v + 0.5 {
        best_n
    } else {
        "structural"
    }
}

/// Feature names for debugging and export; position equals index.
#[allow(dead_code)]
pub const FEATURE_NAMES: [&str; N_FEATURES] = [
    // global features (10)
    "len_path", "len_query", "len_body", "n_params", "n_segments",
    "kw_total", "entropy_total", "ratio_special_total", "ratio_digits_total", "ratio_upper_total",
    // path (8)
    "kw_sql_path", "kw_xss_path", "kw_path_path", "kw_cmd_path",
    "ratio_special_path", "entropy_path", "n_angle_path", "n_quote_path",
    // query (8)
    "kw_sql_query", "kw_xss_query", "kw_path_query", "kw_cmd_query",
    "ratio_special_query", "entropy_query", "n_angle_query", "n_quote_query",
    // body (8)
    "kw_sql_body", "kw_xss_body", "kw_path_body", "kw_cmd_body",
    "ratio_special_body", "entropy_body", "n_angle_body", "n_quote_body",
    // siginj (2)
    "det_sqli", "det_xss",
];

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors from Python (ml/features.py), serialised into ml/golden.json.
    // Path relative to this file: node/src/golden.json, so the test is self-contained
    // and does not depend on the external ml/ directory. Compiled only under cargo test.
    const GOLDEN: &str = include_str!("golden.json");

    #[derive(serde::Deserialize)]
    struct Case {
        path: String,
        query: String,
        body: String,
        features: Vec<f64>,
    }

    #[test]
    fn features_match_python_golden() {
        let cases: Vec<Case> = serde_json::from_str(GOLDEN)
            .expect("golden.json must parse");
        assert!(!cases.is_empty(), "golden.json is empty");
        for (i, c) in cases.iter().enumerate() {
            let got = extract(&c.path, &c.query, &c.body);
            assert_eq!(
                c.features.len(), N_FEATURES,
                "case {}: golden has {} features, expected {}", i, c.features.len(), N_FEATURES
            );
            for (j, (&g, &e)) in got.iter().zip(c.features.iter()).enumerate() {
                let g = g as f64;
                // allow a tiny float tolerance (entropy and ratios)
                let diff = (g - e).abs();
                let tol = 1e-4 * e.abs().max(1.0);
                assert!(
                    diff <= tol,
                    "case {} ('{}?{}'), feature #{} ({}): Rust={} Python={} (diff {})",
                    i, c.path, c.query, j, FEATURE_NAMES[j], g, e, diff
                );
            }
        }
    }

    #[test]
    fn feature_version_and_size() {
        assert_eq!(FEATURE_VERSION, 5);
        assert_eq!(N_FEATURES, 36);
        assert_eq!(FEATURE_NAMES.len(), N_FEATURES);
    }
}
