// dlp.rs — RESPONSE body inspection (Data Loss Prevention). Catches leaks in backend
// responses: secrets (private keys, AWS keys, JWTs, api_key/secret/... assignments),
// PII (card numbers validated with Luhn) and error/stack-trace signatures (information
// disclosure, often a sign of a successful injection). Plus user-supplied regexes.
//
// The caller picks the action: detect (log) | redact (mask) | block.
// Scanning uses regex::bytes (bodies may not be UTF-8), with a size cap.

use regex::bytes::Regex;
use std::sync::OnceLock;

pub struct DlpCfg {
    pub max_scan: usize,      // how many body bytes to scan (0 -> 1 MiB)
    pub secrets: bool,
    pub pii: bool,
    pub errors: bool,
    pub patterns: Vec<String>, // user-supplied regexes (bytes)
}

pub struct Finding {
    pub kind: &'static str,
    pub count: usize,
}

// ── built-in sets (compiled once) ──
struct Pat {
    kind: &'static str,
    re: Regex,
    luhn: bool, // for cards: confirm the number with the Luhn algorithm
}

fn secrets_pats() -> &'static Vec<Pat> {
    static P: OnceLock<Vec<Pat>> = OnceLock::new();
    P.get_or_init(|| {
        let mk = |k, p: &str| Pat { kind: k, re: Regex::new(p).unwrap(), luhn: false };
        vec![
            mk("private_key", r"(?-u)-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
            mk("aws_key", r"(?-u)AKIA[0-9A-Z]{16}"),
            mk("jwt", r"(?-u)eyJ[A-Za-z0-9_=-]{8,}\.[A-Za-z0-9_=-]{8,}\.[A-Za-z0-9_=-]{6,}"),
            mk("secret_assignment", r#"(?i)(?:secret|api[_-]?key|access[_-]?token|client[_-]?secret|password)["' :=]{1,4}["']?[A-Za-z0-9/_+\-]{20,}"#),
        ]
    })
}

fn pii_pats() -> &'static Vec<Pat> {
    static P: OnceLock<Vec<Pat>> = OnceLock::new();
    P.get_or_init(|| {
        vec![Pat {
            kind: "credit_card",
            re: Regex::new(r"(?-u)\b(?:\d[ -]?){13,19}\b").unwrap(),
            luhn: true,
        }]
    })
}

fn error_pats() -> &'static Vec<Pat> {
    static P: OnceLock<Vec<Pat>> = OnceLock::new();
    P.get_or_init(|| {
        let mk = |k, p: &str| Pat { kind: k, re: Regex::new(p).unwrap(), luhn: false };
        vec![
            mk("sql_error", r"(?i)sql syntax|you have an error in your sql|unclosed quotation mark|SQLSTATE\[|PG::\w+Error|PostgreSQL query failed|ORA-[0-9]{5}|mysql_fetch|Warning:\s*mysqli?"),
            mk("stack_trace", r"(?-u)Traceback \(most recent call last\)"),
            mk("php_error", r"(?i)(?:Fatal error|Warning|Notice):.{1,120} on line [0-9]+|\.php on line [0-9]+"),
            mk("java_trace", r"(?-u)at [a-zA-Z0-9_.$]+\([A-Za-z0-9_]+\.java:[0-9]+\)"),
            mk("dotnet_error", r"(?-u)System\.[A-Za-z.]+Exception"),
        ]
    })
}

/// Scan only suitable content types (text/json/xml/js/html). Binary and images are skipped.
pub fn scannable(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.starts_with("text/")
        || ct.contains("json")
        || ct.contains("xml")
        || ct.contains("javascript")
        || ct.contains("html")
        || ct.is_empty()
}

/// Luhn check over a byte slice (digits only; length 13..=19).
fn luhn_ok(bytes: &[u8]) -> bool {
    let digits: Vec<u8> = bytes.iter().filter(|b| b.is_ascii_digit()).map(|b| b - b'0').collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let mut v = d as u32;
        if alt {
            v *= 2;
            if v > 9 { v -= 9; }
        }
        sum += v;
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

/// Scan the body. Returns (findings, optionally the redacted body).
/// `redacted` is built only when redact=true and something matched.
pub fn scan(body: &[u8], content_type: &str, cfg: &DlpCfg, redact: bool) -> (Vec<Finding>, Option<Vec<u8>>) {
    if body.is_empty() || !scannable(content_type) {
        return (Vec::new(), None);
    }
    let cap = if cfg.max_scan == 0 { 1024 * 1024 } else { cfg.max_scan };
    let slice = if body.len() > cap { &body[..cap] } else { body };

    let mut findings: std::collections::BTreeMap<&'static str, usize> = std::collections::BTreeMap::new();
    let mut ranges: Vec<(usize, usize)> = Vec::new();

    let mut run = |pats: &Vec<Pat>| {
        for p in pats {
            for m in p.re.find_iter(slice) {
                if p.luhn && !luhn_ok(&slice[m.start()..m.end()]) {
                    continue;
                }
                *findings.entry(p.kind).or_insert(0) += 1;
                if redact {
                    ranges.push((m.start(), m.end()));
                }
            }
        }
    };
    if cfg.secrets { run(secrets_pats()); }
    if cfg.pii { run(pii_pats()); }
    if cfg.errors { run(error_pats()); }

    // user-supplied regexes
    for pat in &cfg.patterns {
        if pat.trim().is_empty() || pat.len() > 512 {
            continue;
        }
        if let Ok(re) = regex::bytes::RegexBuilder::new(pat)
            .size_limit(1 << 20)
            .dfa_size_limit(1 << 21)
            .build()
        {
            for m in re.find_iter(slice) {
                *findings.entry("custom").or_insert(0) += 1;
                if redact { ranges.push((m.start(), m.end())); }
            }
        }
    }

    let out: Vec<Finding> = findings.into_iter().map(|(kind, count)| Finding { kind, count }).collect();
    if out.is_empty() {
        return (out, None);
    }

    let redacted = if redact && !ranges.is_empty() {
        Some(redact_ranges(body, slice.len(), &mut ranges))
    } else {
        None
    };
    (out, redacted)
}

const MASK: &[u8] = b"[REDACTED]";

/// Replace matched ranges with a mask. The body tail beyond the scan limit is left as is.
fn redact_ranges(body: &[u8], scanned_len: usize, ranges: &mut [(usize, usize)]) -> Vec<u8> {
    ranges.sort_by_key(|r| r.0);
    let mut out = Vec::with_capacity(body.len());
    let mut cur = 0usize;
    for &(s, e) in ranges.iter() {
        if s < cur { continue; } // overlapping match — skip
        out.extend_from_slice(&body[cur..s]);
        out.extend_from_slice(MASK);
        cur = e;
    }
    // remainder of the scanned part plus the unscanned tail
    if cur < body.len() {
        out.extend_from_slice(&body[cur..]);
    }
    let _ = scanned_len;
    out
}
