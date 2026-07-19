// Threatail verdict core. A port of the Go internal/core logic: rules, exceptions,
// location normalisation and body inspection. Rate limiting lives in its own module.

use serde::Deserialize;
use std::sync::OnceLock;

/// Cache of compiled regexes (pattern -> Regex). Compilation is expensive,
/// hence the cache. regex::Regex is thread-safe once compiled.
fn regex_cache() -> &'static dashmap::DashMap<String, regex::Regex> {
    static CACHE: OnceLock<dashmap::DashMap<String, regex::Regex>> = OnceLock::new();
    CACHE.get_or_init(dashmap::DashMap::new)
}

fn regex_match(pattern: &str, text: &str) -> bool {
    regex_is_match(pattern, text)
}

/// Log a skipped rule once per pattern; the key is truncated so we never store megabytes.
fn regex_warn_once(pattern: &str, reason: &str) {
    static WARNED: OnceLock<dashmap::DashSet<String>> = OnceLock::new();
    let warned = WARNED.get_or_init(dashmap::DashSet::new);
    let mut end = pattern.len().min(256);
    while end > 0 && !pattern.is_char_boundary(end) { end -= 1; } // do not cut a UTF-8 character in half
    let key = &pattern[..end];
    if warned.len() > 4096 { warned.clear(); }
    if warned.insert(key.to_string()) {
        tracing::warn!("regex rule skipped ({}) — will not fire: {:?}", reason, key);
    }
}

/// Public cached regex matcher, also used by rate limiting.
/// Important: the DashMap shard lock is NOT held during the match itself (re.is_match),
/// otherwise a slow match on long input serialises every thread. Regex::clone is cheap
/// (an Arc inside), so we take the compiled regex out and match outside the lock.
///
/// Anti-DoS: the `regex` crate is linear-time with no catastrophic backtracking, but a
/// pathological pattern (huge repetitions or nesting) can blow up compilation.
/// So: a pattern length cap, strict size_limit/dfa_size_limit/nest_limit at compile
/// time (pathology is rejected at compilation, not at match time), and a cache cap.
pub fn regex_is_match(pattern: &str, text: &str) -> bool {
    const MAX_PATTERN_LEN: usize = 4096;
    const REGEX_CACHE_CAP: usize = 8192;
    if pattern.len() > MAX_PATTERN_LEN {
        regex_warn_once(pattern, "pattern too long");
        return false;
    }
    let cache = regex_cache();
    if let Some(re) = cache.get(pattern).map(|r| r.clone()) {
        return re.is_match(text);
    }
    if cache.len() > REGEX_CACHE_CAP { cache.clear(); } // guards against growth from many distinct patterns
    match regex::RegexBuilder::new(pattern)
        .size_limit(1 << 20)     // 1 MiB per compiled program
        .dfa_size_limit(1 << 21) // 2 MiB for the DFA cache
        .nest_limit(64)
        .build()
    {
        Ok(re) => {
            cache.insert(pattern.to_string(), re.clone());
            re.is_match(text)
        }
        Err(e) => {
            // A malformed or overly heavy pattern simply means the rule never fires, which is safe.
            regex_warn_once(pattern, &e.to_string());
            false
        }
    }
}

/// The request field a rule matches against.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Field {
    Uri,
    Args,
    Header,
    Body,
    Method,
    Ip,
    Country,
    Location,
    Path,
    Query,
    FullUri,
    Host,
    Scheme,
    HttpVersion,
    UserAgent,
    Referer,
    Cookie,
    ContentType,
    AcceptLanguage,
    Xff,
    BodyLen,
    Arg,
    Ja3,
    Ja4,
    /// 'everything': decoded URI plus body plus key headers in one string, so a single
    /// rule can catch a payload anywhere (query, body, multipart, headers).
    Any,
}

/// Comparison operator.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Operator {
    Contains,
    Equals,
    Prefix,
    Regex,
    #[serde(rename = "not_contains")]
    NotContains,
    #[serde(rename = "not_equals")]
    NotEquals,
    #[serde(rename = "not_prefix")]
    NotPrefix,
    #[serde(rename = "not_regex")]
    NotRegex,
    #[serde(rename = "detect_sqli")]
    DetectSqli,
    #[serde(rename = "detect_xss")]
    DetectXss,
}

/// Action taken on a match.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Block,
    Detect,
    Pass,
    Allow,
    Skip,
    Challenge,
}

/// A custom rule or exception.
#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    // ---- flat single condition (kept for backward compatibility with older rules) ----
    #[serde(default = "default_field")]
    pub field: Field,
    #[serde(default = "default_operator")]
    pub operator: Operator,
    #[serde(default)]
    pub value: String,
    /// For field=header: the header name (e.g. "User-Agent").
    #[serde(default)]
    pub header_name: String,
    // ---- composite condition tree. When present it replaces the flat condition. ----
    #[serde(default)]
    pub when: Option<Cond>,
    pub action: Action,
    #[serde(default)]
    pub status: u16,
    /// Signature label (e.g. "sqli", "xss"), used by the attack-type metrics.
    #[serde(default)]
    pub sig: String,
    /// Whether the rule is enabled. Disabled rules stay in the config but are not applied
    /// (a UI toggle). Defaults to true, so older rules without the field stay active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Exceptions only: when set, suppresses ONLY this signal (sqli/xss/bot/
    /// geo/ml/anomaly/rule-name) without letting the whole request through. None allows everything.
    #[serde(default)]
    pub suppress: Option<String>,
    /// Exceptions only: do not record an event for matching requests, which quiets the feed
    /// WITHOUT removing protection. Unlike allow/suppress, the request is not passed and no signal is
    /// muted; only the incident record is suppressed (see eval_no_log).
    #[serde(default)]
    pub no_log: bool,
}

fn default_field() -> Field { Field::Uri }
fn default_operator() -> Operator { Operator::Contains }
fn default_true() -> bool { true }

/// A condition tree node: either a leaf (one comparison) or a boolean group.
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Cond {
    /// Leaf: a single field/operator/value comparison.
    Leaf {
        /// Raw field name as it comes from the UI: uri|args|header:Name|body|method|ip|country|location.
        field: String,
        operator: Operator,
        #[serde(default)]
        value: String,
    },
    /// Every nested condition must match (AND).
    All { conds: Vec<Cond> },
    /// At least one nested condition matches (OR).
    Any { conds: Vec<Cond> },
    /// Negation (NOT).
    Not { cond: Box<Cond> },
}

/// Verdict decision.
#[derive(Debug, PartialEq)]
pub enum Decision {
    Allow,                 // allow/pass: stop evaluating and let the request through
    Block(u16),            // block with a status code
    Detect,                // log as suspicious but let it through
    Skip,                  // stop rule evaluation but continue the rest of the pipeline
    Challenge,             // serve the browser check (proof of work)
}

/// Request data prepared for matching, built once per request.
pub struct ReqView<'a> {
    pub args: &'a str,
    pub method: &'a str,
    pub ip: &'a str,
    pub country: &'a str,
    pub location: String,        // normalised path
    pub body: String,            // decoded body, when one was read
    // Precomputed normalised strings (double URL decode plus /* */ removal).
    // Computed ONCE per request; rules consume the result rather than decoding per rule.
    pub uri_norm: String,
    pub args_norm: String,
    pub body_norm: String,
    pub any_norm: String,        // uri + body + key headers, for the "any" field
    pub headers: &'a hyper::HeaderMap,
    #[allow(dead_code)]
    pub scheme: &'a str,         // http|https
    #[allow(dead_code)]
    pub http_version: &'a str,   // HTTP/1.1 and similar
    pub ja3: &'a str,            // JA3 TLS fingerprint (md5 hex); empty over plain HTTP
    pub ja4: &'a str,            // JA4 TLS fingerprint; empty over plain HTTP
}

/// Location normalisation: drop the ?query and replace numeric segments with ":id".
/// Matches Go's core.NormalizeLocation.
/// Path canonicalisation: resolve "." and "..", collapse "//". This yields the path
/// the backend will resolve, so equals/prefix rules on path or location cannot be
/// bypassed via directory traversal (`/api/../admin`), consistently with the OpenAPI gate.
/// The input is already URL-decoded (normalize_match), so `%2f` has become `/`.
fn canon_path(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut r = String::from("/");
    r.push_str(&out.join("/"));
    r
}

pub fn normalize_location(uri: &str) -> String {
    let raw = uri.split('?').next().unwrap_or(uri);
    let path = canon_path(raw);
    let mut out = String::with_capacity(path.len());
    for (i, seg) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()) {
            out.push_str(":id");
        } else {
            out.push_str(seg);
        }
    }
    out
}

/// Parse a Go field string ("uri", "args", "header:User-Agent", "body", "method",
/// "ip", "country", "location") into (Field, header_name).
pub fn parse_field(s: &str) -> (Field, String) {
    if let Some(name) = s.strip_prefix("header:") {
        return (Field::Header, name.to_string());
    }
    if let Some(name) = s.strip_prefix("arg:") {
        return (Field::Arg, name.to_string());
    }
    let f = match s {
        "args" => Field::Args,
        "body" => Field::Body,
        "body_len" => Field::BodyLen,
        "method" => Field::Method,
        "ip" => Field::Ip,
        "country" => Field::Country,
        "location" => Field::Location,
        "path" => Field::Path,
        "query" => Field::Query,
        "full_uri" => Field::FullUri,
        "host" => Field::Host,
        "scheme" => Field::Scheme,
        "http_version" => Field::HttpVersion,
        "user_agent" => Field::UserAgent,
        "referer" => Field::Referer,
        "cookie" => Field::Cookie,
        "content_type" => Field::ContentType,
        "accept_language" => Field::AcceptLanguage,
        "x_forwarded_for" => Field::Xff,
        "ja3" => Field::Ja3,
        "ja4" => Field::Ja4,
        "any" => Field::Any,
        _ => Field::Uri,
    };
    (f, String::new())
}

/// Parse an operator from a string.
pub fn parse_operator(s: &str) -> Operator {
    match s {
        "equals" => Operator::Equals,
        "prefix" => Operator::Prefix,
        "regex" => Operator::Regex,
        "not_contains" => Operator::NotContains,
        "not_equals" => Operator::NotEquals,
        "not_prefix" => Operator::NotPrefix,
        "not_regex" => Operator::NotRegex,
        "detect_sqli" => Operator::DetectSqli,
        "detect_xss" => Operator::DetectXss,
        _ => Operator::Contains,
    }
}

/// Parse an action from a string.
pub fn parse_action(s: &str) -> Action {
    match s {
        "detect" => Action::Detect,
        "pass" => Action::Pass,
        "allow" => Action::Allow,
        "skip" => Action::Skip,
        "challenge" => Action::Challenge,
        // require_mtls is handled by the separate mTLS check over mtls_locations;
        // in the rule engine it is a no-op and blocks nothing here.
        "require_mtls" => Action::Skip,
        _ => Action::Block,
    }
}

/// Build a Rule from raw string fields, as delivered by the Go control plane.
pub fn rule_from_raw(field: &str, operator: &str, value: &str, action: &str, status: u16, sig: &str) -> Rule {
    let (f, hname) = parse_field(field);
    Rule {
        field: f,
        operator: parse_operator(operator),
        value: value.to_string(),
        header_name: hname,
        when: None,
        action: parse_action(action),
        status,
        sig: sig.to_string(),
        enabled: true,
        suppress: None,
        no_log: false,
    }
}
fn field_value<'a>(rule: &Rule, req: &'a ReqView) -> std::borrow::Cow<'a, str> {
    use std::borrow::Cow;
    // helper: header value by name
    let hdr = |name: &str| -> &'a str {
        req.headers.get(name).and_then(|h| h.to_str().ok()).unwrap_or("")
    };
    match rule.field {
        // uri/args/path/query/fulluri are matched URL-DECODED, because attacks often arrive
        // percent-encoded (e.g. ' OR '1'='1 becomes %27%20OR...), and regexes against the
        // raw string miss them. Decoding covers both raw and encoded input.
        Field::Uri => Cow::Borrowed(&req.uri_norm),
        Field::Args => Cow::Borrowed(&req.args_norm),
        Field::Method => Cow::Borrowed(req.method),
        Field::Ip => Cow::Borrowed(req.ip),
        Field::Country => Cow::Borrowed(req.country),
        Field::Location => Cow::Borrowed(req.location.as_str()),
        Field::Body => Cow::Borrowed(&req.body_norm),
        Field::BodyLen => Cow::Owned(req.body.len().to_string()),
        Field::Path => {
            let p = req.uri_norm.split('?').next().unwrap_or(&req.uri_norm);
            Cow::Owned(canon_path(p))
        }
        Field::Query => Cow::Borrowed(&req.args_norm),
        Field::Scheme => Cow::Borrowed(req.scheme),
        Field::HttpVersion => Cow::Borrowed(req.http_version),
        Field::Host => Cow::Borrowed(hdr("host")),
        Field::UserAgent => Cow::Borrowed(hdr("user-agent")),
        Field::Referer => Cow::Borrowed(hdr("referer")),
        Field::Cookie => Cow::Borrowed(hdr("cookie")),
        Field::ContentType => Cow::Borrowed(hdr("content-type")),
        Field::AcceptLanguage => Cow::Borrowed(hdr("accept-language")),
        Field::Xff => Cow::Borrowed(hdr("x-forwarded-for")),
        Field::Ja3 => Cow::Borrowed(req.ja3),
        Field::Ja4 => Cow::Borrowed(req.ja4),
        Field::Any => Cow::Borrowed(&req.any_norm),
        Field::FullUri => {
            let host = hdr("host");
            Cow::Owned(format!("{}://{}{}", req.scheme, host, req.uri_norm))
        }
        Field::Arg => {
            // a specific query parameter, arg:name
            let want = rule.header_name.as_str();
            let mut val = "";
            for pair in req.args.split('&') {
                let mut it = pair.splitn(2, '=');
                if it.next() == Some(want) {
                    val = it.next().unwrap_or("");
                    break;
                }
            }
            Cow::Borrowed(val)
        }
        Field::Header => Cow::Borrowed(hdr(rule.header_name.as_str())),
    }
}

/// Compare a single field against a pattern using an operator.
fn cmp_field(field: Field, header_name: &str, operator: Operator, pat: &str, req: &ReqView) -> bool {
    // detect_sqli and detect_xss take NO value, so do not bail out on an empty pattern
    let valueless = matches!(operator, Operator::DetectSqli | Operator::DetectXss);
    if pat.is_empty() && !valueless {
        return false;
    }
    // temporary Rule so field_value can be reused
    let tmp = Rule {
        field,
        operator,
        value: pat.to_string(),
        header_name: header_name.to_string(),
        when: None,
        action: Action::Block,
        status: 0,
        sig: String::new(),
        enabled: true,
        suppress: None,
        no_log: false,
    };
    let val = field_value(&tmp, req);
    match operator {
        Operator::Contains => val.contains(pat),
        Operator::Equals => val.as_ref() == pat,
        Operator::Prefix => val.starts_with(pat),
        Operator::Regex => regex_match(pat, val.as_ref()),
        Operator::NotContains => !val.contains(pat),
        Operator::NotEquals => val.as_ref() != pat,
        Operator::NotPrefix => !val.starts_with(pat),
        Operator::NotRegex => !regex_match(pat, val.as_ref()),
        // Injection detector (the rule's value is ignored): the siginj tokeniser.
        Operator::DetectSqli => crate::siginj::is_sqli(val.as_ref()).is_some(),
        Operator::DetectXss => crate::siginj::is_xss(val.as_ref()).is_some(),
    }
}

/// Evaluate exceptions. Returns (full_allow, list_of_suppressed_signals).
/// An exception without `suppress` allows the whole request, as before. With `suppress=Some(sig)`
/// it mutes ONLY that signal (sqli/xss/bot/geo/ml/anomaly/rule-name) without letting the
/// whole request through, which lets an operator clear one false positive precisely.
pub fn eval_exceptions(rules: &[Rule], req: &ReqView) -> (bool, Vec<String>) {
    let mut full = false;
    let mut sup: Vec<String> = Vec::new();
    for r in rules {
        if r.no_log { continue; } // no_log rules neither pass the request nor mute signals; they only affect logging (eval_no_log)
        if matches(r, req) {
            match &r.suppress {
                Some(s) if !s.is_empty() => sup.push(s.clone()),
                _ => full = true,
            }
        }
    }
    (full, sup)
}

/// Exceptions carrying no_log: on a match no event is recorded, while protection keeps
/// working as usual. Disabled rules (enabled=false) are ignored.
pub fn eval_no_log(rules: &[Rule], req: &ReqView) -> bool {
    rules.iter().any(|r| r.enabled && r.no_log && matches(r, req))
}

/// Recursively evaluate a condition tree.
/// Public: evaluate a condition tree against a request, used by conditional rate limits.
pub fn cond_matches_pub(cond: &Cond, req: &ReqView) -> bool {
    cond_matches(cond, req)
}

fn cond_matches(cond: &Cond, req: &ReqView) -> bool {
    match cond {
        Cond::Leaf { field, operator, value } => {
            let (f, hname) = parse_field(field);
            cmp_field(f, &hname, *operator, value, req)
        }
        Cond::All { conds } => conds.iter().all(|c| cond_matches(c, req)),
        Cond::Any { conds } => conds.iter().any(|c| cond_matches(c, req)),
        Cond::Not { cond } => !cond_matches(cond, req),
    }
}

/// Evaluate one rule: the `when` tree when present, otherwise the flat condition.
fn matches(rule: &Rule, req: &ReqView) -> bool {
    if let Some(tree) = &rule.when {
        return cond_matches(tree, req);
    }
    cmp_field(rule.field, &rule.header_name, rule.operator, &rule.value, req)
}

/// Evaluate a list of rules. Returns the first action that fires.
/// `rules` are custom rules; call separately for exceptions (Pass becomes Allow).
#[allow(dead_code)] // used by tests; production calls eval_rules_sig and eval_exceptions
pub fn eval_rules(rules: &[Rule], req: &ReqView) -> Option<Decision> {
    eval_rules_sig(rules, req).map(|(d, _)| d)
}

/// Like eval_rules, but also returns the sig of the rule that fired, for attack metrics.
pub fn eval_rules_sig(rules: &[Rule], req: &ReqView) -> Option<(Decision, String)> {
    for r in rules {
        if !r.enabled { continue; } // a rule disabled by the toggle is not applied
        if matches(r, req) {
            let d = match r.action {
                Action::Block => Decision::Block(if r.status != 0 { r.status } else { 403 }),
                Action::Detect => Decision::Detect,
                Action::Pass | Action::Allow => Decision::Allow,
                Action::Skip => Decision::Skip,
                Action::Challenge => Decision::Challenge,
            };
            let sig = if r.sig.is_empty() { "rule".to_string() } else { r.sig.clone() };
            return Some((d, sig));
        }
    }
    None
}

// ---- body inspection ----

/// Determine UTF-16 byte order from the BOM or the Content-Type charset.
/// Some(true) = little-endian, Some(false) = big-endian, None = not UTF-16.
fn utf16_endianness(body: &[u8], ct: &str) -> Option<bool> {
    if body.len() >= 2 {
        if body[0] == 0xFF && body[1] == 0xFE {
            return Some(true); // BOM LE
        }
        if body[0] == 0xFE && body[1] == 0xFF {
            return Some(false); // BOM BE
        }
    }
    if ct.contains("utf-16le") || ct.contains("utf16le") {
        return Some(true);
    }
    if ct.contains("utf-16be") || ct.contains("utf16be") {
        return Some(false);
    }
    if ct.contains("utf-16") || ct.contains("utf16") {
        return Some(true); // default to LE
    }
    None
}

/// Transcode UTF-16 (LE/BE) into UTF-8 bytes for inspection. Otherwise ASCII signatures
/// (`<script`, `union select`) never match bytes like `3C 00 73 00`, while backends with
/// BOM auto-detection (Java, .NET) decode the payload correctly. UTF-7 is not covered here (deprecated,
/// no transcoder in std) and remains an unhandled gap.
fn transcode_utf16(body: &[u8], little_endian: bool) -> Vec<u8> {
    let mut units = Vec::with_capacity(body.len() / 2);
    let mut i = 0;
    while i + 1 < body.len() {
        let u = if little_endian {
            u16::from_le_bytes([body[i], body[i + 1]])
        } else {
            u16::from_be_bytes([body[i], body[i + 1]])
        };
        units.push(u);
        i += 2;
    }
    String::from_utf16_lossy(&units).into_bytes()
}

/// Character value in UTF-7's modified base64 (RFC 2152): A-Za-z0-9+/ without padding.
fn utf7_b64_val(c: u8) -> Option<u16> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u16),
        b'a'..=b'z' => Some((c - b'a' + 26) as u16),
        b'0'..=b'9' => Some((c - b'0' + 52) as u16),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode UTF-7 (RFC 2152) into UTF-8 bytes for inspection. `+` opens a shifted run of
/// modified base64 encoding UTF-16BE (every 16 bits is one code unit); the run ends at
/// any non-base64 character (`-` is consumed as an explicit terminator). `+-` means `+`.
/// Direct (non-shifted) characters pass through unchanged. Forwarding to the backend is unaffected.
fn transcode_utf7(body: &[u8]) -> Vec<u8> {
    let mut units: Vec<u16> = Vec::with_capacity(body.len());
    let n = body.len();
    let mut i = 0;
    while i < n {
        let c = body[i];
        if c != b'+' {
            units.push(c as u16);
            i += 1;
            continue;
        }
        i += 1;
        if i < n && body[i] == b'-' {
            units.push(b'+' as u16); // "+-" yields a literal '+'
            i += 1;
            continue;
        }
        let mut bits: u32 = 0;
        let mut nbits: u32 = 0;
        while i < n {
            match utf7_b64_val(body[i]) {
                Some(v) => {
                    bits = (bits << 6) | v as u32;
                    nbits += 6;
                    i += 1;
                    if nbits >= 16 {
                        nbits -= 16;
                        units.push(((bits >> nbits) & 0xFFFF) as u16);
                    }
                }
                None => break,
            }
        }
        if i < n && body[i] == b'-' {
            i += 1; // the explicit terminator is consumed
        }
    }
    String::from_utf16_lossy(&units).into_bytes()
}
/// otherwise a share of control bytes (excluding \t\n\r\f) above 10% means binary. High bytes (0x80+) are NOT
/// counted as binary, so UTF-8 text (Cyrillic and the like) is not mistaken for a binary blob.
fn looks_binary(body: &[u8]) -> bool {
    let sample = &body[..body.len().min(2048)];
    if sample.is_empty() {
        return false; // an empty or tiny body is inspected as text, which is cheap
    }
    let mut ctrl = 0usize;
    for &b in sample {
        if b == 0 {
            return true;
        }
        if b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r' && b != 0x0c {
            ctrl += 1;
        }
    }
    ctrl * 10 > sample.len()
}

/// Extract the inspectable content of a body according to its Content-Type.
/// JSON yields string values; forms and everything else are used as-is (hyper already decoded
/// at the URI level; form bodies are decoded here). The limit is applied before the call.
pub fn extract_body(body: &[u8], content_type: &str) -> String {
    let ct = content_type.to_ascii_lowercase();
    // UTF-16 body (charset=utf-16 or a BOM): transcode to UTF-8 BEFORE any inspection, otherwise
    // ASCII signatures go blind on `..00..00` bytes while the backend decodes the payload. Inspection
    // runs over the transcoded copy; forwarding to the backend is unaffected.
    let transcoded;
    let body: &[u8] = if let Some(le) = utf16_endianness(body, &ct) {
        transcoded = transcode_utf16(body, le);
        &transcoded
    } else if ct.contains("utf-7") || ct.contains("utf7") {
        // UTF-7 body (charset=utf-7): +ADw-script...+AD4- expands to <script> at the backend,
        // while ASCII signatures go blind on raw UTF-7. We transcode a copy for inspection.
        // Gated on charset (UTF-7 has no BOM); without that gate we cannot decode blindly, since an
        // ordinary '+' in a form must not be read as a shifted sequence.
        transcoded = transcode_utf7(body);
        &transcoded
    } else {
        body
    };
    // Binary uploads are NOT inspected as text: it is pointless on compressed or binary content,
    // expensive on large bodies, and produces false positives. The filename is checked separately
    // (headers and URI). Text formats (json/xml/form) are handled below as usual.
    let binary_ct = ct.contains("application/zip")
        || ct.contains("x-zip")
        || ct.contains("octet-stream")
        || ct.contains("gzip")
        || ct.contains("x-compressed")
        || ct.contains("x-rar")
        || ct.contains("x-7z")
        || ct.contains("application/pdf")
        || ct.contains("application/x-tar")
        || ct.contains("msword")
        || ct.contains("officedocument")
        || ct.starts_with("image/")
        || ct.starts_with("video/")
        || ct.starts_with("audio/")
        || ct.starts_with("font/");
    // We skip only when the body is GENUINELY binary. A declared binary Content-Type
    // over a text or JSON body is type spoofing to dodge inspection (octet-stream plus JSON SQLi
    // against an API that reads the body regardless). Such a body is inspected as text below.
    if binary_ct && looks_binary(body) {
        return String::new();
    }
    if ct.contains("application/json") || body.first() == Some(&b'{') || body.first() == Some(&b'[') {
        // pull string values and keys out of the JSON
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) {
            let mut out = String::new();
            collect_json_strings(&val, &mut out);
            return out;
        }
    }
    if ct.contains("xml") {
        return extract_xml_text(body);
    }
    // multipart/form-data: extract field names, filenames and values, otherwise an attack in a field
    // drowns in boundary and header noise or is not inspected at all. content_type supplies the boundary.
    if ct.contains("multipart/form-data") {
        return extract_multipart(body, content_type);
    }
    // form-urlencoded and everything else
    if ct.contains("application/x-www-form-urlencoded") {
        return url_decode(body);
    }
    String::from_utf8_lossy(body).into_owned()
}

/// Extracts field names, filenames and values from multipart/form-data into a flat string
/// for inspection. Part boundaries and headers are discarded.
fn extract_multipart(body: &[u8], content_type: &str) -> String {
    let cl = content_type.to_ascii_lowercase();
    let boundary = match cl.find("boundary=") {
        Some(p) => content_type[p + 9..]
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"'),
        None => "",
    };
    let text = String::from_utf8_lossy(body);
    if boundary.is_empty() {
        return text.into_owned();
    }
    let delim = format!("--{}", boundary);
    let mut out = String::new();
    for part in text.split(delim.as_str()) {
        let val = if let Some(idx) = part.find("\r\n\r\n") {
            &part[idx + 4..]
        } else if let Some(idx) = part.find("\n\n") {
            &part[idx + 2..]
        } else {
            continue;
        };
        let headers = &part[..part.len() - val.len()];
        for kw in ["name=\"", "filename=\""] {
            if let Some(p) = headers.find(kw) {
                let rest = &headers[p + kw.len()..];
                if let Some(end) = rest.find('"') {
                    out.push_str(&rest[..end]);
                    out.push('\n');
                }
            }
        }
        out.push_str(val.trim_end_matches(['\r', '\n']));
        out.push('\n');
    }
    out
}

fn collect_json_strings(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::String(s) => {
            out.push_str(s);
            out.push('\n');
        }
        serde_json::Value::Array(a) => {
            for x in a {
                collect_json_strings(x, out);
            }
        }
        serde_json::Value::Object(m) => {
            for (k, x) in m {
                out.push_str(k);
                out.push('\n');
                collect_json_strings(x, out);
            }
        }
        _ => {}
    }
}

/// Cheap upload checks that do NOT inspect content: a dangerous extension in the name
/// and type spoofing (magic bytes disagreeing with the declared Content-Type). Cheap, low false positives. Returns a label.
pub fn upload_threat(content_type: &str, filename: &str, body: &[u8]) -> Option<&'static str> {
    if !filename.is_empty() && dangerous_ext(filename) {
        return Some("upload_ext");
    }
    if magic_spoof(content_type, body) {
        return Some("upload_spoof");
    }
    None
}

/// Result of parsing an upload: whether a file part was present, any threat found, and the size
/// of the largest file part, for the per-file size limit.
pub struct UploadScan {
    pub is_upload: bool,
    pub threat: Option<&'static str>,
    pub max_file: usize,
}

/// Parse multipart/form-data PART BY PART: every file part (one with filename=) is checked
/// for a dangerous extension and type spoofing (magic bytes vs that part's Content-Type). The signal
/// for 'this is an upload' is the request shape, not the path. Returns the first threat and the largest file size.
pub fn scan_multipart_upload(content_type: &str, body: &[u8]) -> UploadScan {
    let mut scan = UploadScan { is_upload: false, threat: None, max_file: 0 };
    let ctl = content_type.to_ascii_lowercase();
    let boundary = match ctl.find("boundary=") {
        Some(p) => content_type[p + 9..].split(';').next().unwrap_or("").trim().trim_matches('"'),
        None => "",
    };
    if boundary.is_empty() { return scan; }
    let delim = format!("--{}", boundary);
    let text = String::from_utf8_lossy(body);
    for part in text.split(delim.as_str()) {
        let (headers, val) = if let Some(idx) = part.find("\r\n\r\n") {
            (&part[..idx], &part[idx + 4..])
        } else if let Some(idx) = part.find("\n\n") {
            (&part[..idx], &part[idx + 2..])
        } else { continue; };
        let fname = match mp_quoted(headers, "filename=\"") { Some(f) => f, None => continue };
        if fname.is_empty() { continue; } // filename="" means this is not a file field
        scan.is_upload = true;
        let file_body = val.trim_end_matches(['\r', '\n']).as_bytes();
        if file_body.len() > scan.max_file { scan.max_file = file_body.len(); }
        if scan.threat.is_none() {
            if dangerous_ext(fname) {
                scan.threat = Some("upload_ext");
            } else {
                let part_ct = mp_header(headers, "content-type").unwrap_or("");
                if magic_spoof(part_ct, file_body) { scan.threat = Some("upload_spoof"); }
            }
        }
    }
    scan
}

fn mp_quoted<'a>(hay: &'a str, kw: &str) -> Option<&'a str> {
    let p = hay.find(kw)?;
    let rest = &hay[p + kw.len()..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn mp_header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    for line in headers.split(['\r', '\n']).filter(|l| !l.is_empty()) {
        if let Some(colon) = line.find(':') {
            if line[..colon].trim().eq_ignore_ascii_case(name) {
                return Some(line[colon + 1..].split(';').next().unwrap_or("").trim());
            }
        }
    }
    None
}

fn dangerous_ext(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    // executable and script extensions (webshells). Double extensions such as shell.php.jpg are also checked.
    const BAD: &[&str] = &[
        ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".pht", ".phar", ".jsp", ".jspx",
        ".jsw", ".jsv", ".asp", ".aspx", ".ascx", ".ashx", ".asmx", ".cer", ".shtml", ".cgi",
        ".pl", ".exe", ".dll", ".sh", ".bat", ".cmd", ".ps1",
    ];
    BAD.iter()
        .any(|ext| low.ends_with(ext) || low.contains(&format!("{}.", ext)))
}

fn magic_spoof(content_type: &str, body: &[u8]) -> bool {
    if !head_is_dangerous(body) {
        return false;
    }
    // the body is a script or executable while the declared type is 'safe' (image/pdf/zip/media): spoofing
    let ct = content_type.to_ascii_lowercase();
    ct.starts_with("image/")
        || ct.starts_with("video/")
        || ct.starts_with("audio/")
        || ct.starts_with("font/")
        || ct.contains("application/pdf")
        || ct.contains("zip")
}

fn head_is_dangerous(body: &[u8]) -> bool {
    let head = &body[..body.len().min(64)];
    // PE (MZ) and ELF executables
    if head.starts_with(b"MZ") || head.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return true;
    }
    let s = String::from_utf8_lossy(head);
    let t = s.trim_start().to_ascii_lowercase();
    t.starts_with("<?php")
        || t.starts_with("<?=")
        || t.starts_with("<%")
        || t.starts_with("<script")
        || t.starts_with("#!")
}

fn extract_xml_text(body: &[u8]) -> String {
    let s = String::from_utf8_lossy(body);
    let b = s.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < n {
        if b[i] == b'<' {
            // <! ... > covers DOCTYPE/ENTITY/DTD and is PRESERVED, since it carries XXE indicators (<!ENTITY, SYSTEM, PUBLIC);
            // otherwise XXE payloads are lost and never reach the detector.
            if i + 1 < n && b[i + 1] == b'!' {
                let start = i;
                while i < n && b[i] != b'>' {
                    i += 1;
                }
                out.push_str(&s[start..i.min(n)]);
                out.push('\n');
                if i < n {
                    i += 1;
                }
                continue;
            }
            // an ordinary <tag ...> element: markup is skipped
            while i < n && b[i] != b'>' {
                i += 1;
            }
            if i < n {
                i += 1;
            }
            continue;
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Normalise a string for rule matching: URL-decode up to 2 passes (catching double
/// encoding such as %252e -> %2e -> .) plus removal of SQL/C comments /* ... */ (the
/// un/**/ion sel/**/ect bypass). Cheap: the second decode runs only if a '%' remains, and comment
/// removal only if "/*" is present, with an early exit otherwise.
/// Path traversal: the decoded path contains a ".." segment.
/// uri_norm has already been double URL-decoded, so `%2e%2e`, `%252e`
/// and backslashes `\` are all caught. Legitimate paths contain no ".." segments.
pub fn has_traversal(decoded_uri: &str) -> bool {
    let path = decoded_uri.split('?').next().unwrap_or(decoded_uri);
    path.split(['/', '\\']).any(|seg| seg == "..")
}

pub fn normalize_match(raw: &[u8]) -> String {
    // Multi-layer decode: percent, backslash escapes (\uXXXX, \xHH) and HTML entities (&#x3c;, &lt;).
    // Obfuscation often nests layers, so we decode in a bounded loop until the result stabilises.
    let mut cur = url_decode(raw);
    for _ in 0..3 {
        let mut dec = decode_backslash_escapes(&cur);
        dec = decode_html_entities(&dec);
        if dec.as_bytes().contains(&b'%') {
            dec = url_decode(dec.as_bytes());
        }
        if dec == cur {
            break;
        }
        cur = dec;
    }
    // Expand long base64 values (appending the decode to the inspection string), fold
    // full-width characters down to ASCII, then strip ordinary comments (versioned ones are kept).
    strip_sql_comments(&fold_confusables(&expand_base64(&cur)))
}

/// Decode HTML entities: numeric (`&#60;`, `&#x3c;`) and the main named ones that matter
/// for XSS and injection. Anything else (`&amp;copy;` and so on) is left alone.
fn decode_html_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(n);
    let mut i = 0usize;
    while i < n {
        if b[i] == b'&' {
            // Numeric entities &#DDDD / &#xHHHH: the trailing ';' is OPTIONAL
            // (browsers terminate at the first non-digit): &#40, &#x28 and &#0000000040 are all valid.
            if i + 2 < n && b[i + 1] == b'#' {
                let hexmode = b[i + 2] == b'x' || b[i + 2] == b'X';
                let start = if hexmode { i + 3 } else { i + 2 };
                let maxlen = if hexmode { 8 } else { 12 };
                let mut j = start;
                while j < n
                    && j - start < maxlen
                    && (if hexmode { b[j].is_ascii_hexdigit() } else { b[j].is_ascii_digit() })
                {
                    j += 1;
                }
                if j > start {
                    let radix = if hexmode { 16 } else { 10 };
                    if let Ok(cp) = u32::from_str_radix(&s[start..j], radix) {
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                            i = if j < n && b[j] == b';' { j + 1 } else { j };
                            continue;
                        }
                    }
                }
            }
            // Named entities require the trailing ';', otherwise ordinary text produces false positives.
            let mut j = i + 1;
            let lim = (i + 12).min(n);
            while j < lim && b[j].is_ascii_alphabetic() {
                j += 1;
            }
            if j < n && b[j] == b';' && j > i + 1 {
                let decoded: Option<char> = match s[i + 1..j].to_ascii_lowercase().as_str() {
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    "amp" => Some('&'),
                    "sol" => Some('/'),
                    "colon" => Some(':'),
                    "lpar" => Some('('),
                    "rpar" => Some(')'),
                    "equals" => Some('='),
                    "grave" => Some('`'),
                    "excl" => Some('!'),
                    "nbsp" => Some(' '),
                    _ => None,
                };
                if let Some(ch) = decoded {
                    out.push(ch);
                    i = j + 1;
                    continue;
                }
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Folds full-width ASCII forms (U+FF01..U+FF5E) down to plain ASCII (U+0021..U+007E).
/// A bypass such as `＜script＞` collapses to `<script>`.
fn fold_confusables(s: &str) -> String {
    if s.is_ascii() {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let c = ch as u32;
        if (0xFF01..=0xFF5E).contains(&c) {
            out.push(char::from_u32(c - 0xFEE0).unwrap_or(ch));
        } else {
            out.push(ch);
        }
    }
    out
}

/// Decode backslash escapes: `\uXXXX`, `\u{XXXX}`, `\xHH`. Other `\` sequences are
/// left as they are. This unwraps obfuscation such as JSON `\u0025` (percent) leading to `<img ...>`.
fn decode_backslash_escapes(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(n);
    let mut i = 0usize;
    while i < n {
        if b[i] == b'\\' && i + 1 < n {
            match b[i + 1] {
                b'u' | b'U' => {
                    if i + 2 < n && b[i + 2] == b'{' {
                        // \u{XXXX..}: scan hex only, stopping at any non-hex or multi-byte char so the slice stays ASCII
                        let start = i + 3;
                        let mut j = start;
                        while j < n && b[j].is_ascii_hexdigit() && j - start < 8 {
                            j += 1;
                        }
                        if j < n && b[j] == b'}' && j > start {
                            if let Ok(cp) = u32::from_str_radix(&s[start..j], 16) {
                                if let Some(ch) = char::from_u32(cp) {
                                    out.push(ch);
                                    i = j + 1;
                                    continue;
                                }
                            }
                        }
                    } else if i + 6 <= n && b[i + 2..i + 6].iter().all(|c| c.is_ascii_hexdigit()) {
                        // \uXXXX (exactly 4 hex): the bytes are verified ASCII, so slicing is safe
                        if let Ok(cp) = u32::from_str_radix(&s[i + 2..i + 6], 16) {
                            if let Some(ch) = char::from_u32(cp) {
                                out.push(ch);
                                i += 6;
                                continue;
                            }
                        }
                    }
                }
                b'x' | b'X'
                    if i + 4 <= n && b[i + 2..i + 4].iter().all(|c| c.is_ascii_hexdigit()) => {
                        if let Ok(cp) = u8::from_str_radix(&s[i + 2..i + 4], 16) {
                            out.push(cp as char);
                            i += 4;
                            continue;
                        }
                    }
                _ => {}
            }
        }
        // by default the character is kept as is (UTF-8 safe)
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

fn b64_is(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'-' | b'_')
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        let v = b64_val(c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Expands long base64 tokens: the decode is appended to the inspection string (the original is not
/// replaced). Deliberately conservative for low false positives: only valid tokens of length 20..1024 whose
/// output is mostly printable. The decode is used only for signature matching, so junk base64
/// without attack patterns breaks nothing.
pub(crate) fn expand_base64(s: &str) -> String {
    let b = s.as_bytes();
    let n = b.len();
    let mut extra = String::new();
    let mut i = 0;
    let mut budget = 8; // at most 8 tokens per request, keeping CPU cost predictable
    while i < n && budget > 0 {
        if b64_is(b[i]) {
            let start = i;
            while i < n && b64_is(b[i]) {
                i += 1;
            }
            let core = i - start;
            let mut end = i;
            while end < n && b[end] == b'=' {
                end += 1;
            }
            if (20..=1024).contains(&core) {
                if let Some(dec) = b64_decode(&s[start..end]) {
                    if !dec.is_empty() {
                        let printable = dec
                            .iter()
                            .filter(|&&c| c == 9 || c == 10 || c == 13 || (32..=126).contains(&c))
                            .count();
                        if printable * 100 / dec.len() >= 80 {
                            extra.push('\n');
                            extra.push_str(&String::from_utf8_lossy(&dec));
                            budget -= 1;
                        }
                    }
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
    if extra.is_empty() {
        s.to_string()
    } else {
        let mut r = String::with_capacity(s.len() + extra.len());
        r.push_str(s);
        r.push_str(&extra);
        r
    }
}

fn strip_sql_comments(s: &str) -> String {
    if !s.contains("/*") {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut in_versioned = false;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            // A MySQL versioned comment /*!...*/ or /*!12345 ...*/ has its contents EXECUTED,
            // so it must not be stripped (otherwise /*!UNION*/ would vanish and evade signatures):
            // we remove only the markers and keep the contents.
            if i + 2 < b.len() && b[i + 2] == b'!' {
                i += 3;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                in_versioned = true;
                continue;
            }
            // an ordinary /* ... */ comment is replaced with a SPACE, not removed entirely.
            // In MySQL and Postgres /* */ is equivalent to a space: union/**/select == "union select".
            // Removing it entirely would turn "union/**/select" into "unionselect", where siginj sees no
            // keywords and space2comment (sqlmap --tamper=space2comment) would evade detection.
            // The opposite edge case, "un/**/ion" becoming "un ion", is correct: the database itself does NOT
            // join it into union either (they are two identifiers, a syntax error), so we lose no
            // real attack and merely stop flagging a payload that cannot execute.
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
            out.push(b' ');
            continue;
        }
        // the closing */ of a versioned comment: strip the marker
        if in_versioned && i + 1 < b.len() && b[i] == b'*' && b[i + 1] == b'/' {
            in_versioned = false;
            i += 2;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn url_decode(body: &[u8]) -> String {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        match body[i] {
            b'%' if i + 2 < body.len() => {
                let hi = hex(body[i + 1]);
                let lo = hex(body[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                out.push(body[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&fold_overlong_utf8(&out)).into_owned()
}

/// Overlong UTF-8 folding: 2- and 3-byte redundant encodings of ASCII characters become the ASCII byte.
/// A bypass such as `%C0%AE%C0%AF` (= `../`) would otherwise be lost in the lossy String conversion.
fn fold_overlong_utf8(b: &[u8]) -> Vec<u8> {
    // fast path: no overlong lead bytes present
    if !b.iter().any(|&x| x == 0xC0 || x == 0xC1 || x == 0xE0) {
        return b.to_vec();
    }
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        // 2-byte overlong: C0/C1 followed by 80..BF maps to U+0000..U+007F
        if i + 1 < b.len() && (b[i] == 0xC0 || b[i] == 0xC1) && (0x80..=0xBF).contains(&b[i + 1]) {
            let cp = ((b[i] & 0x1F) << 6) | (b[i + 1] & 0x3F); // always <= 0x7F
            out.push(cp);
            i += 2;
            continue;
        }
        // 3-byte overlong: E0 + 80..9F + 80..BF is likewise a redundant encoding of a small code point
        if i + 2 < b.len()
            && b[i] == 0xE0
            && (0x80..=0x9F).contains(&b[i + 1])
            && (0x80..=0xBF).contains(&b[i + 2])
        {
            let cp = ((b[i + 1] as u32 & 0x3F) << 6) | (b[i + 2] as u32 & 0x3F);
            if cp <= 0x7F {
                out.push(cp as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_unwraps_json_unicode_then_percent() {
        // A real bypass: a JSON \u escape over percent encoding yielding <img src onerror=confirm(1)>
        let raw = r#"{"test": true, "k": "\u0025\u0033\u0043\u0069\u006d\u0067\u0025\u0032\u0030\u0073\u0072\u0063\u0025\u0032\u0030\u006f\u006e\u0065\u0072\u0072\u006f\u0072\u003d\u0063\u006f\u006e\u0066\u0069\u0072\u006d\u0025\u0032\u0038\u0031\u0025\u0032\u0039\u0025\u0033\u0045"}"#;
        let n = normalize_match(raw.as_bytes());
        assert!(n.contains("<img"), "должен раскрыться тег: {}", n);
        assert!(n.contains("onerror="), "должен раскрыться обработчик: {}", n);
        assert!(crate::siginj::is_xss(&n).is_some(), "is_xss должен сработать: {}", n);
    }

    #[test]
    fn normalize_handles_hex_escape() {
        assert!(normalize_match(br"\x3cscript\x3e").contains("<script"));
    }

    #[test]
    fn normalize_decodes_html_entities() {
        let n = normalize_match(b"&#60;img src=x onerror=&#x61;lert(1)&#62;");
        assert!(n.contains("<img"), "{}", n);
        assert!(n.contains("onerror="), "{}", n);
        assert!(crate::siginj::is_xss(&normalize_match(b"&lt;script&gt;alert(1)&lt;/script&gt;")).is_some());
    }

    #[test]
    fn normalize_folds_fullwidth() {
        // full-width <script>
        let fw = "\u{FF1C}script\u{FF1E}";
        assert!(normalize_match(fw.as_bytes()).contains("<script"));
    }

    #[test]
    fn normalize_leaves_benign_ampersand() {
        // legitimate text must not be turned into an attack
        let n = normalize_match(b"name=John&age=30&city=Berlin");
        assert!(crate::siginj::is_xss(&n).is_none());
    }

    #[test]
    fn normalize_html_numeric_entity_no_semicolon() {
        // numeric entities without ';', a common WAF bypass
        assert!(normalize_match(b"confirm&#0000000040document.domain)").contains("confirm(document.domain)"));
        assert!(normalize_match(b"&#x3c;svg&#x3e;").contains("<svg"));
        // a named entity without ';' is NOT expanded, avoiding false positives
        assert_eq!(normalize_match(b"johnson&amp"), "johnson&amp");
    }

    #[test]
    fn strip_keeps_versioned_comment_body() {
        // /*!...*/ executes in MySQL, so its contents must be PRESERVED (this bypasses ordinary WAFs)
        let n = normalize_match(b"/*!UNiOn*/ /*!SeLEct*/ 1,2,3").to_lowercase();
        assert!(n.contains("union"), "{}", n);
        assert!(n.contains("select"), "{}", n);
    }

    #[test]
    fn strip_replaces_plain_comment_with_space() {
        // A comment acts as a token separator, emulating how the database parses, rather than joining tokens.
        assert_eq!(strip_sql_comments("a/*x*/b"), "a b");
    }

    #[test]
    fn strip_comment_defeats_space2comment() {
        // sqlmap --tamper=space2comment: union/**/select must NOT collapse into unionselect
        assert_eq!(strip_sql_comments("union/**/select"), "union select");
        assert_eq!(strip_sql_comments("1/**/or/**/1=1"), "1 or 1=1");
        // and end to end through normalisation plus the siginj tokeniser the attack must be detected
        let n = normalize_match(b"1/**/UNION/**/SELECT/**/pass/**/FROM/**/users").to_lowercase();
        assert!(crate::siginj::is_sqli(&n).is_some(), "space2comment SQLi must detect: {}", n);
    }

    #[test]
    fn extract_body_inspects_spoofed_binary_ct() {
        // octet-stream but the body is textual JSON SQLi: type spoofing, so we inspect it
        let out = extract_body(
            b"{\"user\":\"admin' UNION SELECT pass FROM users-- -\"}",
            "application/octet-stream",
        );
        assert!(
            out.to_lowercase().contains("union select"),
            "spoofed octet-stream must be inspected: {}",
            out
        );
        // a genuine binary (PNG magic with NULs) under octet-stream is skipped as before
        let png = [0x89u8, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13];
        assert_eq!(extract_body(&png, "application/octet-stream"), "");
    }

    #[test]
    fn extract_body_transcodes_utf7() {
        // UTF-7 (RFC 2152) encodes '<' as +ADw- and '>' as +AD4-. A backend with charset=utf-7
        // will expand the payload, while raw UTF-7 blinds ASCII signatures. Inspection uses the decode.
        // Assemble "<script>alert(1)</script>" in UTF-7, with special characters as shifted runs.
        let utf7 = "+ADw-script+AD4-alert(1)+ADw-/script+AD4-";
        let out = extract_body(utf7.as_bytes(), "text/html; charset=utf-7");
        let low = out.to_lowercase();
        assert!(
            low.contains("<script>") && low.contains("</script>"),
            "utf-7 body must transcode+inspect: {}",
            out
        );
    }

    #[test]
    fn utf7_plus_literal_and_plain() {
        // "+-" yields a literal '+'; ordinary text without '+' passes through unchanged.
        assert_eq!(super::transcode_utf7(b"a+-b"), b"a+b");
        assert_eq!(super::transcode_utf7(b"plain text"), b"plain text");
    }

    #[test]
    fn extract_body_transcodes_utf16() {
        // UTF-16LE JSON carrying SQLi: without transcoding, ASCII signatures go blind on the `..00` bytes
        let payload = "{\"q\":\"1' UNION SELECT pass FROM users-- -\"}";
        let mut u16body = Vec::new();
        for u in payload.encode_utf16() {
            u16body.extend_from_slice(&u.to_le_bytes());
        }
        let out = extract_body(&u16body, "application/json; charset=utf-16");
        assert!(
            out.to_lowercase().contains("union select"),
            "utf-16 body must transcode+inspect: {}",
            out
        );
    }

    #[test]
    fn multipart_extracts_field_value() {
        let ct = "multipart/form-data; boundary=XYZ";
        let body = "--XYZ\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n<img src=x onerror=alert(1)>\r\n--XYZ--\r\n";
        let ex = extract_body(body.as_bytes(), ct);
        assert!(ex.contains("<img"), "{}", ex);
        assert!(crate::siginj::is_xss(&normalize_match(ex.as_bytes())).is_some());
    }

    #[test]
    fn normalize_folds_overlong_traversal() {
        // %C0%AE%C0%AE%C0%AF = overlong ../
        let n = normalize_match(b"%C0%AE%C0%AE%C0%AFetc%C0%AFpasswd");
        assert!(n.contains("../"), "{}", n);
        assert!(n.contains("/etc/passwd"), "{}", n);
    }

    #[test]
    fn normalize_expands_base64() {
        // base64("alert(document.cookie)")
        let n = normalize_match(b"x=YWxlcnQoZG9jdW1lbnQuY29va2llKQ==");
        assert!(n.contains("document.cookie"), "{}", n);
    }

    #[test]
    fn base64_ignores_short_tokens() {
        // short tokens are not expanded, avoiding false positives on ordinary values
        assert_eq!(normalize_match(b"id=abc123"), "id=abc123");
    }

    #[test]
    fn normalize_no_panic_on_escape_before_multibyte() {
        // REGRESSION: \uAB or \x3 before an invalid byte (which becomes a replacement char) used to panic
        // when slicing &s[i+2..i+6] off a character boundary. The bytes are now checked in advance.
        for esc in [&b"\\uAB"[..], &b"\\x3"[..], &b"\\u{12"[..]] {
            let mut v = b"data=".to_vec();
            v.extend_from_slice(esc);
            v.extend_from_slice(&[0xFF, 0xFE, 0x80]); // invalid UTF-8 becomes replacement characters
            v.extend_from_slice(b"tail");
            let _ = normalize_match(&v); // must not panic
        }
        // valid decoding still works
        assert!(normalize_match(b"\\u003cscript\\u003e").contains("<script"));
    }

    #[test]
    fn upload_flags_webshell_ext() {
        assert_eq!(upload_threat("application/octet-stream", "shell.php", b"x"), Some("upload_ext"));
        assert_eq!(upload_threat("image/jpeg", "x.php.jpg", b"x"), Some("upload_ext"));
        assert_eq!(upload_threat("application/zip", "archive.zip", b"PK\x03\x04"), None);
    }

    #[test]
    fn upload_flags_type_spoof() {
        assert_eq!(
            upload_threat("image/png", "avatar.png", b"<?php system($_GET[0]); ?>"),
            Some("upload_spoof")
        );
        assert!(upload_threat("image/png", "real.png", b"\x89PNG\r\n\x1a\n").is_none());
        // a legitimate zip is not flagged
        assert!(upload_threat("application/zip", "doc.zip", b"PK\x03\x04\x14\x00").is_none());
    }

    #[test]
    fn canon_path_resolves_traversal() {
        assert_eq!(canon_path("/api/../admin"), "/admin");
        assert_eq!(canon_path("/a//b/./c"), "/a/b/c");
        assert_eq!(canon_path("/api/products/../../admin"), "/admin");
        assert_eq!(canon_path("/"), "/");
        // a location rule on /admin now catches directory traversal
        assert_eq!(normalize_location("/api/../admin"), "/admin");
    }

    #[test]
    fn traversal_detect() {
        // ".." as a path segment (uri_norm is already decoded) means traversal
        assert!(has_traversal("/a/../b"));
        assert!(has_traversal("/api/node/../../admin"));
        assert!(has_traversal("..\\..\\b"));       // backslashes
        assert!(has_traversal("/x/../y?z=1"));      // the query is discarded and the path is still traversal
    }
    #[test]
    fn traversal_clean() {
        assert!(!has_traversal("/a/b/c"));
        assert!(!has_traversal("/path/file..txt")); // ".." inside a name rather than as its own segment
        assert!(!has_traversal("/a/./b"));           // "." is not traversal
        assert!(!has_traversal("/?q=1..10"));        // ".." appears only in the query
        assert!(!has_traversal("/"));
    }

    fn hm(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }
    fn view<'a>(method: &'a str, uri: &'a str, args: &'a str, ip: &'a str,
                country: &'a str, body: &str, headers: &'a hyper::HeaderMap) -> ReqView<'a> {
        let uri_norm = normalize_match(uri.as_bytes());
        let args_norm = normalize_match(args.as_bytes());
        let body_norm = normalize_match(body.as_bytes());
        let any_norm = format!("{}\n{}", uri_norm, body_norm);
        ReqView {
            args, method, ip, country,
            location: normalize_location(uri),
            body: body.to_string(),
            uri_norm, args_norm, body_norm, any_norm,
            headers, scheme: "https", http_version: "HTTP/1.1",
            ja3: "", ja4: "",
        }
    }

    #[test]
    fn normalize_strips_query_and_numeric_ids() {
        assert_eq!(normalize_location("/api/users/123?x=1"), "/api/users/:id");
        assert_eq!(normalize_location("/"), "/");
    }

    #[test]
    fn block_on_path_prefix() {
        let h = hm(&[]);
        let req = view("GET", "/admin/panel", "", "1.2.3.4", "US", "", &h);
        let rules = vec![rule_from_raw("path", "prefix", "/admin", "block", 403, "")];
        assert_eq!(eval_rules(&rules, &req), Some(Decision::Block(403)));
    }

    #[test]
    fn block_default_status_is_403() {
        let h = hm(&[]);
        let req = view("GET", "/x", "", "1.2.3.4", "US", "", &h);
        // status=0 must fall back to 403
        let rules = vec![rule_from_raw("path", "prefix", "/x", "block", 0, "")];
        assert_eq!(eval_rules(&rules, &req), Some(Decision::Block(403)));
    }

    #[test]
    fn allow_decision() {
        let h = hm(&[]);
        let req = view("GET", "/healthz", "", "1.2.3.4", "US", "", &h);
        let rules = vec![rule_from_raw("path", "equals", "/healthz", "allow", 0, "")];
        assert_eq!(eval_rules(&rules, &req), Some(Decision::Allow));
    }

    #[test]
    fn no_match_returns_none() {
        let h = hm(&[]);
        let req = view("GET", "/", "", "1.2.3.4", "US", "", &h);
        let rules = vec![rule_from_raw("path", "prefix", "/admin", "block", 403, "")];
        assert_eq!(eval_rules(&rules, &req), None);
    }

    #[test]
    fn header_contains_blocks_tool_ua() {
        let h = hm(&[("user-agent", "sqlmap/1.5")]);
        let req = view("GET", "/", "", "1.2.3.4", "US", "", &h);
        let rules = vec![rule_from_raw("header:User-Agent", "contains", "sqlmap", "block", 403, "ua")];
        assert_eq!(eval_rules(&rules, &req), Some(Decision::Block(403)));
    }

    #[test]
    fn regex_on_args() {
        let h = hm(&[]);
        let req = view("GET", "/s", "q=union+select+1", "1.2.3.4", "US", "", &h);
        let rules = vec![rule_from_raw("args", "regex", "union.+select", "block", 403, "sqli")];
        assert_eq!(eval_rules(&rules, &req), Some(Decision::Block(403)));
    }

    #[test]
    fn not_contains_negation_matches() {
        let h = hm(&[]);
        let req = view("GET", "/x", "", "1.2.3.4", "US", "", &h);
        // /x does NOT contain /admin, so not_contains fires and blocks
        let rules = vec![rule_from_raw("path", "not_contains", "/admin", "block", 403, "")];
        assert_eq!(eval_rules(&rules, &req), Some(Decision::Block(403)));
    }

    #[test]
    fn first_match_wins() {
        let h = hm(&[]);
        let req = view("GET", "/admin", "", "1.2.3.4", "US", "", &h);
        let rules = vec![
            rule_from_raw("path", "prefix", "/admin", "allow", 0, ""),
            rule_from_raw("path", "prefix", "/admin", "block", 403, ""),
        ];
        assert_eq!(eval_rules(&rules, &req), Some(Decision::Allow));
    }

    #[test]
    fn composite_all_any_not() {
        let h = hm(&[("user-agent", "curl/8")]);
        let req = view("POST", "/login", "", "10.0.0.1", "RU", "", &h);
        // AND: country == RU and path prefix /login
        let all = Cond::All { conds: vec![
            Cond::Leaf { field: "country".into(), operator: Operator::Equals, value: "RU".into() },
            Cond::Leaf { field: "path".into(),    operator: Operator::Prefix, value: "/login".into() },
        ]};
        assert!(cond_matches_pub(&all, &req));
        // NOT: country is not US
        let neg = Cond::Not { cond: Box::new(Cond::Leaf {
            field: "country".into(), operator: Operator::Equals, value: "US".into() }) };
        assert!(cond_matches_pub(&neg, &req));
        // ANY: the POST method among the alternatives
        let any = Cond::Any { conds: vec![
            Cond::Leaf { field: "country".into(), operator: Operator::Equals, value: "DE".into() },
            Cond::Leaf { field: "method".into(),  operator: Operator::Equals, value: "POST".into() },
        ]};
        assert!(cond_matches_pub(&any, &req));
    }

    #[test]
    fn eval_rules_sig_returns_signature() {
        let h = hm(&[]);
        let req = view("GET", "/s", "q=<script>", "1.2.3.4", "US", "", &h);
        let rules = vec![rule_from_raw("args", "contains", "<script>", "block", 403, "xss")];
        assert_eq!(eval_rules_sig(&rules, &req), Some((Decision::Block(403), "xss".to_string())));
    }
}
