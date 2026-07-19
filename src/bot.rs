// Heuristic bot detection from request headers, with no external databases.
// Returns (is_bot, reason). Cheap, with no blocking calls.

use hyper::HeaderMap;

/// Suspicious substrings in the User-Agent (tools, scanners, bots).
const BAD_UA: &[&str] = &[
    "curl", "wget", "python-requests", "python-urllib", "go-http-client",
    "libwww", "httpclient", "scrapy", "httrack",
    "nikto", "sqlmap", "nmap", "masscan", "zgrab", "nessus", "acunetix",
    "dirbuster", "gobuster", "wpscan", "semrush", "ahrefsbot", "mj12bot",
    "dotbot", "petalbot", "bytespider", "censys", "zoominfobot",
];

/// Libraries that legitimate mobile apps use frequently
/// (okhttp is the Android networking stack; java covers Android/JVM clients). These count as tool_ua
/// ONLY when the UA carries no mobile markers, otherwise it is a false positive on a real
/// phone app (for example "Android;client-app;okhttp(...);HONOR:NIC-LX1").
const SOFT_UA: &[&str] = &["okhttp", "java/"];

fn is_mobile_app_ua(ua_l: &str) -> bool {
    ua_l.contains("android") || ua_l.contains("iphone") || ua_l.contains("ipad")
        || ua_l.contains("cfnetwork") || ua_l.contains("darwin")
}

/// Whether the UA looks like a tool or script: hard tokens (scanners, bots) always count; soft ones
/// (okhttp, java) count only outside a mobile context.
fn ua_is_tool(ua_l: &str) -> bool {
    if BAD_UA.iter().any(|b| ua_l.contains(b)) {
        return true;
    }
    SOFT_UA.iter().any(|b| ua_l.contains(b)) && !is_mobile_app_ua(ua_l)
}

/// Individual stateless header signals for ML context features (unlike detect(), which
/// returns only the first match). Returns
/// (ua_empty, ua_tool, no_browser_headers, no_referer).
pub fn header_signals(headers: &HeaderMap) -> (bool, bool, bool, bool) {
    let ua = headers
        .get(hyper::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let ua_empty = ua.trim().is_empty();
    let ua_l = ua.to_ascii_lowercase();
    let ua_tool = ua_is_tool(&ua_l);
    let looks_browser = ua_l.contains("mozilla") || ua_l.contains("chrome")
        || ua_l.contains("safari") || ua_l.contains("firefox");
    let no_browser_headers = looks_browser
        && (!headers.contains_key(hyper::header::ACCEPT)
            || !headers.contains_key(hyper::header::ACCEPT_LANGUAGE));
    let no_referer = !headers.contains_key(hyper::header::REFERER);
    (ua_empty, ua_tool, no_browser_headers, no_referer)
}

/// Check a request for bot behaviour. Returns Some(reason) if it is a bot.
pub fn detect(headers: &HeaderMap) -> Option<&'static str> {
    let ua = headers
        .get(hyper::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // 1) empty or missing UA
    if ua.trim().is_empty() {
        return Some("empty_ua");
    }

    let ua_l = ua.to_ascii_lowercase();

    // 2) known tools, scanners or bots in the UA (okhttp/java only outside a mobile context)
    if ua_is_tool(&ua_l) {
        return Some("tool_ua");
    }

    // 3) the UA looks like a browser but the typical browser headers are missing
    let looks_browser = ua_l.contains("mozilla") || ua_l.contains("chrome")
        || ua_l.contains("safari") || ua_l.contains("firefox");
    if looks_browser {
        let has_accept = headers.contains_key(hyper::header::ACCEPT);
        let has_lang = headers.contains_key(hyper::header::ACCEPT_LANGUAGE);
        if !has_accept || !has_lang {
            return Some("fake_browser");
        }
    }

    None
}

/// TLS fingerprint mismatch against the claimed browser. Real Chrome/Chromium/Firefox/Edge builds
/// since roughly 2017-2019 ALWAYS send GREASE values (RFC 8701) in the ClientHello. If the UA claims
/// to be such a browser but the handshake carried no GREASE, it is almost certainly an
/// automated client (curl/python/Go/okhttp) forging the User-Agent header.
///
/// IMPORTANT: this is only reliable when the node terminates TLS DIRECTLY from the client. Behind a CDN
/// the fingerprint belongs to the CDN edge, not the client, so the check must stay off
/// (hence the per-site bot_tls_check flag, disabled by default).
pub fn tls_ua_mismatch(ua: &str, ja3: &str, tls_grease: bool) -> bool {
    if ja3.is_empty() { return false; } // no fingerprint (peek failed, or we are behind a proxy)
    if tls_grease { return false; }     // GREASE present -> looks like a real browser
    let ua_l = ua.to_ascii_lowercase();
    // The Chromium family (chrome/edge/opera/brave/samsung all contain "chrome/") and Firefox.
    // Safari is deliberately excluded: its GREASE support is less consistent, risking false positives.
    
    ua_l.contains("mozilla")
        && (ua_l.contains("chrome/") || ua_l.contains("crios/")
            || ua_l.contains("firefox/") || ua_l.contains("edg/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn empty_ua_is_bot() {
        assert_eq!(detect(&hm(&[])), Some("empty_ua"));
    }

    #[test]
    fn tool_ua_is_bot() {
        assert_eq!(detect(&hm(&[("user-agent", "curl/8.1.2")])), Some("tool_ua"));
        assert_eq!(detect(&hm(&[("user-agent", "sqlmap/1.5#dev")])), Some("tool_ua"));
    }

    #[test]
    fn mobile_okhttp_not_flagged() {
        // legitimate mobile app: okhttp inside an Android UA is NOT tool_ua
        assert_eq!(
            detect(&hm(&[("user-agent", "Android;client-app;okhttp(26.0.0.139);15(35);HONOR:NIC-LX1)")])),
            None
        );
        // a bare okhttp client with no mobile context is still tool_ua
        assert_eq!(detect(&hm(&[("user-agent", "okhttp/4.9.0")])), Some("tool_ua"));
    }

    #[test]
    fn browser_ua_without_headers_is_fake() {
        let h = hm(&[("user-agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537")]);
        assert_eq!(detect(&h), Some("fake_browser"));
    }

    #[test]
    fn real_browser_passes() {
        let h = hm(&[
            ("user-agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537"),
            ("accept", "text/html"),
            ("accept-language", "en-US,en;q=0.9"),
        ]);
        assert_eq!(detect(&h), None);
    }

    #[test]
    fn non_browser_non_tool_passes() {
        // legitimate custom client: not browser-like and not in the tool list
        assert_eq!(detect(&hm(&[("user-agent", "MyMobileApp/3.2")])), None);
    }
}
