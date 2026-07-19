// verbot.rs — search crawler verification via FCrDNS
// (forward-confirmed reverse DNS). Catches User-Agent forgery: a claimed
// Googlebot/Bingbot is confirmed by the rDNS PTR suffix plus a forward resolve back
// to the same IP. Results are cached per IP, since crawlers send many requests.
//
// Resolution is blocking (dns-lookup via the system resolver, like the node's forward resolve),
// so it runs inside spawn_blocking in a background task, NOT in the hot path.

use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub struct CrawlerDef {
    pub name: &'static str,
    ua_tokens: &'static [&'static str], // user-agent substrings (lower case)
    suffixes: &'static [&'static str],  // accepted rDNS suffixes (with a leading dot)
}

// Officially documented crawlers and their rDNS domains.
static CRAWLERS: &[CrawlerDef] = &[
    CrawlerDef {
        name: "googlebot",
        ua_tokens: &["googlebot", "google-inspectiontool", "storebot-google", "googleother", "google-safety", "adsbot-google", "mediapartners-google"],
        suffixes: &[".googlebot.com", ".google.com"],
    },
    CrawlerDef {
        name: "bingbot",
        ua_tokens: &["bingbot", "adidxbot", "bingpreview", "msnbot"],
        suffixes: &[".search.msn.com"],
    },
    CrawlerDef {
        name: "yandex",
        ua_tokens: &["yandexbot", "yandex.com/bots", "yandexmobilebot", "yandeximages"],
        suffixes: &[".yandex.com", ".yandex.net", ".yandex.ru"],
    },
    CrawlerDef {
        name: "duckduckbot",
        ua_tokens: &["duckduckbot", "duckduckgo"],
        suffixes: &[".duckduckgo.com"],
    },
    CrawlerDef {
        name: "applebot",
        ua_tokens: &["applebot"],
        suffixes: &[".applebot.apple.com", ".apple.com"],
    },
    CrawlerDef {
        name: "baidu",
        ua_tokens: &["baiduspider"],
        suffixes: &[".crawl.baidu.com", ".crawl.baidu.jp", ".baidu.com", ".baidu.jp"],
    },
    CrawlerDef {
        name: "facebook",
        ua_tokens: &["facebookexternalhit", "facebookbot", "meta-externalagent", "meta-externalfetcher"],
        suffixes: &[".fbsv.net", ".tfbnw.net"],
    },
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Verified(&'static str), // verified crawler (name)
    Spoofed(&'static str),  // claims to be a crawler but FCrDNS did not confirm it (name)
    Pending,                // check in flight, no result yet
}

struct Entry {
    verdict: Verdict,
    expires: Instant,
}

fn cache() -> &'static dashmap::DashMap<IpAddr, Entry> {
    static C: OnceLock<dashmap::DashMap<IpAddr, Entry>> = OnceLock::new();
    C.get_or_init(dashmap::DashMap::new)
}

const CACHE_CAP: usize = 50_000;
const TTL_OK: Duration = Duration::from_secs(6 * 3600); // verified: cache for a long time
const TTL_BAD: Duration = Duration::from_secs(3600);    // spoof: shorter TTL, in case it changes
const TTL_PENDING: Duration = Duration::from_secs(30);  // prevents launching the check twice

/// Does the User-Agent claim to be a known crawler? (sync, cheap)
pub fn claimed_crawler(ua: &str) -> Option<&'static CrawlerDef> {
    if ua.is_empty() {
        return None;
    }
    let ua_l = ua.to_ascii_lowercase();
    CRAWLERS.iter().find(|c| c.ua_tokens.iter().any(|t| ua_l.contains(t)))
}

/// Cached verdict (sync). None = absent or expired, so a background check is needed.
pub fn cached(ip: &IpAddr) -> Option<Verdict> {
    let c = cache();
    if let Some(e) = c.get(ip) {
        if e.expires > Instant::now() {
            return Some(e.verdict);
        }
    }
    None
}

fn put(ip: IpAddr, verdict: Verdict, ttl: Duration) {
    let c = cache();
    if c.len() > CACHE_CAP {
        // coarse but cheap eviction: drop expired entries
        c.retain(|_, e| e.expires > Instant::now());
    }
    c.insert(ip, Entry { verdict, expires: Instant::now() + ttl });
}

/// Start the background FCrDNS check. Idempotent: marks Pending immediately so that
/// concurrent requests from the same IP do not spawn duplicate checks.
pub fn spawn_verify(ip: IpAddr, def: &'static CrawlerDef) {
    put(ip, Verdict::Pending, TTL_PENDING);
    tokio::spawn(async move {
        let v = verify(ip, def).await;
        let ttl = match v {
            Verdict::Verified(_) => TTL_OK,
            _ => TTL_BAD,
        };
        put(ip, v, ttl);
    });
}

/// FCrDNS: PTR(ip) -> crawler suffix -> forward resolve back to the same ip.
async fn verify(ip: IpAddr, def: &'static CrawlerDef) -> Verdict {
    // 1) reverse (PTR)
    let host = match tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip)).await {
        Ok(Ok(h)) => h,
        _ => return Verdict::Spoofed(def.name), // no PTR record, so it cannot be verified
    };
    let host_l = host.trim_end_matches('.').to_ascii_lowercase();
    if !def.suffixes.iter().any(|s| host_l.ends_with(s)) {
        return Verdict::Spoofed(def.name); // PTR is not one of the crawler's domains
    }
    // 2) forward-confirm: the name must resolve back to the original IP
    let hl = host_l.clone();
    let ips = match tokio::task::spawn_blocking(move || dns_lookup::lookup_host(&hl)).await {
        Ok(Ok(v)) => v,
        _ => return Verdict::Spoofed(def.name),
    };
    if ips.iter().any(|a| a == &ip) {
        Verdict::Verified(def.name)
    } else {
        Verdict::Spoofed(def.name)
    }
}
