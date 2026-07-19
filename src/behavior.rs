// Behavioural bot management. Unlike static signatures (UA/JA3/iprep), this looks at
// HOW a client browses within a sliding window: request rate, path diversity,
// absence of static asset fetches (a browser always pulls css/js/images/fonts),
// user-agent rotation, and systematically incomplete browser headers.
//
// Returns a reason (to act on under bot_mode) or None for human-like
// behaviour. Storage is DashMap<ip, window>, evicted on idle like the rate buckets.
// Thresholds are tuned for low false positives: the 'no static assets' rule fires only when paths
// are DIVERSE (crawler or scanner), not on a legitimate SPA polling a single endpoint.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Instant;

const WINDOW_SECS: u64 = 120; // observation window length
const CAP_SET: usize = 256;   // cap on unique paths/UAs per client (memory guard)
const FLOOR: u32 = 5;         // minimum requests in the window before judging

struct Win {
    start: Instant,
    last: Instant,
    count: u32,          // requests in the window
    assets: u32,         // requests for static assets
    miss_hdr: u32,       // requests with incomplete browser headers
    paths: HashSet<u64>, // hashes of unique paths (capped)
    uas: HashSet<u64>,   // hashes of unique user agents (capped)
}

impl Win {
    fn new(now: Instant) -> Win {
        Win { start: now, last: now, count: 0, assets: 0, miss_hdr: 0,
              paths: HashSet::new(), uas: HashSet::new() }
    }
    fn reset(&mut self, now: Instant) {
        self.start = now;
        self.count = 0;
        self.assets = 0;
        self.miss_hdr = 0;
        self.paths.clear();
        self.uas.clear();
    }
}

#[derive(Default)]
pub struct Behavior {
    win: dashmap::DashMap<String, Win>,
}

impl Behavior {
    pub fn new() -> Self {
        Behavior { win: dashmap::DashMap::new() }
    }

    /// Record a client request and return a behavioural reason, or None.
    /// Call this on EVERY request for a site with behavioural analysis enabled;
    /// the window builds up gradually. `full_headers` means Accept and Accept-Language are present.
    pub fn observe(&self, ip: &str, path: &str, ua: &str, full_headers: bool, sens: &str) -> Option<&'static str> {
        let now = Instant::now();
        let mut w = self.win.entry(ip.to_string()).or_insert_with(|| Win::new(now));
        if now.duration_since(w.start).as_secs() > WINDOW_SECS {
            w.reset(now);
        }
        w.last = now;
        w.count += 1;
        if is_asset(path) { w.assets += 1; }
        if !full_headers { w.miss_hdr += 1; }
        if w.paths.len() < CAP_SET { w.paths.insert(hash_str(path)); }
        if !ua.is_empty() && w.uas.len() < CAP_SET { w.uas.insert(hash_str(ua)); }
        score(w.value(), sens)
    }

    /// Evict idle windows; call periodically to prevent memory growth.
    pub fn cleanup(&self, idle_secs: u64) {
        let now = Instant::now();
        self.win.retain(|_, w| now.duration_since(w.last).as_secs() < idle_secs);
    }
}

fn score(w: &Win, sens: &str) -> Option<&'static str> {
    if w.count < FLOOR {
        return None;
    }
    let (min_n, high_n): (u32, u32) = match sens {
        "low" => (15, 40),
        "high" => (6, 15),
        _ => (10, 25), // medium (default)
    };
    let c = w.count;
    let distinct = w.paths.len() as u32;
    let uas = w.uas.len() as u32;
    // 'almost no static assets': under 10% of requests. A browser ALWAYS pulls css/js/images/fonts,
    // so its share is high. A bot fetching one favicon no longer evades this (the old test was assets==0,
    // which a single static request defeated trivially).
    let scarce_assets = w.assets * 10 < c;

    // user-agent rotation from one IP with almost no static assets: browsers do not behave this way
    if c >= min_n && uas >= 4 && scarce_assets {
        return Some("behavior_ua");
    }
    // crawler: volume, nearly all paths unique, and almost no static assets
    // (70%+ of paths unique means this is not polling of a single endpoint)
    if c >= min_n && scarce_assets && distinct * 10 >= c * 7 {
        return if c >= high_n { Some("behavior_crawl_hi") } else { Some("behavior_crawl") };
    }
    // scanner: very high path diversity plus systematically incomplete headers.
    // This also catches cases where static assets ARE present, which the crawler rule above misses.
    if c >= min_n && distinct * 10 >= c * 8 && w.miss_hdr * 2 >= c {
        return Some("behavior_scan");
    }
    None
}

/// Whether a path requests a static asset, judged by its extension.
fn is_asset(path: &str) -> bool {
    let p = path.rsplit('?').next_back().unwrap_or(path);
    let tail = match p.rsplit('.').next() {
        Some(t) if t.len() <= 5 && t.len() < p.len() => t,
        _ => return false,
    };
    let mut buf = [0u8; 5];
    let n = tail.len();
    for (i, b) in tail.bytes().enumerate() {
        buf[i] = b.to_ascii_lowercase();
    }
    matches!(
        &buf[..n],
        b"css" | b"js" | b"mjs" | b"png" | b"jpg" | b"jpeg" | b"gif" | b"svg" | b"ico"
        | b"woff" | b"woff2" | b"ttf" | b"eot" | b"otf" | b"webp" | b"avif" | b"bmp"
        | b"map" | b"mp4" | b"webm" | b"mp3" | b"wav" | b"wasm"
    )
}

fn hash_str(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(ip: &str, reqs: &[(&str, &str, bool)], sens: &str) -> Option<&'static str> {
        let b = Behavior::new();
        let mut last = None;
        for (path, ua, full) in reqs {
            last = b.observe(ip, path, ua, *full, sens);
        }
        last
    }

    #[test]
    fn human_browsing_is_clean() {
        // browser: pages plus plenty of static assets, full headers, one UA -> clean (high static share)
        let reqs: Vec<(&str, &str, bool)> = vec![
            ("/", "M/5.0 Chrome", true), ("/style.css", "M/5.0 Chrome", true),
            ("/app.js", "M/5.0 Chrome", true), ("/logo.png", "M/5.0 Chrome", true),
            ("/about", "M/5.0 Chrome", true), ("/hero.jpg", "M/5.0 Chrome", true),
            ("/icon.svg", "M/5.0 Chrome", true), ("/font.woff2", "M/5.0 Chrome", true),
            ("/contact", "M/5.0 Chrome", true), ("/fav.ico", "M/5.0 Chrome", true),
            ("/pricing", "M/5.0 Chrome", true), ("/bg.webp", "M/5.0 Chrome", true),
        ];
        assert_eq!(run("1.1.1.1", &reqs, "medium"), None);
    }

    #[test]
    fn spa_polling_one_endpoint_is_clean() {
        // an SPA polling one endpoint 30 times with no static assets is NOT a bot (1 path, no diversity)
        let reqs: Vec<(&str, &str, bool)> =
            (0..30).map(|_| ("/api/status", "M/5.0 Chrome", true)).collect();
        assert_eq!(run("2.2.2.2", &reqs, "medium"), None);
    }

    #[test]
    fn below_floor_is_none() {
        // fewer than FLOOR requests: too early to judge
        let reqs: Vec<(&str, &str, bool)> =
            (0..4).map(|i| if i == 0 { ("/a", "x", false) } else { ("/b", "x", false) }).collect();
        assert_eq!(run("3.3.3.3", &reqs, "medium"), None);
    }

    #[test]
    fn crawler_flagged() {
        // 20 unique paths, no static assets -> crawler (volume below high_n=25)
        let paths: Vec<String> = (0..20).map(|i| format!("/page/{}", i)).collect();
        let reqs: Vec<(&str, &str, bool)> =
            paths.iter().map(|p| (p.as_str(), "python-requests/2.31", true)).collect();
        assert_eq!(run("4.4.4.4", &reqs, "medium"), Some("behavior_crawl"));
    }

    #[test]
    fn crawler_high_volume_flagged() {
        // 30 unique paths -> high-severity crawler (at or above high_n=25)
        let paths: Vec<String> = (0..30).map(|i| format!("/p/{}", i)).collect();
        let reqs: Vec<(&str, &str, bool)> =
            paths.iter().map(|p| (p.as_str(), "curl/8", true)).collect();
        assert_eq!(run("5.5.5.5", &reqs, "medium"), Some("behavior_crawl_hi"));
    }

    #[test]
    fn ua_rotation_flagged() {
        // one path but five rotating UAs with no static assets -> behavior_ua (this branch specifically)
        let uas = ["UA-a", "UA-b", "UA-c", "UA-d", "UA-e"];
        let reqs: Vec<(&str, &str, bool)> =
            (0..10).map(|i| ("/api/x", uas[i % 5], true)).collect();
        assert_eq!(run("6.6.6.6", &reqs, "medium"), Some("behavior_ua"));
    }

    #[test]
    fn scanner_with_assets_flagged() {
        // high diversity, incomplete headers, and static assets PRESENT (the crawler rule does not fire
        // because the static share is not small) -> the scanner rule must catch it
        let admin: Vec<String> = (0..10).map(|i| format!("/admin{}", i)).collect();
        let mut reqs: Vec<(&str, &str, bool)> = admin.iter().map(|p| (p.as_str(), "", false)).collect();
        reqs.push(("/favicon.ico", "x", true));
        reqs.push(("/style.css", "x", true));
        assert_eq!(run("7.7.7.7", &reqs, "medium"), Some("behavior_scan"));
    }

    #[test]
    fn one_asset_does_not_bypass() {
        // FIX: a crawler plus one favicon no longer evades detection (assets==0 used to save the bot)
        let mut paths: Vec<String> = (0..20).map(|i| format!("/crawl/{}", i)).collect();
        paths.push("/favicon.ico".into());
        let reqs: Vec<(&str, &str, bool)> =
            paths.iter().map(|p| (p.as_str(), "bot", true)).collect();
        assert_eq!(run("8.8.8.8", &reqs, "medium"), Some("behavior_crawl"));
    }

    #[test]
    fn sensitivity_levels() {
        // 7 unique paths: caught at high (min_n=6) but not at medium (10) or low (15)
        let paths: Vec<String> = (0..7).map(|i| format!("/s/{}", i)).collect();
        let reqs: Vec<(&str, &str, bool)> =
            paths.iter().map(|p| (p.as_str(), "bot", true)).collect();
        assert_eq!(run("9.9.9.1", &reqs, "high"), Some("behavior_crawl"));
        assert_eq!(run("9.9.9.2", &reqs, "medium"), None);
        assert_eq!(run("9.9.9.3", &reqs, "low"), None);
    }

    #[test]
    fn is_asset_detection() {
        assert!(is_asset("/style.css"));
        assert!(is_asset("/app.js"));
        assert!(is_asset("/logo.png"));
        assert!(is_asset("/favicon.ico"));
        assert!(is_asset("/a/b/c.woff2"));
        assert!(is_asset("/style.css?v=2"));      // the query string is stripped
        assert!(!is_asset("/api/users"));         // no extension
        assert!(!is_asset("/data.json"));         // .json no longer counts as a static asset
        assert!(!is_asset("/page"));
        assert!(!is_asset("/"));
    }
}
