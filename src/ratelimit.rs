// Token-bucket rate limiting. Unlike the C version (per worker), the counters here are
// shared across all async tasks in the process (one process, one shared state),
// which makes the limit more accurate. The key is (IP + rule index).

use std::time::Instant;

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct RateRule {
    pub location: String,
    pub operator: String, // prefix|equals|regex
    pub rps: u32,
    #[serde(default)]
    pub burst: u32,
    #[serde(default)]
    pub status: u16,
    /// Extra condition tree: the limit applies only when it matches. None means unconditional.
    #[serde(default)]
    pub when: Option<crate::verdict::Cond>,
    /// Source of the limit key: "ip" (default) | "token" | "header:Name" | "cookie:name".
    #[serde(default)]
    pub key: String,
    /// Action on exceeding the limit: "block" (429, default) | "challenge" (PoW instead of a block).
    #[serde(default)]
    pub action: String,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct RateLimiter {
    // DashMap gives per-key sharded locks instead of one global Mutex.
    buckets: dashmap::DashMap<u64, Bucket>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            buckets: dashmap::DashMap::new(),
        }
    }

    /// Check the limit. true = exceeded (block). rps == 0 means no limit.
    pub fn limited(&self, key: u64, rps: u32, burst: u32) -> bool {
        if rps == 0 {
            return false;
        }
        let cap = rps as f64 + burst as f64;
        let now = Instant::now();
        let mut b = self.buckets.entry(key).or_insert(Bucket {
            tokens: cap,
            last: now,
        });
        let dt = now.duration_since(b.last).as_secs_f64();
        if dt > 0.0 {
            b.tokens = (b.tokens + rps as f64 * dt).min(cap);
            b.last = now;
        }
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            false
        } else {
            true
        }
    }

    /// Evict stale buckets; call periodically. Removes keys untouched for longer than
    /// `idle_secs`; without this the map grows without bound when there are many
    /// unique IPs.
    pub fn cleanup(&self, idle_secs: u64) {
        let now = Instant::now();
        self.buckets.retain(|_, b| now.duration_since(b.last).as_secs() < idle_secs);
    }
}

/// Select a rate rule by location using longest-match (equals > longer prefix > regex),
/// with declaration order as the tie-breaker. Returns the index and the parameters.
pub fn pick_rule<'a>(rules: &'a [RateRule], location: &str) -> Option<(usize, &'a RateRule)> {
    let mut best: Option<(usize, &RateRule)> = None;
    let mut best_score: i64 = -1;
    for (i, r) in rules.iter().enumerate() {
        if r.location.is_empty() || r.rps == 0 {
            continue;
        }
        let (matched, score) = match r.operator.as_str() {
            "equals" => (location == r.location, 100_000i64),
            "regex" => (crate::verdict::regex_is_match(&r.location, location), 0i64),
            _ => (location.starts_with(&r.location), r.location.len() as i64), // prefix
        };
        if matched && score > best_score {
            best_score = score;
            best = Some((i, r));
        }
    }
    best
}

/// Key hash (IP + rule index) using FNV-1a; cheap.
pub fn rate_key(ip: &str, rule_idx: usize) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in ip.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^= rule_idx as u64 + 1;
    h = h.wrapping_mul(0x100000001b3);
    h
}

/// FNV-1a hash of an arbitrary string (used for the site key and per-key limit material).
pub fn str_key(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ── Adaptive per-site load meter, used to tighten limits while under attack ──
struct LoadWin {
    start: Instant,
    count: u32,
    rate: u32, // rps of the last COMPLETED window (stable between windows)
}

pub struct SiteLoad {
    m: dashmap::DashMap<u64, LoadWin>,
}

impl SiteLoad {
    pub fn new() -> Self {
        SiteLoad { m: dashmap::DashMap::new() }
    }
    /// Record a request for a site and return the rps of the last completed window.
    pub fn observe(&self, site_key: u64, window_secs: u64) -> u32 {
        let w = window_secs.max(1);
        let now = Instant::now();
        let mut e = self.m.entry(site_key).or_insert(LoadWin { start: now, count: 0, rate: 0 });
        if now.duration_since(e.start).as_secs() >= w {
            e.rate = (e.count as u64 / w) as u32;
            e.count = 0;
            e.start = now;
        }
        e.count = e.count.saturating_add(1);
        e.rate
    }
    pub fn cleanup(&self, idle_secs: u64) {
        let now = Instant::now();
        self.m.retain(|_, w| now.duration_since(w.start).as_secs() < idle_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rps_zero_never_limits() {
        let rl = RateLimiter::new();
        for _ in 0..1000 {
            assert!(!rl.limited(1, 0, 0));
        }
    }

    #[test]
    fn bucket_allows_then_blocks() {
        let rl = RateLimiter::new();
        // rps=2, burst=0 -> cap=2: two pass, the third is blocked (refill over a fraction of a ms is ~0)
        assert!(!rl.limited(42, 2, 0));
        assert!(!rl.limited(42, 2, 0));
        assert!(rl.limited(42, 2, 0));
    }

    #[test]
    fn burst_raises_capacity() {
        let rl = RateLimiter::new();
        // rps=1, burst=3 -> cap=4: four pass, the fifth is blocked
        for _ in 0..4 {
            assert!(!rl.limited(7, 1, 3));
        }
        assert!(rl.limited(7, 1, 3));
    }

    #[test]
    fn keys_are_isolated() {
        let rl = RateLimiter::new();
        assert!(!rl.limited(1, 1, 0));
        assert!(rl.limited(1, 1, 0)); // key 1 is exhausted
        assert!(!rl.limited(2, 1, 0)); // key 2 is independent
    }

    fn rr(loc: &str, op: &str, rps: u32) -> RateRule {
        RateRule { location: loc.into(), operator: op.into(), rps, burst: 0, status: 429, when: None, key: String::new(), action: String::new() }
    }

    #[test]
    fn pick_equals_and_longest_prefix_win() {
        let rules = vec![
            rr("/", "prefix", 50),
            rr("/api/", "prefix", 20),
            rr("/api/v2/auth", "equals", 5),
        ];
        assert_eq!(pick_rule(&rules, "/api/v2/auth").unwrap().1.rps, 5);  // exact equals
        assert_eq!(pick_rule(&rules, "/api/users").unwrap().1.rps, 20);  // longer prefix
        assert_eq!(pick_rule(&rules, "/blog").unwrap().1.rps, 50);       // generic
    }

    #[test]
    fn pick_skips_zero_rps_and_no_match() {
        let rules = vec![rr("/x", "prefix", 0)]; // rps=0 -> pass through
        assert!(pick_rule(&rules, "/x").is_none());
        let rules = vec![rr("/admin", "prefix", 10)];
        assert!(pick_rule(&rules, "/public").is_none());
    }

    #[test]
    fn rate_key_deterministic_and_distinct() {
        assert_eq!(rate_key("1.2.3.4", 0), rate_key("1.2.3.4", 0));
        assert_ne!(rate_key("1.2.3.4", 0), rate_key("1.2.3.4", 1));
        assert_ne!(rate_key("1.2.3.4", 0), rate_key("1.2.3.5", 0));
    }
}
