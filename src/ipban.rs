// Per-site automatic IP banning (option 2: distributed through the cloud).
//
// Flow:
//   1) the node counts strikes (terminal attack blocks) locally, keyed by (domain, IP);
//   2) once the threshold is reached within the window, strike():
//        • immediately applies a local provisional ban, cutting the source off on this node at once;
//        • returns Some(until), and the caller reports action="autoban" to the cloud.
//   3) the cloud stores the ban and serves it as a FEED to every node of that site (/api/node/bans);
//   4) each node polls the feed (every 20 s) and atomically swaps in the cloud ban set;
//      as soon as the feed carries the local ban, the provisional local entry is dropped and
//      the feed becomes the source of truth (including for unbanning from the dashboard).
//   5) is_banned() = local OR feed, giving an early block at the start of the pipeline.
//
// Strike counting is local to each node (its own blocks for that node/site pair). The ban itself
// is distributed to all nodes of the site via the feed. The provisional local ban lives for LOCAL_TTL,
// which is enough for the cloud (5 s event flush) plus feed polling (20 s) to pick it up.

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// How long a local provisional ban lives before the cloud feed takes over.
/// Must cover the event flush (5 s) plus the feed polling interval (20 s) with margin.
const LOCAL_TTL: u64 = 90;

struct Strikes {
    count: u32,
    window_start: u64,
}

pub struct IpBan {
    // (domain, IP) -> strikes in the current window (node-local)
    strikes: DashMap<(String, String), Strikes>,
    // this node's immediate provisional bans: (domain, IP) -> expiry (unix seconds)
    local: DashMap<(String, String), u64>,
    // bans from the cloud feed (all nodes of the site): (domain, IP) -> expiry (unix seconds)
    feed: arc_swap::ArcSwap<HashMap<(String, String), u64>>,
}

impl IpBan {
    pub fn new() -> Self {
        IpBan {
            strikes: DashMap::new(),
            local: DashMap::new(),
            feed: arc_swap::ArcSwap::from_pointee(HashMap::new()),
        }
    }

    /// Whether an IP is currently banned for a site (locally OR via the cloud feed).
    pub fn is_banned(&self, domain: &str, ip: &str) -> bool {
        let key = (domain.to_string(), ip.to_string());
        let n = now();
        if let Some(u) = self.local.get(&key) {
            if *u > n { return true; }
        }
        if let Some(u) = self.feed.load().get(&key) {
            if *u > n { return true; }
        }
        false
    }

    /// Record a violation (a terminal attack block). Once the threshold is crossed it immediately applies
    /// a local ban, shutting the source down at once, and returns Some(until) to report to the cloud.
    pub fn strike(&self, domain: &str, ip: &str, threshold: u32, window: u64, duration: u64) -> Option<u64> {
        if threshold == 0 { return None; } // auto-ban is disabled
        if self.is_banned(domain, ip) { return None; } // already banned: do not pile up more strikes or events
        let key = (domain.to_string(), ip.to_string());
        let n = now();
        let trip = {
            let mut e = self.strikes.entry(key.clone()).or_insert(Strikes { count: 0, window_start: n });
            if n.saturating_sub(e.window_start) > window {
                e.count = 0;
                e.window_start = n;
            }
            e.count += 1;
            e.count >= threshold
        };
        if trip {
            self.strikes.remove(&key);
            let dur = duration.max(1);
            // immediate local ban (provisional, until the feed picks it up)
            self.local.insert(key, n + dur.min(LOCAL_TTL));
            return Some(n + dur); // the FULL duration is what goes to the cloud
        }
        None
    }

    /// Atomically replace the cloud ban set from the feed. items: (domain, IP, until_unix).
    /// Provisional local bans already present in the feed are dropped, so the feed becomes the
    /// source of truth (important for unbanning: gone from the feed means the node stops blocking).
    pub fn replace_feed(&self, items: Vec<(String, String, u64)>) {
        let n = now();
        let m: HashMap<(String, String), u64> = items
            .into_iter()
            .filter(|(_, _, until)| *until > n)
            .map(|(d, ip, until)| ((d, ip), until))
            .collect();
        // drop local bans that the feed already carries, and expired ones
        self.local.retain(|k, u| *u > n && !m.contains_key(k));
        self.feed.store(Arc::new(m));
    }

    /// Evict stale strikes and provisional local bans.
    pub fn cleanup(&self) {
        let n = now();
        self.strikes.retain(|_, s| n.saturating_sub(s.window_start) < 3600);
        self.local.retain(|_, u| *u > n);
    }
}

impl Default for IpBan {
    fn default() -> Self { Self::new() }
}
