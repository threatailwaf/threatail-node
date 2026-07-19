// ato.rs — account takeover (ATO) protection: credential stuffing, distributed and
// single-source brute force against login endpoints. Watches attempt velocity in a sliding window:
//   • many DISTINCT logins from one IP        -> credential stuffing (replaying leaked pairs);
//   • one login from many IPs                 -> distributed brute force;
//   • simply many attempts from one IP        -> plain brute force.
// Storage is DashMap<ip, window> and DashMap<hash(login), window> with capped sets to bound memory,
// plus periodic idle eviction (as in behavior/rate buckets). Everything is disabled by default.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Instant;

const CAP_SET: usize = 512;      // cap on unique logins per IP within the window (memory guard)
const MAX_KEYS: usize = 200_000; // soft ceiling on the number of keys in each map

fn hh(s: &str) -> u64 {
    let mut d = DefaultHasher::new();
    s.hash(&mut d);
    d.finish()
}

pub struct AtoCfg {
    pub window_secs: u64,
    pub ip_attempts: u32, // 0 = off: max login attempts from one IP per window
    pub ip_users: u32,    // 0 = off: max DISTINCT logins from one IP (stuffing)
    pub user_ips: u32,    // 0 = off: max DISTINCT IPs per login (distributed)
}

struct IpWin {
    start: Instant,
    attempts: u32,
    users: HashSet<u64>,
}
struct UserWin {
    start: Instant,
    ips: HashSet<u64>,
}

pub struct Ato {
    by_ip: dashmap::DashMap<String, IpWin>,
    by_user: dashmap::DashMap<u64, UserWin>,
}

impl Ato {
    pub fn new() -> Self {
        Ato { by_ip: dashmap::DashMap::new(), by_user: dashmap::DashMap::new() }
    }

    /// Record a login attempt. Returns a reason when a threshold is exceeded.
    pub fn observe(&self, ip: &str, username: &str, cfg: &AtoCfg) -> Option<&'static str> {
        let now = Instant::now();
        let win = cfg.window_secs.max(1);

        // ── per-IP ──
        if self.by_ip.len() > MAX_KEYS { self.by_ip.retain(|_, w| now.duration_since(w.start).as_secs() < win); }
        let (ip_att, ip_usr) = {
            let mut e = self.by_ip.entry(ip.to_string())
                .or_insert_with(|| IpWin { start: now, attempts: 0, users: HashSet::new() });
            if now.duration_since(e.start).as_secs() >= win {
                e.start = now; e.attempts = 0; e.users.clear();
            }
            e.attempts = e.attempts.saturating_add(1);
            if !username.is_empty() && e.users.len() < CAP_SET {
                e.users.insert(hh(username));
            }
            (e.attempts, e.users.len() as u32)
        };

        // ── per-user ──
        let mut uip: u32 = 0;
        if !username.is_empty() {
            if self.by_user.len() > MAX_KEYS { self.by_user.retain(|_, w| now.duration_since(w.start).as_secs() < win); }
            let mut u = self.by_user.entry(hh(username))
                .or_insert_with(|| UserWin { start: now, ips: HashSet::new() });
            if now.duration_since(u.start).as_secs() >= win {
                u.start = now; u.ips.clear();
            }
            if u.ips.len() < CAP_SET {
                u.ips.insert(hh(ip));
            }
            uip = u.ips.len() as u32;
        }

        // ── verdict (a threshold of 0 disables that signal) ──
        if cfg.ip_users > 0 && ip_usr >= cfg.ip_users {
            return Some("ato_cred_stuffing");
        }
        if cfg.user_ips > 0 && uip >= cfg.user_ips {
            return Some("ato_distributed");
        }
        if cfg.ip_attempts > 0 && ip_att >= cfg.ip_attempts {
            return Some("ato_bruteforce");
        }
        None
    }

    /// Evict idle windows; called periodically.
    pub fn cleanup(&self, idle_secs: u64) {
        let now = Instant::now();
        self.by_ip.retain(|_, w| now.duration_since(w.start).as_secs() < idle_secs);
        self.by_user.retain(|_, w| now.duration_since(w.start).as_secs() < idle_secs);
    }
}

/// Extract the login from the request body (form-urlencoded or JSON) using a list of field names.
/// Scans at most 64 KB of the body. Returns the first non-empty match.
pub fn extract_login(content_type: &str, body: &[u8], fields: &[String]) -> Option<String> {
    if body.is_empty() || fields.is_empty() {
        return None;
    }
    let slice = if body.len() > 65536 { &body[..65536] } else { body };
    let ct = content_type.to_ascii_lowercase();

    if ct.contains("application/json") {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(slice) {
            for f in fields {
                if let Some(s) = v.get(f).and_then(|x| x.as_str()) {
                    let s = s.trim();
                    if !s.is_empty() {
                        return Some(s.to_ascii_lowercase());
                    }
                }
            }
        }
        return None;
    }

    // default: application/x-www-form-urlencoded (or a form body with no explicit content type)
    let text = std::str::from_utf8(slice).ok()?;
    for pair in text.split('&') {
        let mut it = pair.splitn(2, '=');
        let key = it.next().unwrap_or("");
        if fields.iter().any(|f| f.eq_ignore_ascii_case(key)) {
            let raw = it.next().unwrap_or("");
            let val = urldecode(raw);
            let val = val.trim();
            if !val.is_empty() {
                return Some(val.to_ascii_lowercase());
            }
        }
    }
    None
}

/// Minimal URL decoder for form values (%XX, and '+' becomes a space).
fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => { out.push(b' '); i += 1; }
            b'%' if i + 2 < b.len() => {
                let hi = (b[i + 1] as char).to_digit(16);
                let lo = (b[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(b[i]); i += 1;
                }
            }
            c => { out.push(c); i += 1; }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
