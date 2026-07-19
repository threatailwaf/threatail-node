// In-memory response cache on the node. IMPORTANT: the cache is only consulted after all
// WAF checks have passed — a hit saves the backend round-trip, it never bypasses detection.
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Entry {
    status: u16,
    headers: Vec<(String, String)>,
    body: Bytes,
    stored: Instant,
    ttl: Duration,
    last: Instant,
}

/// A cache hit, ready to be served.
pub struct Hit {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    pub age: u64,
}

pub struct Cache {
    inner: Mutex<HashMap<String, Entry>>,
    max_entries: usize,
    max_obj: usize, // maximum size of a single object
}

impl Cache {
    pub fn new(max_entries: usize, max_obj: usize) -> Self {
        Cache { inner: Mutex::new(HashMap::new()), max_entries, max_obj }
    }

    /// A fresh hit, or None if missing or expired.
    pub fn get(&self, key: &str) -> Option<Hit> {
        let mut m = self.inner.lock().ok()?;
        let expired = {
            let e = m.get(key)?;
            e.stored.elapsed() >= e.ttl
        };
        if expired {
            m.remove(key);
            return None;
        }
        let e = m.get_mut(key)?;
        e.last = Instant::now();
        Some(Hit {
            status: e.status,
            headers: e.headers.clone(),
            body: e.body.clone(),
            age: e.stored.elapsed().as_secs(),
        })
    }

    /// Store a response with a TTL. Oversized objects are not cached.
    pub fn put(&self, key: String, status: u16, headers: Vec<(String, String)>, body: Bytes, ttl: Duration) {
        if body.len() > self.max_obj {
            return;
        }
        let mut m = match self.inner.lock() {
            Ok(m) => m,
            Err(_) => return,
        };
        // approximate LRU: when full, evict the entries with the oldest `last`
        while m.len() >= self.max_entries {
            if let Some(k) = m.iter().min_by_key(|(_, e)| e.last).map(|(k, _)| k.clone()) {
                m.remove(&k);
            } else {
                break;
            }
        }
        let now = Instant::now();
        m.insert(key, Entry { status, headers, body, stored: now, ttl, last: now });
    }
}
