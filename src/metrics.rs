// Node metrics: atomic in-memory counters plus a per-second sliding window
// for live RPS. Rendered as Prometheus text (/metrics) and JSON (/stats).

use std::sync::atomic::{AtomicU64, AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const WINDOW_SECS: usize = 60; // window depth for live RPS

pub struct Metrics {
    pub started: u64,
    pub requests_total: AtomicU64,
    pub blocked_total: AtomicU64,
    pub challenged_total: AtomicU64,
    pub detected_total: AtomicU64,
    pub passed_total: AtomicU64,
    pub status_2xx: AtomicU64,
    pub status_3xx: AtomicU64,
    pub status_4xx: AtomicU64,
    pub status_5xx: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub active_conns: AtomicI64,
    pub tls_handshakes_ok: AtomicU64,
    pub tls_handshakes_fail: AtomicU64,
    pub policy_version: AtomicU64,
    // methods
    pub m_get: AtomicU64,
    pub m_post: AtomicU64,
    pub m_put: AtomicU64,
    pub m_patch: AtomicU64,
    pub m_delete: AtomicU64,
    pub m_other: AtomicU64,
    // blocks by source
    pub blk_rule: AtomicU64,
    pub blk_bot: AtomicU64,
    pub blk_geo: AtomicU64,
    pub blk_ratelimit: AtomicU64,
    pub blk_threat: AtomicU64,
    pub blk_iplist: AtomicU64,
    pub blk_anomaly: AtomicU64,
    // threat levels (by Threat Score)
    pub threat_low: AtomicU64,
    pub threat_medium: AtomicU64,
    pub threat_high: AtomicU64,
    // attack types (by sig)
    pub atk_sqli: AtomicU64,
    pub atk_xss: AtomicU64,
    pub atk_traversal: AtomicU64,
    pub atk_rce: AtomicU64,
    pub atk_lfi: AtomicU64,
    pub atk_scanner: AtomicU64,
    pub atk_general: AtomicU64,
    // latency: sum and count, for computing the mean
    pub lat_sum_ms: AtomicU64,
    pub lat_count: AtomicU64,
    // latency histogram (for p50/p95/p99). Cumulative buckets in ms (Prometheus `le`).
    // boundaries: 1,5,10,25,50,100,250,500,1000,2500,5000,+Inf
    pub lat_b: [AtomicU64; 12],
    // backend (upstream) latency, tracked separately to tell a slow WAF from a slow backend
    pub up_lat_sum_ms: AtomicU64,
    pub up_lat_count: AtomicU64,
    pub up_errors: AtomicU64,        // backend connection errors (502/504/timeout)
    pub overloaded_total: AtomicU64, // requests shed due to the RAM budget (503)
    pub breaker_open_total: AtomicU64, // backend transitions to the open state (circuit breaker)
    // challenge: browser check outcome
    pub challenge_passed: AtomicU64, // passed the check (human)
    pub challenge_failed: AtomicU64, // failed (bot or timeout)
    // ML inference
    pub ml_evals: AtomicU64,         // how many times the model ran
    pub ml_hits: AtomicU64,          // how many times proba met the threshold
    pub ml_proba_sum_x1000: AtomicU64, // sum of proba x 1000, for the mean
    // score distribution across buckets; a mean would hide a detection collapse.
    // b0:[0,0.25) b1:[0.25,0.5) b2:[0.5,0.8) b3:[0.8,1]
    pub ml_b0: AtomicU64,
    pub ml_b1: AtomicU64,
    pub ml_b2: AtomicU64,
    pub ml_b3: AtomicU64,
    // lock-free ring buffer for RPS: each slot is an AtomicU64
    // packed as (second << 32) | counter. Reads and writes are atomic.
    ring: Vec<AtomicU64>,
    // per-site metrics (host label), so Grafana can filter by site.
    // Key series only: requests, blocks, latency, backend latency.
    // Infrastructure metrics (memory, TLS, connections) stay per node.
    per_host: dashmap::DashMap<String, HostStat>,
}

/// Counters for a single site (host), used by the per-site metrics.
#[derive(Default)]
pub struct HostStat {
    pub requests: AtomicU64,
    pub blocked: AtomicU64,
    pub passed: AtomicU64,
    pub lat_sum_ms: AtomicU64,
    pub lat_count: AtomicU64,
    pub up_lat_sum_ms: AtomicU64,
    pub up_lat_count: AtomicU64,
}

/// Latency histogram bucket boundaries in ms, cumulative. The last one is +Inf.
const LAT_BUCKETS: [u64; 11] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            started: now(),
            requests_total: AtomicU64::new(0),
            blocked_total: AtomicU64::new(0),
            challenged_total: AtomicU64::new(0),
            detected_total: AtomicU64::new(0),
            passed_total: AtomicU64::new(0),
            status_2xx: AtomicU64::new(0),
            status_3xx: AtomicU64::new(0),
            status_4xx: AtomicU64::new(0),
            status_5xx: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            active_conns: AtomicI64::new(0),
            tls_handshakes_ok: AtomicU64::new(0),
            tls_handshakes_fail: AtomicU64::new(0),
            policy_version: AtomicU64::new(0),
            m_get: AtomicU64::new(0), m_post: AtomicU64::new(0), m_put: AtomicU64::new(0),
            m_patch: AtomicU64::new(0), m_delete: AtomicU64::new(0), m_other: AtomicU64::new(0),
            blk_rule: AtomicU64::new(0), blk_bot: AtomicU64::new(0), blk_geo: AtomicU64::new(0),
            blk_ratelimit: AtomicU64::new(0), blk_threat: AtomicU64::new(0),
            blk_iplist: AtomicU64::new(0), blk_anomaly: AtomicU64::new(0),
            threat_low: AtomicU64::new(0), threat_medium: AtomicU64::new(0), threat_high: AtomicU64::new(0),
            atk_sqli: AtomicU64::new(0), atk_xss: AtomicU64::new(0), atk_traversal: AtomicU64::new(0),
            atk_rce: AtomicU64::new(0), atk_lfi: AtomicU64::new(0), atk_scanner: AtomicU64::new(0),
            atk_general: AtomicU64::new(0),
            lat_sum_ms: AtomicU64::new(0), lat_count: AtomicU64::new(0),
            lat_b: Default::default(),
            up_lat_sum_ms: AtomicU64::new(0), up_lat_count: AtomicU64::new(0), up_errors: AtomicU64::new(0),
            overloaded_total: AtomicU64::new(0),
            breaker_open_total: AtomicU64::new(0),
            challenge_passed: AtomicU64::new(0), challenge_failed: AtomicU64::new(0),
            ml_evals: AtomicU64::new(0), ml_hits: AtomicU64::new(0), ml_proba_sum_x1000: AtomicU64::new(0),
            ml_b0: AtomicU64::new(0), ml_b1: AtomicU64::new(0), ml_b2: AtomicU64::new(0), ml_b3: AtomicU64::new(0),
            ring: (0..WINDOW_SECS).map(|_| AtomicU64::new(0)).collect(),
            per_host: dashmap::DashMap::new(),
        }
    }

    /// Record an HTTP method.
    pub fn record_method(&self, method: &str) {
        match method {
            "GET" => &self.m_get, "POST" => &self.m_post, "PUT" => &self.m_put,
            "PATCH" => &self.m_patch, "DELETE" => &self.m_delete, _ => &self.m_other,
        }.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a block by source (sig/action).
    pub fn record_block_source(&self, sig: &str) {
        let c = match sig {
            "rule" => &self.blk_rule,
            "bot" => &self.blk_bot,
            "geo" => &self.blk_geo,
            "ratelimit" => &self.blk_ratelimit,
            "threat_score" => &self.blk_threat,
            "ip_blacklist" | "ip_whitelist" => &self.blk_iplist,
            "anomaly" => &self.blk_anomaly,
            "ml" => &self.blk_threat,
            _ => &self.blk_rule,
        };
        c.fetch_add(1, Ordering::Relaxed);
        // classify the attack type from a substring of sig
        let s = sig.to_ascii_lowercase();
        let atk = if s.contains("sqli") || s.contains("sql") { Some(&self.atk_sqli) }
            else if s.contains("xss") { Some(&self.atk_xss) }
            else if s.contains("traversal") || s.contains("lfi_path") { Some(&self.atk_traversal) }
            else if s.contains("rce") || s.contains("cmd") { Some(&self.atk_rce) }
            else if s.contains("lfi") || s.contains("rfi") { Some(&self.atk_lfi) }
            else if s.contains("scan") || s.contains("bot") { Some(&self.atk_scanner) }
            else { None };
        if let Some(a) = atk { a.fetch_add(1, Ordering::Relaxed); }
        else if sig == "rule" { self.atk_general.fetch_add(1, Ordering::Relaxed); }
    }

    /// Record the threat level from the Threat Score value.
    pub fn record_threat_level(&self, score: u32) {
        let c = if score >= 60 { &self.threat_high }
            else if score >= 30 { &self.threat_medium }
            else { &self.threat_low };
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// Record latency, for the mean.
    pub fn record_latency(&self, ms: u32) {
        self.lat_sum_ms.fetch_add(ms as u64, Ordering::Relaxed);
        self.lat_count.fetch_add(1, Ordering::Relaxed);
        // cumulative histogram: increment every bucket whose boundary is >= ms
        let v = ms as u64;
        for (i, &b) in LAT_BUCKETS.iter().enumerate() {
            if v <= b { self.lat_b[i].fetch_add(1, Ordering::Relaxed); }
        }
        self.lat_b[11].fetch_add(1, Ordering::Relaxed); // +Inf
    }

    /// Backend (upstream) latency, tracked apart from the total.
    pub fn record_upstream_latency(&self, ms: u32) {
        self.up_lat_sum_ms.fetch_add(ms as u64, Ordering::Relaxed);
        self.up_lat_count.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_upstream_error(&self) { self.up_errors.fetch_add(1, Ordering::Relaxed); }
    pub fn record_overloaded(&self) { self.overloaded_total.fetch_add(1, Ordering::Relaxed); }
    pub fn record_breaker_open(&self) { self.breaker_open_total.fetch_add(1, Ordering::Relaxed); }

    /// Outcome of a challenge check.
    pub fn record_challenge(&self, passed: bool) {
        if passed { self.challenge_passed.fetch_add(1, Ordering::Relaxed); }
        else { self.challenge_failed.fetch_add(1, Ordering::Relaxed); }
    }

    /// ML inference: called on every model run.
    pub fn record_ml(&self, proba: f64, hit: bool) {
        self.ml_evals.fetch_add(1, Ordering::Relaxed);
        if hit { self.ml_hits.fetch_add(1, Ordering::Relaxed); }
        self.ml_proba_sum_x1000.fetch_add((proba * 1000.0) as u64, Ordering::Relaxed);
        let b = if proba < 0.25 { &self.ml_b0 }
                else if proba < 0.5 { &self.ml_b1 }
                else if proba < 0.8 { &self.ml_b2 }
                else { &self.ml_b3 };
        b.fetch_add(1, Ordering::Relaxed);
    }

    /// Record per-site metrics (host). outcome: "pass" | "block" | other.
    /// lat_ms is the total latency; up_lat_ms is the backend latency (0 if there was none).
    pub fn record_host(&self, host: &str, outcome: &str, lat_ms: u32, up_lat_ms: u32) {
        if host.is_empty() { return; }
        let h = self.per_host.entry(host.to_string()).or_default();
        h.requests.fetch_add(1, Ordering::Relaxed);
        match outcome {
            "block" | "blocked" => { h.blocked.fetch_add(1, Ordering::Relaxed); }
            "pass" | "passed" => { h.passed.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
        if lat_ms > 0 {
            h.lat_sum_ms.fetch_add(lat_ms as u64, Ordering::Relaxed);
            h.lat_count.fetch_add(1, Ordering::Relaxed);
        }
        if up_lat_ms > 0 {
            h.up_lat_sum_ms.fetch_add(up_lat_ms as u64, Ordering::Relaxed);
            h.up_lat_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn avg_latency(&self) -> f64 {
        let c = self.lat_count.load(Ordering::Relaxed);
        if c == 0 { 0.0 } else { self.lat_sum_ms.load(Ordering::Relaxed) as f64 / c as f64 }
    }

    /// Process RSS in bytes (Linux /proc/self/statm).
    fn process_rss_bytes(&self) -> u64 {
        if let Ok(s) = std::fs::read_to_string("/proc/self/statm") {
            // the second field holds resident pages
            if let Some(pages) = s.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()) {
                return pages * 4096; // 4 KB page size
            }
        }
        0
    }

    /// Record a request: update the total, the status class and the RPS ring.
    pub fn record(&self, status: u16) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        match status {
            200..=299 => { self.status_2xx.fetch_add(1, Ordering::Relaxed); }
            300..=399 => { self.status_3xx.fetch_add(1, Ordering::Relaxed); }
            400..=499 => { self.status_4xx.fetch_add(1, Ordering::Relaxed); }
            500..=599 => { self.status_5xx.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
        let t = now();
        let slot = (t as usize) % WINDOW_SECS;
        // atomic slot update: if the second matches, increment the counter;
        // otherwise overwrite the slot with the new second and a counter of 1. CAS loop.
        let cell = &self.ring[slot];
        loop {
            let cur = cell.load(Ordering::Relaxed);
            let cur_sec = cur >> 32;
            let cur_cnt = cur & 0xFFFF_FFFF;
            let new_val = if cur_sec == t {
                (t << 32) | ((cur_cnt + 1) & 0xFFFF_FFFF)
            } else {
                (t << 32) | 1
            };
            if cell.compare_exchange_weak(cur, new_val, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                break;
            }
        }
    }

    pub fn inc_blocked(&self) { self.blocked_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_challenged(&self) { self.challenged_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_detected(&self) { self.detected_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_passed(&self) { self.passed_total.fetch_add(1, Ordering::Relaxed); }
    pub fn add_bytes(&self, inb: u64, outb: u64) {
        self.bytes_in.fetch_add(inb, Ordering::Relaxed);
        self.bytes_out.fetch_add(outb, Ordering::Relaxed);
    }
    pub fn conn_open(&self) { self.active_conns.fetch_add(1, Ordering::Relaxed); }
    pub fn conn_close(&self) { self.active_conns.fetch_sub(1, Ordering::Relaxed); }
    pub fn tls_handshake_ok(&self) { self.tls_handshakes_ok.fetch_add(1, Ordering::Relaxed); }
    pub fn tls_handshake_fail(&self) { self.tls_handshakes_fail.fetch_add(1, Ordering::Relaxed); }
    #[allow(dead_code)]
    pub fn set_policy_version(&self, v: u64) { self.policy_version.store(v, Ordering::Relaxed); }

    /// Live RPS: the mean over the last `secs` seconds from the ring, excluding the current partial second.
    pub fn rps(&self, secs: u64) -> f64 {
        let secs = secs.clamp(1, WINDOW_SECS as u64);
        let t = now();
        let mut sum = 0u64;
        for cell in self.ring.iter() {
            let v = cell.load(Ordering::Relaxed);
            let sec = v >> 32;
            let cnt = v & 0xFFFF_FFFF;
            // count seconds in the window [t-secs, t-1], excluding the current partial one
            if sec >= t.saturating_sub(secs) && sec < t {
                sum += cnt;
            }
        }
        sum as f64 / secs as f64
    }

    /// JSON snapshot for the UI.
    pub fn json(&self, node_id: &str) -> serde_json::Value {
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        serde_json::json!({
            "node_id": node_id,
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": now().saturating_sub(self.started),
            "requests_total": l(&self.requests_total),
            "blocked_total": l(&self.blocked_total),
            "challenged_total": l(&self.challenged_total),
            "detected_total": l(&self.detected_total),
            "passed_total": l(&self.passed_total),
            "status_2xx": l(&self.status_2xx),
            "status_3xx": l(&self.status_3xx),
            "status_4xx": l(&self.status_4xx),
            "status_5xx": l(&self.status_5xx),
            "bytes_in": l(&self.bytes_in),
            "bytes_out": l(&self.bytes_out),
            "active_conns": self.active_conns.load(Ordering::Relaxed),
            "tls_handshakes_ok": self.tls_handshakes_ok.load(Ordering::Relaxed),
            "tls_handshakes_fail": self.tls_handshakes_fail.load(Ordering::Relaxed),
            "policy_version": l(&self.policy_version),
            "rps_5s": self.rps(5),
            "rps_30s": self.rps(30),
            "rps_60s": self.rps(60),
            "avg_latency_ms": self.avg_latency(),
            "process_rss_bytes": self.process_rss_bytes(),
            "methods": {
                "GET": l(&self.m_get), "POST": l(&self.m_post), "PUT": l(&self.m_put),
                "PATCH": l(&self.m_patch), "DELETE": l(&self.m_delete), "OTHER": l(&self.m_other),
            },
            "blocked_by": {
                "rule": l(&self.blk_rule), "bot": l(&self.blk_bot), "geo": l(&self.blk_geo),
                "ratelimit": l(&self.blk_ratelimit), "threat_score": l(&self.blk_threat),
                "ip_list": l(&self.blk_iplist), "anomaly": l(&self.blk_anomaly),
            },
            "threat_levels": {
                "low": l(&self.threat_low), "medium": l(&self.threat_medium), "high": l(&self.threat_high),
            },
            "attacks": {
                "sqli": l(&self.atk_sqli), "xss": l(&self.atk_xss), "traversal": l(&self.atk_traversal),
                "rce": l(&self.atk_rce), "lfi": l(&self.atk_lfi), "scanner": l(&self.atk_scanner),
                "general": l(&self.atk_general),
            },
        })
    }

    /// Prometheus text exposition format.
    pub fn prometheus(&self, node_id: &str, body_buf_now: usize) -> String {
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut s = String::with_capacity(2048);
        let nid = node_id.replace('"', "");
        macro_rules! metric {
            ($name:expr, $help:expr, $typ:expr, $val:expr) => {{
                s.push_str(&format!("# HELP {} {}\n", $name, $help));
                s.push_str(&format!("# TYPE {} {}\n", $name, $typ));
                s.push_str(&format!("{}{{node=\"{}\"}} {}\n", $name, nid, $val));
            }};
        }
        metric!("threatail_requests_total", "Total requests handled", "counter", l(&self.requests_total));
        metric!("threatail_blocked_total", "Total blocked", "counter", l(&self.blocked_total));
        metric!("threatail_challenged_total", "Total challenges issued", "counter", l(&self.challenged_total));
        metric!("threatail_detected_total", "Total detections", "counter", l(&self.detected_total));
        metric!("threatail_passed_total", "Total passed", "counter", l(&self.passed_total));
        metric!("threatail_status_2xx_total", "2xx responses", "counter", l(&self.status_2xx));
        metric!("threatail_status_3xx_total", "3xx responses", "counter", l(&self.status_3xx));
        metric!("threatail_status_4xx_total", "4xx responses", "counter", l(&self.status_4xx));
        metric!("threatail_status_5xx_total", "5xx responses", "counter", l(&self.status_5xx));
        metric!("threatail_bytes_in_total", "Bytes received", "counter", l(&self.bytes_in));
        metric!("threatail_bytes_out_total", "Bytes sent", "counter", l(&self.bytes_out));
        metric!("threatail_active_connections", "Active connections", "gauge", self.active_conns.load(Ordering::Relaxed));
        metric!("threatail_tls_handshakes_ok_total", "Successful TLS handshakes", "counter", l(&self.tls_handshakes_ok));
        metric!("threatail_tls_handshakes_fail_total", "Failed TLS handshakes", "counter", l(&self.tls_handshakes_fail));
        metric!("threatail_policy_version", "Applied policy version", "gauge", l(&self.policy_version));
        metric!("threatail_uptime_seconds", "Process uptime", "gauge", now().saturating_sub(self.started));
        // RPS as a gauge (sliding window)
        s.push_str("# HELP threatail_rps Requests per second (rolling window)\n");
        s.push_str("# TYPE threatail_rps gauge\n");
        s.push_str(&format!("threatail_rps{{node=\"{}\",window=\"5s\"}} {:.3}\n", nid, self.rps(5)));
        s.push_str(&format!("threatail_rps{{node=\"{}\",window=\"30s\"}} {:.3}\n", nid, self.rps(30)));
        s.push_str(&format!("threatail_rps{{node=\"{}\",window=\"60s\"}} {:.3}\n", nid, self.rps(60)));

        // mean latency
        metric!("threatail_latency_avg_ms", "Average response latency (ms)", "gauge", format!("{:.1}", self.avg_latency()));
        // latency histogram (for p50/p95/p99 via histogram_quantile)
        s.push_str("# HELP threatail_latency_ms Response latency histogram (ms)\n# TYPE threatail_latency_ms histogram\n");
        for (i, &b) in LAT_BUCKETS.iter().enumerate() {
            s.push_str(&format!("threatail_latency_ms_bucket{{node=\"{}\",le=\"{}\"}} {}\n", nid, b, l(&self.lat_b[i])));
        }
        s.push_str(&format!("threatail_latency_ms_bucket{{node=\"{}\",le=\"+Inf\"}} {}\n", nid, l(&self.lat_b[11])));
        s.push_str(&format!("threatail_latency_ms_sum{{node=\"{}\"}} {}\n", nid, l(&self.lat_sum_ms)));
        s.push_str(&format!("threatail_latency_ms_count{{node=\"{}\"}} {}\n", nid, l(&self.lat_count)));
        // backend (upstream) latency and errors
        let up_c = l(&self.up_lat_count);
        let up_avg = if up_c == 0 { 0.0 } else { l(&self.up_lat_sum_ms) as f64 / up_c as f64 };
        metric!("threatail_upstream_latency_avg_ms", "Average backend latency (ms, since start)", "gauge", format!("{:.1}", up_avg));
        // raw counters for a WINDOWED mean in Grafana: rate(sum)/rate(count)
        s.push_str(&format!("# HELP threatail_upstream_latency_ms_sum Sum of backend latencies (ms)\n# TYPE threatail_upstream_latency_ms_sum counter\nthreatail_upstream_latency_ms_sum{{node=\"{}\"}} {}\n", nid, l(&self.up_lat_sum_ms)));
        s.push_str(&format!("# HELP threatail_upstream_latency_ms_count Backend request count\n# TYPE threatail_upstream_latency_ms_count counter\nthreatail_upstream_latency_ms_count{{node=\"{}\"}} {}\n", nid, up_c));
        metric!("threatail_upstream_errors_total", "Backend connection errors", "counter", l(&self.up_errors));
        metric!("threatail_overloaded_total", "Requests shed due to RAM body-buffer budget (503)", "counter", l(&self.overloaded_total));
        metric!("threatail_body_buffer_bytes", "Current total request-body bytes buffered in RAM", "gauge", body_buf_now);
        metric!("threatail_breaker_open_total", "Backend circuit-breaker open transitions", "counter", l(&self.breaker_open_total));
        // challenge
        metric!("threatail_challenge_passed_total", "Challenge passed (human)", "counter", l(&self.challenge_passed));
        metric!("threatail_challenge_failed_total", "Challenge failed (bot)", "counter", l(&self.challenge_failed));
        // ML inference
        metric!("threatail_ml_evaluations_total", "ML model evaluations", "counter", l(&self.ml_evals));
        metric!("threatail_ml_hits_total", "ML hits (proba>=threshold)", "counter", l(&self.ml_hits));
        let ml_c = l(&self.ml_evals);
        let ml_avg = if ml_c == 0 { 0.0 } else { l(&self.ml_proba_sum_x1000) as f64 / 1000.0 / ml_c as f64 };
        metric!("threatail_ml_proba_avg", "Average ML attack probability", "gauge", format!("{:.4}", ml_avg));
        metric!("threatail_ml_score_lt025_total", "ML score in [0,0.25)", "counter", l(&self.ml_b0));
        metric!("threatail_ml_score_025_05_total", "ML score in [0.25,0.5)", "counter", l(&self.ml_b1));
        metric!("threatail_ml_score_05_08_total", "ML score in [0.5,0.8)", "counter", l(&self.ml_b2));
        metric!("threatail_ml_score_gte08_total", "ML score in [0.8,1]", "counter", l(&self.ml_b3));
        // process memory
        metric!("threatail_process_memory_bytes", "Process RSS memory (bytes)", "gauge", self.process_rss_bytes());

        // per-site metrics (host label), for filtering by site in Grafana
        s.push_str("# HELP threatail_site_requests_total Requests per site\n# TYPE threatail_site_requests_total counter\n");
        for e in self.per_host.iter() {
            s.push_str(&format!("threatail_site_requests_total{{node=\"{}\",host=\"{}\"}} {}\n",
                nid, e.key().replace('"', ""), e.requests.load(Ordering::Relaxed)));
        }
        s.push_str("# HELP threatail_site_blocked_total Blocked per site\n# TYPE threatail_site_blocked_total counter\n");
        for e in self.per_host.iter() {
            s.push_str(&format!("threatail_site_blocked_total{{node=\"{}\",host=\"{}\"}} {}\n",
                nid, e.key().replace('"', ""), e.blocked.load(Ordering::Relaxed)));
        }
        s.push_str("# HELP threatail_site_passed_total Passed per site\n# TYPE threatail_site_passed_total counter\n");
        for e in self.per_host.iter() {
            s.push_str(&format!("threatail_site_passed_total{{node=\"{}\",host=\"{}\"}} {}\n",
                nid, e.key().replace('"', ""), e.passed.load(Ordering::Relaxed)));
        }
        // mean WAF and backend latency per site (gauge)
        s.push_str("# HELP threatail_site_latency_avg_ms Average response latency per site (ms)\n# TYPE threatail_site_latency_avg_ms gauge\n");
        for e in self.per_host.iter() {
            let cnt = e.lat_count.load(Ordering::Relaxed);
            let avg = if cnt == 0 { 0.0 } else { e.lat_sum_ms.load(Ordering::Relaxed) as f64 / cnt as f64 };
            s.push_str(&format!("threatail_site_latency_avg_ms{{node=\"{}\",host=\"{}\"}} {:.1}\n",
                nid, e.key().replace('"', ""), avg));
        }
        s.push_str("# HELP threatail_site_upstream_latency_avg_ms Average backend latency per site (ms)\n# TYPE threatail_site_upstream_latency_avg_ms gauge\n");
        for e in self.per_host.iter() {
            let cnt = e.up_lat_count.load(Ordering::Relaxed);
            let avg = if cnt == 0 { 0.0 } else { e.up_lat_sum_ms.load(Ordering::Relaxed) as f64 / cnt as f64 };
            s.push_str(&format!("threatail_site_upstream_latency_avg_ms{{node=\"{}\",host=\"{}\"}} {:.1}\n",
                nid, e.key().replace('"', ""), avg));
        }

        // methods (method label)
        s.push_str("# HELP threatail_requests_by_method_total Requests by HTTP method\n# TYPE threatail_requests_by_method_total counter\n");
        for (m, a) in [("GET",&self.m_get),("POST",&self.m_post),("PUT",&self.m_put),("PATCH",&self.m_patch),("DELETE",&self.m_delete),("OTHER",&self.m_other)] {
            s.push_str(&format!("threatail_requests_by_method_total{{node=\"{}\",method=\"{}\"}} {}\n", nid, m, l(a)));
        }
        // blocks by source (source label)
        s.push_str("# HELP threatail_blocked_by_source_total Blocks by source\n# TYPE threatail_blocked_by_source_total counter\n");
        for (src, a) in [("rule",&self.blk_rule),("bot",&self.blk_bot),("geo",&self.blk_geo),("ratelimit",&self.blk_ratelimit),("threat_score",&self.blk_threat),("ip_list",&self.blk_iplist),("anomaly",&self.blk_anomaly)] {
            s.push_str(&format!("threatail_blocked_by_source_total{{node=\"{}\",source=\"{}\"}} {}\n", nid, src, l(a)));
        }
        // threat levels (level label)
        s.push_str("# HELP threatail_threat_level_total Requests by threat level\n# TYPE threatail_threat_level_total counter\n");
        for (lv, a) in [("low",&self.threat_low),("medium",&self.threat_medium),("high",&self.threat_high)] {
            s.push_str(&format!("threatail_threat_level_total{{node=\"{}\",level=\"{}\"}} {}\n", nid, lv, l(a)));
        }
        // attack types (type label)
        s.push_str("# HELP threatail_attacks_total Attacks by type\n# TYPE threatail_attacks_total counter\n");
        for (ty, a) in [("sqli",&self.atk_sqli),("xss",&self.atk_xss),("traversal",&self.atk_traversal),("rce",&self.atk_rce),("lfi",&self.atk_lfi),("scanner",&self.atk_scanner),("general",&self.atk_general)] {
            s.push_str(&format!("threatail_attacks_total{{node=\"{}\",type=\"{}\"}} {}\n", nid, ty, l(a)));
        }
        s
    }
}
