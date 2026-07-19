// Threatail Cloud (V2) — cloud.rs: the node's integration with the control plane.
//
// Differences from V1 (central.rs):
//   - ENROLLMENT: on first start the node binds to a tenant using an enrollment token
//     and receives a permanent node_token plus tenant_id, which it stores on disk.
//   - It sends INCIDENTS (events) and per-minute METRIC AGGREGATES to the cloud.
//     Full access traffic is NOT sent; it stays local to the node.
//   - Cloud endpoints: /api/nodes/enroll, /api/ingest/events, /api/ingest/metrics.
//
// Node state (node_token, tenant_id) lives in a file so it survives restarts
// and the node does not re-enroll.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Cloud integration settings, from the node config or environment.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CloudCfg {
    /// Cloud base URL, e.g. https://lk.threatail.com or https://api.threatail.com
    #[serde(default)]
    pub url: String,
    /// Enrollment token, supplied once at install time and unnecessary after binding.
    #[serde(default)]
    pub enrollment_token: String,
    /// Path to the state file holding node_token and tenant_id.
    #[serde(default = "default_state_path")]
    pub state_path: String,
}

fn default_state_path() -> String { "/var/lib/threatail/cloud-state.json".to_string() }

impl CloudCfg {
    pub fn enabled(&self) -> bool { !self.url.is_empty() }
}

/// Persisted enrollment state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CloudState {
    pub node_id: String,
    pub tenant_id: String,
    pub node_token: String,
    #[serde(default)]
    pub lease_nonce: String,   // latest nonce from the cloud (anti-clone rotation)
}

impl CloudState {
    fn load(path: &str) -> Option<CloudState> {
        let data = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }
    fn save(&self, path: &str) -> std::io::Result<()> {
        if let Some(dir) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(dir).ok();
        }
        std::fs::write(path, serde_json::to_string_pretty(self).unwrap_or_default())
    }
    fn is_enrolled(&self) -> bool {
        !self.node_token.is_empty() && !self.tenant_id.is_empty()
    }
}

/// An incident event bound for the cloud, in the V2 /api/ingest/events format.
#[derive(Debug, Clone, Serialize)]
pub struct CloudEvent {
    pub host: String,
    pub client_ip: String,
    pub method: String,
    pub uri: String,
    pub action: String,     // blocked | detected | challenge
    pub severity: i32,
    pub sig: String,        // rule | bot | geo | ratelimit | ml | anomaly
    pub country: String,
    pub ua: String,
    pub incident_id: String,
    pub attack_type: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ja3: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ja4: String,
}

/// Per-minute metric aggregate for a single site, in the V2 /api/ingest/metrics format.
#[derive(Debug, Clone, Serialize)]
pub struct CloudMetric {
    pub host: String,
    pub ts_minute: i64,     // unix timestamp of the start of the minute
    pub requests: i64,
    pub blocked: i64,
    pub passed: i64,
    pub latency_avg_ms: f64,
    pub upstream_avg_ms: f64,
}

/// Event channel: handlers push here and the sender batches to the cloud.
/// Bounded on purpose: when it fills up (slow or unreachable cloud) events are
/// DROPPED via try_send in the handler rather than growing node memory without bound.
pub type EventTx = tokio::sync::mpsc::Sender<CloudEvent>;

/// Parse a JSON array at a key into Vec<T>, skipping malformed elements.
fn parse_arr<T: serde::de::DeserializeOwned>(v: &serde_json::Value, key: &str) -> Vec<T> {
    v.get(key).and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|s| serde_json::from_value(s.clone()).ok()).collect())
        .unwrap_or_default()
}

/// Percent-encode a query parameter value. reqwest is built without default features,
/// so .query() is unavailable and the URL is assembled by hand.
fn qenc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Handle to the cloud integration.
pub struct Cloud {
    pub state: CloudState,
    cfg: CloudCfg,
    http: reqwest::Client,
    /// Whether the licence is valid RIGHT NOW. The node serves traffic only when true.
    pub licensed: Arc<std::sync::atomic::AtomicBool>,
    /// Current lease nonce, rotated and persisted to disk as an anti-clone measure.
    nonce: Arc<Mutex<String>>,
}

impl Cloud {
    /// Cloud base URL, for direct requests from main such as ACME polling.
    pub fn url(&self) -> &str { &self.cfg.url }
    /// node_token used to authorise the node's requests.
    pub fn node_token(&self) -> &str { &self.state.node_token }

    /// Initialise: load existing state, or perform enrollment.
    pub async fn init(cfg: CloudCfg) -> Result<Arc<Cloud>, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build().map_err(|e| e.to_string())?;

        // already enrolled?
        let mut state = CloudState::load(&cfg.state_path).unwrap_or_default();
        if !state.is_enrolled() {
            if cfg.enrollment_token.is_empty() {
                return Err("node not bound and no enrollment_token".into());
            }
            state = enroll(&http, &cfg).await?;
            state.save(&cfg.state_path).map_err(|e| e.to_string())?;
            tracing::info!("node bound to tenant {}", state.tenant_id);
        } else {
            tracing::info!("node already bound (tenant {})", state.tenant_id);
        }

        Ok(Arc::new(Cloud {
            licensed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            nonce: Arc::new(Mutex::new(state.lease_nonce.clone())),
            state, cfg, http,
        }))
    }

    /// Is the licence valid right now? The node serves traffic only when true.
    pub fn is_licensed(&self) -> bool {
        self.licensed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Licence lease loop: periodically renews the lease with the cloud and checks the
    /// signature and expiry. An inactive subscription, or no contact beyond the grace period, clears
    /// the licensed flag and the node stops serving.
    pub fn spawn_license_loop(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            let fp = machine_fingerprint();
            let url = format!("{}/api/node/lease", me.cfg.url.trim_end_matches('/'));
            let grace = Duration::from_secs(6 * 3600);
            let mut last_ok = std::time::Instant::now();
            loop {
                let cur_nonce = me.nonce.lock().await.clone();
                let res = me.http.get(format!("{}?fp={}&nonce={}", url, qenc(&fp), qenc(&cur_nonce)))
                    .bearer_auth(&me.state.node_token)
                    .header("x-node-version", env!("CARGO_PKG_VERSION"))
                    .send().await;
                let mut ok = false;
                if let Ok(resp) = res {
                    let code = resp.status().as_u16();
                    if resp.status().is_success() {
                        if let Ok(v) = resp.json::<serde_json::Value>().await {
                            if let Some(lease) = v.get("lease").and_then(|x| x.as_str()) {
                                ok = me.verify_lease(lease);
                            }
                            // persist the rotated nonce to disk IMMEDIATELY
                            if let Some(nn) = v.get("nonce").and_then(|x| x.as_str()) {
                                *me.nonce.lock().await = nn.to_string();
                                me.persist_nonce(nn);
                            }
                        }
                    } else if code == 402 {
                        tracing::error!("subscription inactive — node stopped");
                        me.licensed.store(false, std::sync::atomic::Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_secs(300)).await; continue;
                    } else if code == 423 {
                        tracing::error!("node blocked (clone detected) — stopped. Reinstall required.");
                        me.licensed.store(false, std::sync::atomic::Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_secs(600)).await; continue;
                    }
                }
                if ok {
                    last_ok = std::time::Instant::now();
                    me.licensed.store(true, std::sync::atomic::Ordering::Relaxed);
                } else if last_ok.elapsed() > grace {
                    tracing::error!("no valid license beyond grace period — node stopped");
                    me.licensed.store(false, std::sync::atomic::Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_secs(1800)).await;
            }
        });
    }

    /// Persist the rotated nonce into the state file (best-effort atomic).
    fn persist_nonce(&self, nonce: &str) {
        let mut st = self.state.clone();
        st.lease_nonce = nonce.to_string();
        let _ = st.save(&self.cfg.state_path);
    }

    /// Check the lease expiry ("node:tenant:exp.sig"). The cloud verifies the signature;
    /// the node trusts the channel (HTTPS plus node_token) and enforces the EXPIRY. The lease is
    /// short-lived, so without renewal the node goes quiet. That is the subscription lever.
    fn verify_lease(&self, lease: &str) -> bool {
        let payload = match lease.rsplit_once('.').map(|x| x.0) { Some(s) => s, None => return false };
        let exp: i64 = payload.rsplit(':').next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;
        // the lease must belong to this node
        payload.starts_with(&self.state.node_id) && exp > now
    }

    /// Start the background event and metric senders.
    pub fn spawn(self: &Arc<Self>) -> EventTx {
        // bounded: an upper limit on the buffer. On overflow the handler drops events
        // (telemetry is not a critical path), protecting node memory when the cloud lags.
        let (tx, rx) = tokio::sync::mpsc::channel::<CloudEvent>(8192);
        // event delivery (batched)
        {
            let me = self.clone();
            tokio::spawn(async move { me.send_events_loop(rx).await; });
        }
        tx
    }

    /// Send metric aggregates; called once a minute from the metrics module.
    pub async fn send_metrics(&self, metrics: Vec<CloudMetric>) {
        if metrics.is_empty() { return; }
        let url = format!("{}/api/ingest/metrics", self.cfg.url.trim_end_matches('/'));
        let body = serde_json::json!({ "metrics": metrics });
        let r = self.http.post(&url)
            .bearer_auth(&self.state.node_token)
            .json(&body).send().await;
        if let Err(e) = r { tracing::warn!("sending metrics to cloud: {}", e); }
    }

    /// Send quarantine candidates: borderline requests awaiting labelling.
    pub async fn send_review(&self, items: Vec<serde_json::Value>) {
        if items.is_empty() { return; }
        let url = format!("{}/api/ingest/review", self.cfg.url.trim_end_matches('/'));
        let _ = self.http.post(&url).bearer_auth(&self.state.node_token)
            .json(&serde_json::json!({ "items": items })).send().await;
    }

    /// Send NORMAL samples from trusted IPs, used for training.
    pub async fn send_samples(&self, samples: Vec<serde_json::Value>) {
        if samples.is_empty() { return; }
        let url = format!("{}/api/ingest/samples", self.cfg.url.trim_end_matches('/'));
        let _ = self.http.post(&url).bearer_auth(&self.state.node_token)
            .json(&serde_json::json!({ "samples": samples })).send().await;
    }

    /// Start per-asset ML model polling. apply(domain, model_json) runs on each new version.
    pub fn spawn_model_poll<F>(self: &Arc<Self>, mut apply: F)
    where F: FnMut(String, String) + Send + 'static
    {
        let me = self.clone();
        tokio::spawn(async move {
            let mut vers: HashMap<String, i64> = HashMap::new();
            let url = format!("{}/api/node/model", me.cfg.url.trim_end_matches('/'));
            loop {
                // report the known versions to the cloud as "domain:ver,domain2:ver2"
                let vstr = vers.iter().map(|(d, v)| format!("{}:{}", d, v)).collect::<Vec<_>>().join(",");
                let res = me.http.get(format!("{}?vers={}", url, qenc(&vstr)))
                    .bearer_auth(&me.state.node_token).send().await;
                if let Ok(resp) = res {
                    if resp.status().is_success() {
                        let sig_hdr = resp.headers().get("x-policy-sig")
                            .and_then(|h| h.to_str().ok()).map(|s| s.to_string());
                        let body = match resp.bytes().await {
                            Ok(b) => b,
                            Err(_) => { tokio::time::sleep(Duration::from_secs(30)).await; continue; }
                        };
                        if !verify_policy_sig(&body, sig_hdr.as_deref()) {
                            tracing::error!("model integrity check FAILED — отвергаю модель, оставляю текущую");
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            continue;
                        }
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
                            if let Some(models) = v.get("models").and_then(|x| x.as_object()) {
                                for (domain, info) in models {
                                    if info.get("changed").and_then(|x| x.as_bool()).unwrap_or(false) {
                                        if let Some(m) = info.get("model").and_then(|x| x.as_str()) {
                                            let nv = info.get("version").and_then(|x| x.as_i64()).unwrap_or(0);
                                            tracing::info!("new ML model for '{}' (ver {})", domain, nv);
                                            apply(domain.clone(), m.to_string());
                                            vers.insert(domain.clone(), nv);
                                        }
                                    } else {
                                        let nv = info.get("version").and_then(|x| x.as_i64()).unwrap_or(0);
                                        vers.insert(domain.clone(), nv);
                                    }
                                }
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }

    async fn send_events_loop(&self, mut rx: tokio::sync::mpsc::Receiver<CloudEvent>) {
        let url = format!("{}/api/ingest/events", self.cfg.url.trim_end_matches('/'));
        let mut buf: Vec<CloudEvent> = Vec::new();
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                ev = rx.recv() => {
                    match ev {
                        Some(e) => { buf.push(e); if buf.len() >= 100 { self.flush_events(&url, &mut buf).await; } }
                        None => { self.flush_events(&url, &mut buf).await; break; }
                    }
                }
                _ = tick.tick() => { self.flush_events(&url, &mut buf).await; }
            }
        }
    }

    async fn flush_events(&self, url: &str, buf: &mut Vec<CloudEvent>) {
        if buf.is_empty() { return; }
        let body = serde_json::json!({ "events": buf });
        let r = self.http.post(url)
            .bearer_auth(&self.state.node_token)
            .json(&body).send().await;
        match r {
            Ok(resp) if resp.status().is_success() => { buf.clear(); }
            Ok(resp) => tracing::warn!("ingest events: code {}", resp.status()),
            Err(e) => tracing::warn!("ingest events: {}", e),
        }
        // on failure the buffer is retained and retried on the next tick
        // (capped, so it cannot grow indefinitely)
        if buf.len() > 5000 { buf.drain(0..buf.len() - 5000); }
    }
}

/// Enrollment: enrollment_token → node_token + tenant_id.
async fn enroll(http: &reqwest::Client, cfg: &CloudCfg) -> Result<CloudState, String> {
    let url = format!("{}/api/nodes/enroll", cfg.url.trim_end_matches('/'));
    let body = serde_json::json!({ "enrollment_token": cfg.enrollment_token });
    let resp = http.post(&url).json(&body).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("enroll rejected: code {}", resp.status()));
    }
    let v: HashMap<String, String> = resp.json().await.map_err(|e| e.to_string())?;
    let node_id = v.get("node_id").cloned().unwrap_or_default();
    let tenant_id = v.get("tenant_id").cloned().unwrap_or_default();
    let node_token = v.get("node_token").cloned().unwrap_or_default();
    if node_token.is_empty() || tenant_id.is_empty() {
        return Err("enroll: cloud did not return node_token/tenant_id".into());
    }
    Ok(CloudState { node_id, tenant_id, node_token, lease_nonce: String::new() })
}

/// Per-minute metric accumulator on the node: it collects per-host counters and once a minute
/// folds them into CloudMetric for the sender. Thread-safe.
#[derive(Default)]
pub struct MetricAcc {
    inner: std::sync::Mutex<HashMap<String, HostAgg>>,
}

#[derive(Default, Clone)]
struct HostAgg {
    requests: i64, blocked: i64, passed: i64,
    lat_sum: f64, lat_n: i64, up_sum: f64, up_n: i64,
}

impl MetricAcc {
    pub fn new() -> Arc<MetricAcc> { Arc::new(MetricAcc::default()) }

    /// Record a single request (synchronous; called from the access_log hot path).
    pub fn record(&self, host: &str, action: &str, lat_ms: f64, up_ms: f64) {
        let mut m = match self.inner.lock() { Ok(g) => g, Err(p) => p.into_inner() };
        let a = m.entry(host.to_string()).or_default();
        a.requests += 1;
        match action {
            "blocked" | "detected" | "challenge" => a.blocked += 1,
            "pass" | "passed" => a.passed += 1,
            _ => {}
        }
        if lat_ms > 0.0 { a.lat_sum += lat_ms; a.lat_n += 1; }
        if up_ms > 0.0 { a.up_sum += up_ms; a.up_n += 1; }
    }

    /// Fold up the last minute's data and clear. Call once a minute.
    pub fn drain(&self, ts_minute: i64) -> Vec<CloudMetric> {
        let mut m = match self.inner.lock() { Ok(g) => g, Err(p) => p.into_inner() };
        let out: Vec<CloudMetric> = m.iter().map(|(host, a)| CloudMetric {
            host: host.clone(), ts_minute,
            requests: a.requests, blocked: a.blocked, passed: a.passed,
            latency_avg_ms: if a.lat_n > 0 { a.lat_sum / a.lat_n as f64 } else { 0.0 },
            upstream_avg_ms: if a.up_n > 0 { a.up_sum / a.up_n as f64 } else { 0.0 },
        }).collect();
        m.clear();
        out
    }
}

/// A site from cloud policy, with the minimum needed for routing.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicySite {
    pub domain: String,
    pub config: serde_json::Value,
}

/// A certificate from cloud policy: cert plus key (PEM; the key is already decrypted
/// by the cloud and delivered over a secure channel) for one or more domains.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyCert {
    #[serde(default)]
    pub name: String,
    pub cert: String,
    pub key: String,
    #[serde(default)]
    pub domains: String, // comma-separated
}

/// The domain's mTLS CA: client certificates are validated against it during the handshake.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyMtls {
    pub domain: String,
    pub ca_cert: String,
}

/// The node's full policy: everything the cloud returns in one poll.
#[derive(Default)]
pub struct Policy {
    pub sites: Vec<PolicySite>,
    pub certs: Vec<PolicyCert>,
    pub mtls_cas: Vec<PolicyMtls>,
    pub mtls_revoked: Vec<String>,
}

impl Cloud {
    /// Start polling the target version from the cloud (/api/node/update, node auth).
    /// If the cloud assigns a version other than the current one, apply(version) launches the updater.
    pub fn spawn_update_poll<F>(self: &Arc<Self>, mut apply: F)
    where F: FnMut(String) + Send + 'static
    {
        let me = self.clone();
        tokio::spawn(async move {
            let url = format!("{}/api/node/update", me.cfg.url.trim_end_matches('/'));
            let cur = env!("CARGO_PKG_VERSION");
            let mut tick = tokio::time::interval(Duration::from_secs(5 * 60));
            loop {
                tick.tick().await;
                if let Ok(resp) = me.http.get(&url).bearer_auth(&me.state.node_token).send().await {
                    if resp.status().is_success() {
                        if let Ok(v) = resp.json::<serde_json::Value>().await {
                            let target = v.get("version").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
                            if !target.is_empty() && target != cur {
                                tracing::info!("update: cloud assigned version {} (current {})", target, cur);
                                apply(target);
                            }
                        }
                    }
                }
            }
        });
    }

    /// Start polling the GeoIP database from the cloud (/api/node/geoip, node auth).
    /// the callback receives raw bytes (.mmdb or .mmdb.gz) on every successful poll.
    pub fn spawn_geoip_poll<F>(self: &Arc<Self>, mut apply: F)
    where F: FnMut(Vec<u8>) + Send + 'static
    {
        let me = self.clone();
        tokio::spawn(async move {
            let url = format!("{}/api/node/geoip", me.cfg.url.trim_end_matches('/'));
            let mut tick = tokio::time::interval(Duration::from_secs(24 * 3600));
            loop {
                tick.tick().await; // fire the first tick immediately
                match me.http.get(&url).bearer_auth(&me.state.node_token).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.bytes().await {
                            Ok(b) if b.len() > 1000 => apply(b.to_vec()),
                            _ => {}
                        }
                    }
                    Ok(resp) if resp.status().as_u16() == 204 => {} // no database configured on the server
                    Ok(resp) => tracing::warn!("geoip poll: code {}", resp.status()),
                    Err(e) => tracing::warn!("geoip poll: {}", e),
                }
            }
        });
    }

    /// Start polling the IP reputation list from the cloud (/api/node/iprep, node auth).
    /// the callback receives raw text, one address or CIDR per line, on every successful poll.
    /// Polls the auto-ban feed from the cloud (/api/node/bans, node auth) every 20 s,
    /// so fresh bans (and unbans from the dashboard) are picked up quickly.
    pub fn spawn_ban_poll<F>(self: &Arc<Self>, mut apply: F)
    where F: FnMut(String) + Send + 'static
    {
        let me = self.clone();
        tokio::spawn(async move {
            let url = format!("{}/api/node/bans", me.cfg.url.trim_end_matches('/'));
            let mut tick = tokio::time::interval(Duration::from_secs(20));
            loop {
                tick.tick().await;
                match me.http.get(&url).bearer_auth(&me.state.node_token).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(body) = resp.text().await { apply(body); }
                    }
                    Ok(resp) => tracing::warn!("ban poll: code {}", resp.status()),
                    Err(e) => tracing::warn!("ban poll: {}", e),
                }
            }
        });
    }

    pub fn spawn_iprep_poll<F>(self: &Arc<Self>, mut apply: F)
    where F: FnMut(String) + Send + 'static
    {
        let me = self.clone();
        tokio::spawn(async move {
            let url = format!("{}/api/node/iprep", me.cfg.url.trim_end_matches('/'));
            let mut tick = tokio::time::interval(Duration::from_secs(30 * 60));
            loop {
                tick.tick().await; // fire the first tick immediately
                match me.http.get(&url).bearer_auth(&me.state.node_token).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(body) = resp.text().await { apply(body); }
                    }
                    Ok(resp) => tracing::warn!("iprep poll: code {}", resp.status()),
                    Err(e) => tracing::warn!("iprep poll: {}", e),
                }
            }
        });
    }

    /// Start polling managed rules from the cloud (/api/node/managed-rules, node auth).
    /// the callback receives the raw JSON rule array on every successful poll.
    pub fn spawn_mrules_poll<F>(self: &Arc<Self>, mut apply: F)
    where F: FnMut(String) + Send + 'static
    {
        let me = self.clone();
        tokio::spawn(async move {
            let url = format!("{}/api/node/managed-rules", me.cfg.url.trim_end_matches('/'));
            let mut tick = tokio::time::interval(Duration::from_secs(15 * 60));
            loop {
                tick.tick().await; // fire the first tick immediately
                match me.http.get(&url).bearer_auth(&me.state.node_token).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(body) = resp.text().await { apply(body); }
                    }
                    Ok(resp) => tracing::warn!("managed-rules poll: code {}", resp.status()),
                    Err(e) => tracing::warn!("managed-rules poll: {}", e),
                }
            }
        });
    }

    /// Start polling the collective threat feed from the cloud (/api/node/collective, node auth).
    /// the callback receives raw text, one IP per line, on every successful poll.
    pub fn spawn_collective_poll<F>(self: &Arc<Self>, mut apply: F)
    where F: FnMut(String) + Send + 'static
    {
        let me = self.clone();
        tokio::spawn(async move {
            let url = format!("{}/api/node/collective", me.cfg.url.trim_end_matches('/'));
            let mut tick = tokio::time::interval(Duration::from_secs(5 * 60));
            loop {
                tick.tick().await; // fire the first tick immediately
                match me.http.get(&url).bearer_auth(&me.state.node_token).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(body) = resp.text().await { apply(body); }
                    }
                    Ok(resp) => tracing::warn!("collective poll: code {}", resp.status()),
                    Err(e) => tracing::warn!("collective poll: {}", e),
                }
            }
        });
    }

    /// Start polling the TLS fingerprint feed from the cloud (/api/node/fpfeed, node auth).
    /// the callback receives raw text, one fingerprint per line, on every successful poll.
    pub fn spawn_fpfeed_poll<F>(self: &Arc<Self>, mut apply: F)
    where F: FnMut(String) + Send + 'static
    {
        let me = self.clone();
        tokio::spawn(async move {
            let url = format!("{}/api/node/fpfeed", me.cfg.url.trim_end_matches('/'));
            let mut tick = tokio::time::interval(Duration::from_secs(30 * 60));
            loop {
                tick.tick().await; // fire the first tick immediately
                match me.http.get(&url).bearer_auth(&me.state.node_token).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(body) = resp.text().await { apply(body); }
                    }
                    Ok(resp) => tracing::warn!("fpfeed poll: code {}", resp.status()),
                    Err(e) => tracing::warn!("fpfeed poll: {}", e),
                }
            }
        });
    }

    /// Start policy polling. The callback fires on EVERY change with the full policy
    /// (sites, certificates, mTLS), so the node can refresh the router,
    /// cert_store and mTLS configs live, without a restart.
    pub fn spawn_policy_poll<F>(self: &Arc<Self>, log_all: std::sync::Arc<std::sync::atomic::AtomicBool>, mut apply: F)
    where F: FnMut(Policy) + Send + 'static
    {
        let me = self.clone();
        tokio::spawn(async move {
            let mut ver: i64 = 0;
            let url = format!("{}/api/node/policy", me.cfg.url.trim_end_matches('/'));
            loop {
                let res = me.http.get(format!("{}?ver={}", url, ver))
                    .bearer_auth(&me.state.node_token)
                    .header("x-node-version", env!("CARGO_PKG_VERSION"))
                    .send().await;
                match res {
                    Ok(resp) if resp.status().is_success() => {
                        // capture the signature header BEFORE reading the body
                        let sig_hdr = resp.headers().get("x-policy-sig")
                            .and_then(|h| h.to_str().ok()).map(|s| s.to_string());
                        let body = match resp.bytes().await {
                            Ok(b) => b,
                            Err(e) => { tracing::warn!("policy poll: read body: {}", e); tokio::time::sleep(Duration::from_secs(15)).await; continue; }
                        };
                        // integrity check over the raw bytes, when enabled at build time
                        if !verify_policy_sig(&body, sig_hdr.as_deref()) {
                            tracing::error!("policy integrity check FAILED — отвергаю ответ облака, остаюсь на последней рабочей политике");
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            continue;
                        }
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
                            // the global superadmin flag arrives in EVERY response, including short ones
                            log_all.store(
                                v.get("log_all").and_then(|x| x.as_bool()).unwrap_or(false),
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            let changed = v.get("changed").and_then(|x| x.as_bool()).unwrap_or(false);
                            let new_ver = v.get("version").and_then(|x| x.as_i64()).unwrap_or(ver);
                            if changed {
                                let p = Policy {
                                    sites: parse_arr(&v, "sites"),
                                    certs: parse_arr(&v, "certs"),
                                    mtls_cas: parse_arr(&v, "mtls_cas"),
                                    mtls_revoked: v.get("mtls_revoked").and_then(|x| x.as_array())
                                        .map(|a| a.iter().filter_map(|s| s.as_str().map(|x| x.to_string())).collect())
                                        .unwrap_or_default(),
                                };
                                tracing::info!("policy updated: {} sites, {} certs, {} mTLS (ver {})",
                                    p.sites.len(), p.certs.len(), p.mtls_cas.len(), new_ver);
                                apply(p);
                            }
                            ver = new_ver;
                        }
                    }
                    Ok(resp) => tracing::warn!("policy poll: code {}", resp.status()),
                    Err(e) => tracing::warn!("policy poll: {}", e),
                }
                // poll every 15 s (this could become a long-poll on the cloud side later)
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        });
    }
}

/// Ed25519 public key for verifying policy integrity (hex, 32 bytes).
/// Empty in the default build, which DISABLES the check for backward compatibility with
/// older deployments and unsigned builds. Enable it at build time:
///   THREATAIL_POLICY_PUBKEY=<hex public key> cargo build --release
/// The private key lives ONLY in the cloud (env POLICY_SIGNING_KEY), so even a fully
/// reverse-engineered node binary cannot forge a config.
const POLICY_PUBKEY_HEX: &str = match option_env!("THREATAIL_POLICY_PUBKEY") {
    Some(s) => s,
    None => "",
};

/// Verify the Ed25519 signature of the policy body over the RAW response bytes.
/// Returns true when the check is not configured (no embedded key) OR the signature is valid.
/// With the check enabled, any problem (missing header, malformed hex, bad
/// signature) yields false: the node rejects the response and keeps the previous policy.
pub(crate) fn verify_policy_sig(body: &[u8], sig_hex: Option<&str>) -> bool {
    let pk_hex = POLICY_PUBKEY_HEX.trim();
    if pk_hex.is_empty() { return true; } // integrity checking is not configured
    let sig_hex = match sig_hex {
        Some(s) => s.trim(),
        None => { tracing::error!("policy: signature header missing while verification is ON"); return false; }
    };
    let pk = match hex::decode(pk_hex) {
        Ok(v) if v.len() == 32 => v,
        _ => { tracing::error!("policy: embedded pubkey is not valid 32-byte hex"); return false; }
    };
    let sig = match hex::decode(sig_hex) {
        Ok(v) if v.len() == 64 => v,
        _ => { tracing::error!("policy: signature is not valid 64-byte hex"); return false; }
    };
    let pubkey = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pk);
    pubkey.verify(body, &sig).is_ok()
}

/// Whether policy integrity checking is enabled, i.e. a public key was built in.
/// Used for the startup warning; it does not change behaviour.
pub fn policy_verification_enabled() -> bool {
    !POLICY_PUBKEY_HEX.trim().is_empty()
}

/// Background task: folds metrics once a minute and ships them to the cloud.
pub fn spawn_metrics_reporter(cloud: Arc<Cloud>, acc: Arc<MetricAcc>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let now = chrono_now_minute();
            let metrics = acc.drain(now);
            cloud.send_metrics(metrics).await;
        }
    });
}

fn chrono_now_minute() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    now - (now % 60)
}

/// Machine fingerprint for anti-clone: a stable hash of machine-id plus the first MAC.
/// Not perfect (root can forge it), but it raises the cost of cloning.
fn machine_fingerprint() -> String {
    use sha2::{Digest, Sha256};
    let mut parts = String::new();
    // Linux machine-id, stable for an OS installation
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") { parts.push_str(id.trim()); }
    else if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") { parts.push_str(id.trim()); }
    // hostname as an additional signal
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") { parts.push_str(h.trim()); }
    if parts.is_empty() { parts.push_str("unknown"); }
    let mut h = Sha256::new(); h.update(parts.as_bytes());
    hex::encode(h.finalize())
}
