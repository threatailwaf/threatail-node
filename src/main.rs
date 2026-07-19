// Threatail node, stage 2: configuration, multi-domain support and TLS (rustls).
// Listens on HTTP and optionally HTTPS, routes by Host to the site's backend and
// proxies via hyper. We do not write our own HTTP parser. Verdicts come in the next stage.

mod config;
mod apisec;
mod jwks;
mod verbot;
mod ato;
mod dlp;
mod openapi;
mod tls;
mod verdict;
mod ratelimit;
mod netutil;
mod geo;
mod iprep;
mod tlsfp;
mod bot;
mod siginj;
mod fpfeed;
mod ipban;
mod behavior;
mod challenge;
mod i18n;
mod attack;
mod metrics;
mod features;
mod mlmodel;
mod cache;
#[allow(dead_code)] mod central;   // legacy V1 client: only site_from_policy and go_asset_to_site are still used
#[allow(dead_code)] mod cloud;     // cloud integration: enrolment, events and metrics, lease, policy and model polling
#[allow(dead_code)] mod clickhouse;// legacy: unused in V2, where events go to the cloud
mod anomaly;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicU32, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_rustls::HttpsConnector;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::TcpListener;
#[allow(unused_imports)]
use tokio_rustls::TlsAcceptor;

use config::{Config, Router, Site};
use ratelimit::RateLimiter;

type BoxedBody = BoxBody<Bytes, hyper::Error>;
type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Shared node state.
/// Buffer of NORMAL samples from trusted IPs (path, query, body), keyed by domain.
/// Flushed periodically to the cloud (ml_samples, label=0) for model training.
/// Sampled 1 in 8 and size-capped, so only a slice of traffic reaches the cloud.
// The map is domain -> queue of (path, query, body, context features).
// A type alias would not make the ownership story any clearer.
#[allow(clippy::type_complexity)]
struct SampleBuf {
    inner: std::sync::Mutex<std::collections::HashMap<String, std::collections::VecDeque<(String, String, String, Vec<f32>)>>>,
    cap: usize,
    counter: std::sync::atomic::AtomicU64,
}
impl SampleBuf {
    fn new(cap: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
            cap,
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }
    /// Record a normal sample (1 in 8). A full per-domain buffer does not grow further.
    fn record(&self, domain: &str, path: &str, query: &str, body: &str, ctx: &[f32]) {
        if !self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed).is_multiple_of(8) { return; }
        let mut m = match self.inner.lock() { Ok(m) => m, Err(_) => return };
        let q = m.entry(domain.to_string()).or_default();
        if q.len() >= self.cap { return; }
        q.push_back((path.to_string(), query.to_string(), body.to_string(), ctx.to_vec()));
    }
    /// Drain up to max_per_domain samples per domain into JSON for the cloud.
    fn drain(&self, max_per_domain: usize) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let mut m = match self.inner.lock() { Ok(m) => m, Err(_) => return out };
        for (domain, q) in m.iter_mut() {
            let take = q.len().min(max_per_domain);
            for _ in 0..take {
                if let Some((p, qs, b, ctx)) = q.pop_front() {
                    out.push(serde_json::json!({ "domain": domain, "path": p, "query": qs, "body": b, "ctx": ctx }));
                }
            }
        }
        out
    }
}

/// Buffer of quarantine candidates: ready-made JSON objects for /api/ingest/review.
/// Without it the grey zone was detected but never sent, leaving the quarantine empty.
struct ReviewBuf {
    inner: std::sync::Mutex<std::collections::VecDeque<serde_json::Value>>,
    cap: usize,
}
impl ReviewBuf {
    fn new(cap: usize) -> Self {
        Self { inner: std::sync::Mutex::new(std::collections::VecDeque::new()), cap }
    }
    /// Push a candidate. On overflow the oldest is evicted.
    fn push(&self, item: serde_json::Value) {
        let mut q = match self.inner.lock() { Ok(q) => q, Err(_) => return };
        if q.len() >= self.cap { q.pop_front(); }
        q.push_back(item);
    }
    fn drain(&self, max: usize) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let mut q = match self.inner.lock() { Ok(q) => q, Err(_) => return out };
        while out.len() < max {
            match q.pop_front() { Some(v) => out.push(v), None => break }
        }
        out
    }
}

// ─── Canonical request PATTERN for grouping quarantine entries ───────────────────
// The problem: an operator confirms not 4-10 paths (as with context-aware WAFs using a URL/parameter
// model) but dozens, because /api/orders/12 and /api/orders/99 count as DIFFERENT,
// and parameter order plus tracking parameters fragment the group further. The fix: reduce a request to
// a template — a path with generalised ID segments plus the sorted parameter NAMES (without
// values) plus a coarse verdict bucket. Then every ID variant of one endpoint collapses into
// a SINGLE confirmation. The pattern is computed on the node and stored in ml_review.pattern; the dashboard
// groups and labels by it (control/main.rs). IMPORTANT: this logic mirrors the SQL fallback
// in control (path_template/norm_query); keep both in sync when editing.

/// A run of 3 or more consecutive digits, the usual sign of a numeric ID inside a slug.
fn has_digit_run3(s: &str) -> bool {
    let mut run = 0u32;
    for b in s.bytes() {
        if b.is_ascii_digit() { run += 1; if run >= 3 { return true; } } else { run = 0; }
    }
    false
}

/// Whether a path segment looks like an identifier: a number, UUID, long hex string or a slug containing an ID run.
fn seg_is_id(seg: &str) -> bool {
    if seg.is_empty() { return false; }
    let b = seg.as_bytes();
    // a plain number
    if b.iter().all(|c| c.is_ascii_digit()) { return true; }
    // UUID 8-4-4-4-12
    if seg.len() == 36
        && b[8] == b'-' && b[13] == b'-' && b[18] == b'-' && b[23] == b'-'
        && b.iter().enumerate().all(|(i, &c)| matches!(i, 8|13|18|23) == (c == b'-')
            && (c == b'-' || c.is_ascii_hexdigit()))
    {
        return true;
    }
    // long hex (12+ chars): sha, oid or token
    if seg.len() >= 12 && b.iter().all(|c| c.is_ascii_hexdigit()) { return true; }
    // a mixed alphanumeric slug with a run of 3+ digits (item-12345, winter2024sale)
    if b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        && has_digit_run3(seg)
    {
        return true;
    }
    false
}

/// Path to template: ID-like segments become {id}. Order and static segments are
/// preserved, otherwise distinct endpoints would merge.
fn template_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut first = true;
    for seg in path.split('/') {
        if !first { out.push('/'); }
        first = false;
        if seg.is_empty() { continue; }
        if seg_is_id(seg) { out.push_str("{id}"); } else { out.push_str(seg); }
    }
    out
}

/// Query to a sorted, unique list of parameter NAMES, with values discarded.
/// a=1&b=2 and b=2&a=1&utm=x&a=9 both yield "a&b&utm", independent of order, values and duplicates.
fn template_query(query: &str) -> String {
    let mut keys: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for pair in query.split('&') {
        if pair.is_empty() { continue; }
        let k = pair.split('=').next().unwrap_or("");
        if !k.is_empty() { keys.insert(k); }
    }
    keys.into_iter().collect::<Vec<_>>().join("&")
}

/// Canonical pattern for quarantine grouping. The bucket separates a confirmed
/// attack sample (\"a\", label=1) from the ML grey zone (\"g\"), so that labelling a group with one
/// label does not mix an outright attack with uncertain-but-normal traffic on the same URL.
fn review_pattern(host: &str, method: &str, path: &str, query: &str, bucket: &str) -> String {
    format!("{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
        host, method, template_path(path), template_query(query), bucket)
}

/// Quarantine seeding dedup by PATTERN: true means it may be sent (this pattern has not been sent recently).
/// The key used to be the raw (host, method, path, query) including values, so one endpoint with an ID
/// in the path, or a sweep of payloads, flooded the queue. The key is now review_pattern and the window
/// is longer (1800 s by default): a pattern already awaiting labelling is not resent until
/// it cools down. Configurable via REVIEW_DEDUP_TTL (seconds). Memory is bounded by TTL-based cleanup.
fn review_dedup(pattern: &str) -> bool {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<u64, i64>>> = std::sync::OnceLock::new();
    static TTL: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    let ttl = *TTL.get_or_init(|| {
        std::env::var("REVIEW_DEDUP_TTL").ok().and_then(|v| v.parse().ok()).filter(|&t| t > 0).unwrap_or(1800)
    });
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut h = DefaultHasher::new();
    pattern.hash(&mut h);
    let key = h.finish();
    let now = now_unix();
    let mut m = match seen.lock() { Ok(g) => g, Err(p) => p.into_inner() };
    if m.len() > 8192 { m.retain(|_, t| now - *t < ttl); }
    match m.get(&key) {
        Some(t) if now - *t < ttl => false,
        _ => { m.insert(key, now); true }
    }
}

/// Build a JSON quarantine candidate in the /api/ingest/review format.
/// ML severity band from ensemble confidence: 1=low, 2=medium, 3=high, 4=critical (0 is below low).
fn ml_band(conf: f64) -> u8 {
    if conf >= 0.95 {
        4
    } else if conf >= 0.85 {
        3
    } else if conf >= 0.70 {
        2
    } else if conf >= 0.50 {
        1
    } else {
        0
    }
}

// Builds one flat JSON record; grouping the arguments into a struct would just
// move the same fields one level down for a single call site.
#[allow(clippy::too_many_arguments)]
fn review_item(domain: &str, ip: &str, country: &str, method: &str, uri: &str, path: &str, query: &str, body: &str, proba: f32, ctx: &[f32], pattern: &str) -> serde_json::Value {
    serde_json::json!({
        "host": domain, "client_ip": ip, "country": country, "method": method,
        "uri": uri, "path": path, "query": query, "body": body, "ml_proba": proba,
        "ctx": ctx, "pattern": pattern,
    })
}

struct Shared {
    router: Arc<ArcSwap<Router>>, // hot-swapped when policy updates
    client: HttpClient,           // with backend certificate validation
    client_insecure: HttpClient,  // without backend certificate validation, for self-signed origins
    rr: AtomicUsize,
    rl: RateLimiter,
    load: ratelimit::SiteLoad, // adaptive per-site load meter
    behavior: behavior::Behavior, // behavioural bot management (per-client window)
    ato: ato::Ato,                // ATO and credential-stuffing protection (login windows)
    ipban: ipban::IpBan, // automatic IP banning (strikes locally, bans from the cloud feed)
    log_all: std::sync::Arc<std::sync::atomic::AtomicBool>, // global: log every request (superadmin)
    geo: Arc<arc_swap::ArcSwapOption<geo::Geo>>,
    iprep: Arc<ArcSwap<iprep::IpRep>>, // threat-intel set of malicious IPs (hot-swapped)
    collective: Arc<ArcSwap<iprep::IpRep>>, // cross-tenant collective threat feed (opt-in)
    mrules: Arc<ArcSwap<Vec<verdict::Rule>>>, // centrally managed rules (virtual patching)
    fpfeed: Arc<ArcSwap<fpfeed::FpFeed>>, // feed of malicious JA3/JA4 TLS fingerprints (hot-swapped)
    events: Option<cloud::EventTx>, // event channel to the cloud, when enrolled
    node_id: String,
    ml: anomaly::Anomaly, // unsupervised anomaly profile
    metrics: Arc<metrics::Metrics>, // live counters (Prometheus and JSON)
    ml_models: Arc<arc_swap::ArcSwap<std::collections::HashMap<String, std::sync::Arc<mlmodel::Model>>>>, // per-asset supervised ML (the '' key is the tenant-wide model)
    cache: cache::Cache, // in-memory response cache, consulted ONLY after the WAF
    // ACME HTTP-01: token -> key_authorization. Populated by polling the control plane.
    // Served at /.well-known/acme-challenge/<token> on :80 for Let's Encrypt issuance.
    acme: Arc<arc_swap::ArcSwap<std::collections::HashMap<String, String>>>,
    // metric aggregator for the cloud (per host, per minute); None when the node is standalone
    metric_acc: Option<std::sync::Arc<cloud::MetricAcc>>,
    samples: std::sync::Arc<SampleBuf>, // normal samples from trusted IPs, bound for the cloud (ml_samples)
    reviews: std::sync::Arc<ReviewBuf>, // quarantine candidates, bound for the cloud (ml_review)
    body_buf: Arc<AtomicUsize>, // current total body buffering in RAM (anti-OOM)
    body_budget: usize,         // global body buffering ceiling (env, bytes)
    breaker: Arc<Breaker>,      // passive circuit breaker per backend
    ssrf: Arc<ResolveGuard>,    // backend anti-SSRF (resolve check for private and metadata addresses)
}

#[tokio::main]
// The env-driven Config is assembled field by field; a struct literal would repeat
// every default and drift the moment a field is added.
#[allow(clippy::field_reassign_with_default)]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    // crypto provider for rustls, installed once before any TLS is used
    let _ = rustls::crypto::ring::default_provider().install_default();

    // defence in depth: when policy signature verification is unconfigured (no embedded key),
    // the node accepts any config from the cloud channel, so we warn explicitly without changing behaviour.
    if !cloud::policy_verification_enabled() {
        tracing::warn!("policy signature verification is OFF (THREATAIL_POLICY_PUBKEY not built in) — \
            the node will accept any policy delivered over the cloud channel. For integrity, rebuild with \
            THREATAIL_POLICY_PUBKEY=<hex pubkey>.");
    }

    let cfg_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/threatail/config.json".to_string());
    let cfg = match Config::load(&cfg_path) {
        Ok(c) => {
            tracing::info!("config loaded: {} ({} sites)", cfg_path, c.sites.len());
            c
        }
        Err(_) => {
            // cloud mode: there is no JSON config, since the installer writes only environment variables.
            // Sites arrive from the cloud via policy; we set default listen addresses here.
            let mut d = Config::default();
            d.listen_https = std::env::var("THREATAIL_LISTEN_HTTPS").unwrap_or_else(|_| "0.0.0.0:443".into());
            d.listen_http  = std::env::var("THREATAIL_LISTEN_HTTP").unwrap_or_else(|_| "0.0.0.0:80".into());
            d.metrics_listen = std::env::var("THREATAIL_METRICS_LISTEN").unwrap_or_default();
            d.metrics_token  = std::env::var("THREATAIL_METRICS_TOKEN").unwrap_or_default();
            d.http2_enabled = true;
            d.geoip_db = std::env::var("THREATAIL_GEOIP_DB").unwrap_or_default();
            d.model_path = std::env::var("THREATAIL_MODEL_PATH").unwrap_or_else(|_| "/var/lib/threatail/model.json".into());
            tracing::info!("config file not found — cloud mode (https {}, http {})", d.listen_https, d.listen_http);
            d
        }
    };

    // backend connector supporting both http and https by URL scheme, for HTTPS origins.
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("native roots")
        .https_or_http()
        .enable_http1()
        .build();
    // backend pool keep-alive, global, configurable via THREATAIL_UPSTREAM_IDLE_SECS (default 15 s).
    let idle_secs: u64 = std::env::var("THREATAIL_UPSTREAM_IDLE_SECS").ok().and_then(|s| s.parse().ok()).filter(|&n| n > 0).unwrap_or(15);
    let client: HttpClient = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(idle_secs))
        .build(https);

    // insecure connector that does NOT validate the backend certificate, for internal
    // origins with self-signed certificates or bare IPs. Enabled by the site's insecure_backend flag.
    let tls_noverify = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(tls::NoVerify))
        .with_no_client_auth();
    let https_insecure = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_noverify)
        .https_or_http()
        .enable_http1()
        .build();
    let client_insecure: HttpClient = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(idle_secs))
        .build(https_insecure);

    // live router: the control plane swaps it atomically when policy updates
    let router = Arc::new(ArcSwap::from_pointee(Router::new(&cfg)));

    // TLS certificate store, hot-swappable without a restart
    let cert_store = tls::empty_store();
    // store of per-SNI ServerConfigs for mTLS domains, with full client validation
    let config_store = tls::empty_config_store();

    // ── CLOUD MODE ──
    // Cloud configuration from the environment (written by the installer to /etc/threatail/node.env):
    //   THREATAIL_CLOUD_URL and THREATAIL_ENROLLMENT_TOKEN. Enrolment state lives on disk.
    let cloud = {
        let cc = cloud::CloudCfg {
            url: std::env::var("THREATAIL_CLOUD_URL").unwrap_or_default(),
            enrollment_token: std::env::var("THREATAIL_ENROLLMENT_TOKEN").unwrap_or_default(),
            state_path: std::env::var("THREATAIL_STATE_PATH")
                .unwrap_or_else(|_| "/var/lib/threatail/cloud-state.json".to_string()),
        };
        if cc.enabled() {
            tracing::info!("cloud: {}", cc.url);
            match cloud::Cloud::init(cc).await {
                Ok(c) => Some(c),
                Err(e) => { tracing::error!("cloud binding failed: {}", e); None }
            }
        } else {
            tracing::info!("THREATAIL_CLOUD_URL not set — cloud mode disabled");
            None
        }
    };

    // the 'log every request' flag, set per node and delivered by the cloud in policy.
    // Created before policy polling; the same Arc goes into Shared below.
    let log_all = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // buffer of normal samples from trusted IPs, flushed to the cloud every 60 s (ml_samples).
    let samples = std::sync::Arc::new(SampleBuf::new(5000));
    let reviews = std::sync::Arc::new(ReviewBuf::new(2000));
    if let Some(c) = cloud.clone() {
        let buf = samples.clone();
        let rbuf = reviews.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let batch = buf.drain(2000);
                if !batch.is_empty() { c.send_samples(batch).await; }
                let rbatch = rbuf.drain(500);
                if !rbatch.is_empty() { c.send_review(rbatch).await; }
            }
        });
    }

    // policy polling: the cloud sends a site list and we hot-swap a new Router.
    // events: the channel to the cloud. license: the lease loop; the node serves traffic only while licensed.
    let (events, node_id) = if let Some(c) = &cloud {
        let r = router.clone();
        let cs = cert_store.clone();
        let cfgs = config_store.clone();
        let http2 = cfg.http2_enabled;
        c.spawn_policy_poll(log_all.clone(), move |p: cloud::Policy| {
            // 1) sites -> router
            let mut built: Vec<Site> = p.sites
                .into_iter()
                .filter_map(|ps| central::site_from_policy(ps.domain, ps.config))
                .collect();
            // revoked client certificates (mTLS), applied to sites with mTLS enabled
            if !p.mtls_revoked.is_empty() {
                let revset: std::collections::HashSet<String> = p.mtls_revoked.iter()
                    .map(|s| s.trim_start_matches('0').to_ascii_lowercase()).collect();
                for s in built.iter_mut() {
                    if !s.mtls_locations.is_empty() {
                        s.mtls_revoked = p.mtls_revoked.clone();
                        s.mtls_revoked_set = revset.clone();
                    }
                }
            }
            // 2) certificates -> cert_store (the key is already decrypted by the cloud)
            let mut cmap: std::collections::HashMap<String, std::sync::Arc<rustls::sign::CertifiedKey>> =
                std::collections::HashMap::new();
            for pc in &p.certs {
                if pc.cert.is_empty() || pc.key.is_empty() { continue; }
                match tls::certified_key_from_pem(&pc.cert, &pc.key) {
                    Ok(ck) => {
                        let doms: Vec<String> = pc.domains.split(',')
                            .map(|d| d.trim().to_ascii_lowercase())
                            .filter(|d| !d.is_empty())
                            .collect();
                        if doms.is_empty() {
                            cmap.insert(pc.name.to_ascii_lowercase(), ck);
                        } else {
                            for d in doms { cmap.insert(d, ck.clone()); }
                        }
                    }
                    Err(e) => tracing::warn!("cert {}: cannot parse PEM: {:?}", pc.name, e),
                }
            }
            let cert_n = cmap.len();
            // 3) mTLS: a per-SNI ServerConfig validating the client certificate against the domain CA
            let mut mmap: std::collections::HashMap<String, std::sync::Arc<rustls::ServerConfig>> =
                std::collections::HashMap::new();
            for m in &p.mtls_cas {
                let dom = m.domain.to_ascii_lowercase();
                match cmap.get(&dom) {
                    Some(ck) => match tls::mtls_server_config(ck.clone(), &m.ca_cert, http2) {
                        Ok(cfg) => { mmap.insert(dom, cfg); }
                        Err(e) => tracing::warn!("mTLS {}: cannot build config: {:?}", m.domain, e),
                    },
                    None => tracing::warn!("mTLS {}: no TLS cert for domain — mTLS not activated", m.domain),
                }
            }
            let mtls_n = mmap.len();
            cs.store(std::sync::Arc::new(cmap));
            cfgs.store(std::sync::Arc::new(mmap));
            r.store(std::sync::Arc::new(Router::from_sites(built.clone())));
            tracing::info!("applied: {} site(s), {} cert-domain(s), {} mTLS-domain(s)",
                built.len(), cert_n, mtls_n);
        });
        c.spawn_license_loop();
        (Some(c.spawn()), c.state.node_id.clone())
    } else {
        (None, String::new())
    };

    let model_path = if cfg.model_path.is_empty() {
        "/var/lib/threatail/model.json".to_string()
    } else {
        cfg.model_path.clone()
    };
    let body_budget = detect_body_budget();
    tracing::info!("body buffer budget: {} MB (auto from RAM; override THREATAIL_BODY_BUDGET_MB)",
        body_budget / (1024 * 1024));
    let shared = Arc::new(Shared {
        router,
        client,
        client_insecure,
        rr: AtomicUsize::new(0),
        rl: RateLimiter::new(),
        load: ratelimit::SiteLoad::new(),
        behavior: behavior::Behavior::new(),
        ato: ato::Ato::new(),
        ipban: ipban::IpBan::new(),
        log_all,
        geo: Arc::new(arc_swap::ArcSwapOption::new(geo::Geo::open(&cfg.geoip_db).map(Arc::new))),
        iprep: Arc::new(ArcSwap::from_pointee(iprep::IpRep::default())),
        collective: Arc::new(ArcSwap::from_pointee(iprep::IpRep::default())),
        mrules: Arc::new(ArcSwap::from_pointee(Vec::new())),
        fpfeed: Arc::new(ArcSwap::from_pointee(fpfeed::FpFeed::default())),
        events,
        node_id: node_id.clone(),
        ml: anomaly::Anomaly::load(&model_path),
        metrics: Arc::new(metrics::Metrics::new()),
        ml_models: {
            // precedence: an explicit path, then the embedded default model if present. Stored under the '' key
            // (shared). The cloud later adds per-asset models by domain on the fly.
            let m = if cfg.ml_model_path.is_empty() {
                None
            } else {
                mlmodel::Model::load(&cfg.ml_model_path)
            };
            let m = m.or_else(mlmodel::Model::load_default);
            let mut map = std::collections::HashMap::new();
            if let Some(m) = m {
                if cfg.ml_model_path.is_empty() {
                    tracing::info!("ML: using built-in default model");
                }
                map.insert(String::new(), m);
            }
            Arc::new(arc_swap::ArcSwap::from_pointee(map))
        },
        acme: Arc::new(arc_swap::ArcSwap::from_pointee(std::collections::HashMap::new())),
        cache: cache::Cache::new(
            std::env::var("CACHE_MAX_ENTRIES").ok().and_then(|v| v.parse().ok()).unwrap_or(10000),
            std::env::var("CACHE_MAX_OBJ").ok().and_then(|v| v.parse().ok()).unwrap_or(4 * 1024 * 1024),
        ),
        metric_acc: cloud.as_ref().map(|_| cloud::MetricAcc::new()),
        samples,
        reviews,
        body_buf: Arc::new(AtomicUsize::new(0)),
        body_budget,
        breaker: Arc::new(Breaker::new()),
        ssrf: Arc::new(ResolveGuard::new()),
    });

    // ── DECLARATIVE SOURCES (standalone operation) ──
    // Everything below is normally delivered by cloud policy. Read from local files
    // it lets the node run fully from a hand-written config. When the cloud is also
    // attached its polling overwrites these later, so the cloud stays authoritative.
    //
    // Each of these has a matching per-site on/off flag that already existed. Without
    // a source behind it, flipping that flag did nothing at all and said nothing about
    // it — which is the failure mode this section removes.
    {
        // TLS certificates. Without this the node cannot serve HTTPS standalone:
        // the listener binds, then every handshake fails for want of a certificate.
        if !cfg.certs.is_empty() {
            let mut cmap: std::collections::HashMap<String, std::sync::Arc<rustls::sign::CertifiedKey>> =
                std::collections::HashMap::new();
            for c in &cfg.certs {
                let cert_pem = match std::fs::read_to_string(&c.cert_file) {
                    Ok(v) => v,
                    Err(e) => { tracing::error!("cert {}: {}", c.cert_file, e); continue; }
                };
                let key_pem = match std::fs::read_to_string(&c.key_file) {
                    Ok(v) => v,
                    Err(e) => { tracing::error!("key {}: {}", c.key_file, e); continue; }
                };
                match tls::certified_key_from_pem(&cert_pem, &key_pem) {
                    Ok(ck) => {
                        for d in &c.domains {
                            let d = d.trim().to_ascii_lowercase();
                            if !d.is_empty() { cmap.insert(d, ck.clone()); }
                        }
                    }
                    Err(e) => tracing::error!("cert {}: {}", c.cert_file, e),
                }
            }
            tracing::info!("certificates: {} domains from config", cmap.len());
            cert_store.store(std::sync::Arc::new(cmap));
        }

        // mTLS: a per-SNI server config that validates client certificates against
        // the site's CA. mtls_locations without a CA would only observe that some
        // certificate was presented, which is not authentication.
        let mut mtls_map: std::collections::HashMap<String, std::sync::Arc<rustls::ServerConfig>> =
            std::collections::HashMap::new();
        for site in &cfg.sites {
            if site.mtls_ca_file.is_empty() || site.mtls_locations.is_empty() { continue; }
            let dom = site.domain.to_ascii_lowercase();
            let Some(ck) = cert_store.load().get(&dom).cloned() else {
                tracing::error!("mtls {}: no certificate for this domain, mTLS disabled", dom);
                continue;
            };
            match std::fs::read_to_string(&site.mtls_ca_file) {
                Ok(ca) => match tls::mtls_server_config(ck, &ca, cfg.http2_enabled) {
                    Ok(sc) => { mtls_map.insert(dom, sc); }
                    Err(e) => tracing::error!("mtls {}: {}", site.domain, e),
                },
                Err(e) => tracing::error!("mtls ca {}: {}", site.mtls_ca_file, e),
            }
        }
        if !mtls_map.is_empty() {
            tracing::info!("mTLS: {} domains from config", mtls_map.len());
            config_store.store(std::sync::Arc::new(mtls_map));
        }

        // IP reputation, one address or CIDR per line.
        if !cfg.iprep_file.is_empty() {
            match std::fs::read_to_string(&cfg.iprep_file) {
                Ok(t) => {
                    let rep = iprep::IpRep::parse(&t);
                    tracing::info!("ip reputation: {} entries from {}", rep.len(), cfg.iprep_file);
                    shared.iprep.store(std::sync::Arc::new(rep));
                }
                Err(e) => tracing::error!("iprep {}: {}", cfg.iprep_file, e),
            }
        }

        // Managed rules, a JSON array in the same shape the cloud distributes.
        if !cfg.managed_rules_file.is_empty() {
            match std::fs::read_to_string(&cfg.managed_rules_file) {
                Ok(t) => match serde_json::from_str::<serde_json::Value>(&t) {
                    Ok(v) => {
                        let rules = central::managed_rules_from_json(&v);
                        tracing::info!("managed rules: {} from {}", rules.len(), cfg.managed_rules_file);
                        shared.mrules.store(std::sync::Arc::new(rules));
                    }
                    Err(e) => tracing::error!("managed rules {}: {}", cfg.managed_rules_file, e),
                },
                Err(e) => tracing::error!("managed rules {}: {}", cfg.managed_rules_file, e),
            }
        }

        // Malicious TLS fingerprints, one JA3 or JA4 per line.
        if !cfg.fpfeed_file.is_empty() {
            match std::fs::read_to_string(&cfg.fpfeed_file) {
                Ok(t) => {
                    let feed = fpfeed::FpFeed::parse(&t);
                    tracing::info!("tls fingerprint feed: {} entries from {}", feed.len(), cfg.fpfeed_file);
                    shared.fpfeed.store(std::sync::Arc::new(feed));
                }
                Err(e) => tracing::error!("fpfeed {}: {}", cfg.fpfeed_file, e),
            }
        }
    }

    // cloud metrics reporter: folds aggregates once a minute and ships them
    if let (Some(c), Some(acc)) = (&cloud, &shared.metric_acc) {
        cloud::spawn_metrics_reporter(c.clone(), acc.clone());
    }

    // Automatic ML model loading from the cloud, PER DOMAIN. /api/node/model returns a
    // signed envelope {"models":{domain:{version,changed,model}}}; spawn_model_poll parses it,
    // VERIFIES THE SIGNATURE and calls apply(domain, model_json) only for models that changed.
    // Stored in the per-asset map (the '' key is the tenant-wide model).
    if let Some(c) = &cloud {
        let sh = shared.clone();
        c.spawn_model_poll(move |domain, model_json| {
            let safe: String = domain
                .chars()
                .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
                .collect();
            let tmp = format!(
                "/tmp/threatail-model-{}.json",
                if safe.is_empty() { "general".to_string() } else { safe }
            );
            if std::fs::write(&tmp, &model_json).is_ok() {
                if let Some(m) = mlmodel::Model::load(&tmp) {
                    let mut map = (**sh.ml_models.load()).clone();
                    map.insert(domain.clone(), m);
                    sh.ml_models.store(std::sync::Arc::new(map));
                    tracing::info!(
                        "ML model updated from cloud for '{}'",
                        if domain.is_empty() { "(general)" } else { &domain }
                    );
                } else {
                    tracing::warn!("ML model from cloud failed validation for '{}'", domain);
                }
            }
        });
    }

    // Background JWKS refresh for sites verifying RS*/ES* signatures (apisec phase 1.5).
    // Every 10 minutes it fetches keys from every configured api_jwt_jwks_url (https, public address).
    // The first pass runs immediately so keys are available by the time enforcement starts.
    {
        let sh = shared.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                tick.tick().await;
                let router = sh.router.load();
                let mut urls: std::collections::HashSet<String> = std::collections::HashSet::new();
                for s in router.by_domain.values() {
                    let a = &s.api_sec;
                    if a.jwt_enabled && a.jwt_verify_sig && !a.jwt_jwks_url.is_empty() {
                        urls.insert(a.jwt_jwks_url.clone());
                    }
                }
                for (_, s) in &router.wildcards {
                    let a = &s.api_sec;
                    if a.jwt_enabled && a.jwt_verify_sig && !a.jwt_jwks_url.is_empty() {
                        urls.insert(a.jwt_jwks_url.clone());
                    }
                }
                for u in urls {
                    let _ = crate::jwks::refresh(&u, &client).await;
                }
            }
        });
    }

    // ACME HTTP-01: poll the cloud frequently for active challenges and refresh the
    // token -> key_auth map served at /.well-known/acme-challenge/<token> on :80.
    // The V2 endpoint /api/node/acme-challenges returns {"challenges": {token: key_auth}}.
    if let Some(c) = &cloud {
        let sh = shared.clone();
        let base = c.url().to_string();
        let token = c.node_token().to_string();
        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            let url = format!("{}/api/node/acme-challenges", base);
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tick.tick().await;
                match client.get(&url).bearer_auth(&token).send().await {
                    Ok(resp) if resp.status().as_u16() == 200 => {
                        if let Ok(v) = resp.json::<serde_json::Value>().await {
                            let mut map = std::collections::HashMap::new();
                            // V2 format: challenges is an object mapping token to key_auth
                            if let Some(obj) = v.get("challenges").and_then(|x| x.as_object()) {
                                for (tok, ka) in obj {
                                    if let Some(k) = ka.as_str() {
                                        map.insert(tok.clone(), k.to_string());
                                    }
                                }
                            }
                            sh.acme.store(Arc::new(map));
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::debug!("ACME challenge: cloud unavailable: {}", e),
                }
            }
        });
    }
    // Auto-update: the cloud can assign a target node version. The node starts the
    // updater (root via sudoers) as a separate process and does NOT wait; the updater
    // reinstalls the binary and restarts the service.
    if let Some(c) = &cloud {
        c.spawn_update_poll(move |ver| {
            // The service runs as an unprivileged user with NoNewPrivileges=yes,
            // so sudo and directly replacing the binary are impossible. The node merely writes a request file
            // into STATE_DIR, which it can write to, and a systemd .path unit launches the updater
            // as root to reinstall the binary and restart the service.
            let state_dir = std::env::var("THREATAIL_STATE_DIR").unwrap_or_else(|_| "/var/lib/threatail".to_string());
            let req = std::path::Path::new(&state_dir).join(".update-request");
            match std::fs::write(&req, ver.trim().as_bytes()) {
                Ok(_) => tracing::info!("update: requested version {} (via {})", ver, req.display()),
                Err(e) => tracing::error!("update: cannot write update request {}: {}", req.display(), e),
            }
        });
    }

    // GeoIP database from the cloud, as in V1: the cloud serves the mmdb, the node fetches it
    // and reopens geo on the fly. This only works when the cloud has a source configured.
    if let Some(c) = &cloud {
        let dest = if cfg.geoip_db.is_empty() { "/var/lib/threatail/geoip.mmdb".to_string() } else { cfg.geoip_db.clone() };
        let sh = shared.clone();
        let d2 = dest.clone();
        c.spawn_geoip_poll(move |bytes| {
            match write_geoip(&bytes, &d2) {
                Ok(()) => match geo::Geo::open(&d2) {
                    Some(g) => { sh.geo.store(Some(std::sync::Arc::new(g))); tracing::info!("GeoIP updated from cloud"); }
                    None => tracing::warn!("GeoIP: file written but failed to open"),
                },
                Err(e) => tracing::warn!("GeoIP from cloud: {}", e),
            }
        });
    }

    // IP reputation: the malicious IP list from the cloud, with sources configured by the superadmin,
    // hot-swapped wholesale. Applied per site via the iprep_enabled flag.
    if let Some(c) = &cloud {
        let sh = shared.clone();
        c.spawn_iprep_poll(move |body| {
            let rep = iprep::IpRep::parse(&body);
            let n = rep.len();
            sh.iprep.store(std::sync::Arc::new(rep));
            tracing::info!("IP reputation: {} entries from cloud", n);
        });
    }

    // Collective defence: the cross-tenant attacker IP feed from the cloud (tenant opt-in),
    // hot-swapped. Applied per site via the collective_defense_enabled flag.
    if let Some(c) = &cloud {
        let sh = shared.clone();
        c.spawn_collective_poll(move |body| {
            let rep = iprep::IpRep::parse(&body);
            let n = rep.len();
            sh.collective.store(std::sync::Arc::new(rep));
            tracing::info!("collective feed: {} cross-tenant IPs from cloud", n);
        });
    }

    // Managed rules (virtual patching): a central set from the cloud, curated by the superadmin,
    // hot-swapped. Applied per site via the managed_rules_enabled flag.
    if let Some(c) = &cloud {
        let sh = shared.clone();
        c.spawn_mrules_poll(move |body| {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                let rules = central::managed_rules_from_json(&v);
                let n = rules.len();
                sh.mrules.store(std::sync::Arc::new(rules));
                tracing::info!("managed rules: {} from cloud", n);
            }
        });
    }

    // Feed of malicious TLS fingerprints (JA3/JA4) from the cloud, hot-swapped wholesale.
    // Applied per site via the fpfeed_enabled flag.
    if let Some(c) = &cloud {
        let sh = shared.clone();
        c.spawn_fpfeed_poll(move |body| {
            let feed = fpfeed::FpFeed::parse(&body);
            let n = feed.len();
            sh.fpfeed.store(std::sync::Arc::new(feed));
            tracing::info!("TLS feed: {} fingerprints from cloud", n);
        });
    }

    // Auto-ban feed from the cloud: banned IPs per site (option 2). We parse
    // {items:[{host,ip,until}]} and atomically swap the set in; blocking happens early in the pipeline.
    if let Some(c) = &cloud {
        let sh = shared.clone();
        c.spawn_ban_poll(move |body| {
            let mut items: Vec<(String, String, u64)> = Vec::new();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(arr) = v.get("items").and_then(|x| x.as_array()) {
                    for it in arr {
                        let host = it.get("host").and_then(|x| x.as_str()).unwrap_or("");
                        let ip = it.get("ip").and_then(|x| x.as_str()).unwrap_or("");
                        let until = it.get("until").and_then(|x| x.as_u64()).unwrap_or(0);
                        if !host.is_empty() && !ip.is_empty() && until > 0 {
                            items.push((host.to_string(), ip.to_string(), until));
                        }
                    }
                }
            }
            let n = items.len();
            sh.ipban.replace_feed(items);
            tracing::debug!("auto-ban feed: {} active bans from cloud", n);
        });
    }

    if !cfg.geoip_update_url.is_empty() && !cfg.geoip_db.is_empty() {
        let sh = shared.clone();
        let url = cfg.geoip_update_url.clone();
        let path = cfg.geoip_db.clone();
        let hours = if cfg.geoip_update_hours == 0 { 24 } else { cfg.geoip_update_hours };
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(hours * 3600));
            tick.tick().await; // skip the immediate first tick, since the database was already loaded from disk
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            loop {
                tick.tick().await;
                match update_geoip(&client, &url, &path).await {
                    Ok(()) => {
                        if let Some(g) = geo::Geo::open(&path) {
                            sh.geo.store(Some(Arc::new(g)));
                            tracing::info!("geo database updated and applied: {}", path);
                        }
                    }
                    Err(e) => tracing::warn!("geo update failed: {}", e),
                }
            }
        });
    }

    // periodically flush the ML profile to disk and log training status
    {
        let sh = shared.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                sh.ml.flush();
                sh.rl.cleanup(300); // evict rate buckets idle for over 5 minutes (leak guard)
                sh.load.cleanup(600); // clean up the per-site load meter
                sh.behavior.cleanup(600); // evict behavioural windows idle for over 10 minutes
                sh.ato.cleanup(1800);     // evict login windows idle for over 30 minutes
                sh.ipban.cleanup(); // evict stale auto-ban strikes
                let r = sh.router.load();
                for domain in r.by_domain.keys() {
                    let st = sh.ml.status(domain);
                    tracing::info!(
                        "ML {} training: {}% (requests {}/{}, IPs {}, endpoints {}, window {}h){}",
                        domain, st.progress, st.samples, st.target, st.unique_ips,
                        st.locations, st.window_hours,
                        if st.ready { " — TRAINED" } else { "" }
                    );
                }
                // (in V2 status and dataset go to the cloud via events and metrics)
            }
        });
    }

    // HTTPS listener, when configured and certificates exist
    if !cfg.listen_https.is_empty() {
        let default_cfg = tls::dynamic_server_config(cert_store.clone(), cfg.http2_enabled);
        // an h1-only variant without h2 in ALPN, for sites with HTTP/2 disabled
        let default_cfg_h1 = tls::dynamic_server_config(cert_store.clone(), false);
        let addr: SocketAddr = cfg.listen_https.parse()?;
        let sh = shared.clone();
        let h2 = cfg.http2_enabled;
        let cs = config_store.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_https(addr, default_cfg, default_cfg_h1, cs, sh, h2).await {
                tracing::error!("HTTPS listener crashed: {:?}", e);
            }
        });
        tracing::info!("HTTPS listening {} (HTTP/2: {})", cfg.listen_https, if cfg.http2_enabled { "on" } else { "off" });
    }

    // metrics server (/metrics for Prometheus, /stats for JSON) on an internal port
    if !cfg.metrics_listen.is_empty() {
        if let Ok(maddr) = cfg.metrics_listen.parse::<SocketAddr>() {
            let sh = shared.clone();
            let token = cfg.metrics_token.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_metrics(maddr, sh, token).await {
                    tracing::error!("metrics server stopped: {:?}", e);
                }
            });
            tracing::info!("metrics listening {}", maddr);
        } else {
            tracing::warn!("invalid metrics_listen: {}", cfg.metrics_listen);
        }
    }

    // HTTP listener (main task)
    let addr: SocketAddr = cfg.listen_http.parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("HTTP listening {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let sh = shared.clone();
        tokio::task::spawn(async move {
            let m = sh.metrics.clone();
            m.conn_open();
            let service = service_fn(move |req| handle(req, sh.clone(), peer, false, None, String::new(), String::new(), false));
            if let Err(e) = http1::Builder::new().timer(TokioTimer::new()).header_read_timeout(std::time::Duration::from_secs(15)).serve_connection(io, service).with_upgrades().await {
                tracing::debug!("HTTP connection error {}: {:?}", peer, e);
            }
            m.conn_close();
        });
    }
}

/// HTTPS listener: TLS handshake, then http1 or http2 based on the negotiated ALPN.
/// Per-IP anti-DoS state: active connections plus a window tracking new-connection rate.
struct IpState {
    active: u32,                       // current concurrent connections
    win_start: std::time::Instant,     // start of the one-second window
    new_in_win: u32,                   // new connections in the current window
}

async fn serve_https(
    addr: SocketAddr,
    default_cfg: Arc<rustls::ServerConfig>,
    default_cfg_h1: Arc<rustls::ServerConfig>,
    config_store: tls::ConfigStore,
    shared: Arc<Shared>,
    h2_enabled: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio_rustls::LazyConfigAcceptor;
    let listener = TcpListener::bind(addr).await?;
    // Cap on concurrent TLS handshakes, providing backpressure during a spike.
    let handshake_limit = Arc::new(tokio::sync::Semaphore::new(512));
    // Per-IP anti-DoS:
    //  - rate: a cap on NEW connections per second per IP. This cuts off a flooder without breaking
    //    carrier NAT/CGNAT, where many devices hold keep-alive connections but open few new ones.
    //  - cap: a ceiling on CONCURRENT connections per IP, as insurance against blatant abuse.
    //    It is set high so legitimate NAT pools are unaffected.
    let per_ip: Arc<dashmap::DashMap<std::net::IpAddr, IpState>> = Arc::new(dashmap::DashMap::new());
    const MAX_CONN_PER_IP: u32 = 512;       // concurrent connections per IP (safety ceiling)
    const MAX_NEW_PER_SEC: u32 = 50;        // new connections per second per IP (anti-flood)
    const HANDSHAKE_TIMEOUT_SECS: u64 = 10; // guards against slowloris during the handshake
    // per_ip leak guard: IpGuard removes an entry only when active==0 && new_in_win==0,
    // but new_in_win only resets on a NEW connection from the same IP more than 1 s later. So an IP
    // that connected once and left would leave a residual entry forever. We therefore periodically
    // sweep entries with no active connections whose window has expired (over 2 s; the limit window is 1 s).
    {
        let per_ip = per_ip.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tick.tick().await;
                let now = std::time::Instant::now();
                per_ip.retain(|_, s| s.active > 0 || now.duration_since(s.win_start).as_secs() < 2);
            }
        });
    }
    loop {
        let (stream, peer) = listener.accept().await?;
        let sh = shared.clone();
        let permit_src = handshake_limit.clone();
        let cfg_store = config_store.clone();
        let def_cfg = default_cfg.clone();
        let def_cfg_h1 = default_cfg_h1.clone();
        let per_ip = per_ip.clone();
        let ip = peer.ip();
        // check the IP limits: concurrent ceiling plus new-per-second rate
        {
            let now = std::time::Instant::now();
            let mut st = per_ip.entry(ip).or_insert_with(|| IpState { active: 0, win_start: now, new_in_win: 0 });
            if now.duration_since(st.win_start).as_secs() >= 1 {
                st.win_start = now;
                st.new_in_win = 0;
            }
            if st.active >= MAX_CONN_PER_IP {
                drop(st);
                sh.metrics.tls_handshake_fail();
                tracing::debug!("reject: concurrent-connection cap from IP {}", ip);
                continue;
            }
            if st.new_in_win >= MAX_NEW_PER_SEC {
                drop(st);
                sh.metrics.tls_handshake_fail();
                tracing::debug!("reject: new-connection rate exceeded from IP {}", ip);
                continue;
            }
            st.active += 1;
            st.new_in_win += 1;
        }
        tokio::task::spawn(async move {
            // RAII decrement of the IP's active connection counter on exit
            struct IpGuard { per_ip: Arc<dashmap::DashMap<std::net::IpAddr, IpState>>, ip: std::net::IpAddr }
            impl Drop for IpGuard {
                fn drop(&mut self) {
                    if let Some(mut s) = self.per_ip.get_mut(&self.ip) {
                        s.active = s.active.saturating_sub(1);
                    }
                    // remove the entry when nothing is active, done separately so no reference is held
                    self.per_ip.remove_if(&self.ip, |_, s| s.active == 0 && s.new_in_win == 0);
                }
            }
            let _ipg = IpGuard { per_ip, ip };

            let _permit = match permit_src.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };
            // JA3/JA4: a best-effort peek at the ClientHello BEFORE rustls. peek does not consume, so rustls
            // reads the same bytes. Short timeout; an incomplete or unavailable ClientHello means we skip the
            // fingerprint rather than delaying the handshake. One peek per connection adds nothing to the
            // per-request hot path, since the handshake costs orders of magnitude more.
            let (ja3, ja4, tls_grease) = {
                let mut pb = [0u8; 2048];
                match tokio::time::timeout(std::time::Duration::from_millis(50), stream.peek(&mut pb)).await {
                    Ok(Ok(n)) if n > 0 => match tlsfp::fingerprint(&pb[..n]) {
                        Some(fp) => (fp.ja3, fp.ja4, fp.grease),
                        None => (String::new(), String::new(), false),
                    },
                    _ => (String::new(), String::new(), false),
                }
            };
            // LazyConfigAcceptor: read the ClientHello (and SNI) first, then pick the
            // config, either the domain's mTLS one or the shared one. All under a timeout, against slowloris.
            let lazy = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
            let timeout = std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
            let start = match tokio::time::timeout(timeout, lazy).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => { sh.metrics.tls_handshake_fail(); tracing::debug!("ClientHello {} error: {:?}", peer, e); return; }
                Err(_) => { sh.metrics.tls_handshake_fail(); tracing::debug!("handshake timeout {}", peer); return; }
            };
            // select the config by SNI
            let sni = start.client_hello().server_name().map(|s| s.to_ascii_lowercase());
            // Front-side HTTP/2 can be disabled for a specific site, in which case we serve a
            // config without h2 in ALPN so the client cannot negotiate it. Per-domain mTLS configs
            // are left alone; their ALPN follows the global setting.
            let site_h2 = sni.as_ref()
                .and_then(|d| sh.router.load().match_host(d).map(|s| s.http2))
                .unwrap_or(true);
            let chosen = sni.as_ref()
                .and_then(|d| cfg_store.load().get(d).cloned())
                .unwrap_or_else(|| if site_h2 { def_cfg.clone() } else { def_cfg_h1.clone() });
            let tls_stream = match tokio::time::timeout(timeout, start.into_stream(chosen)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => { sh.metrics.tls_handshake_fail(); tracing::debug!("TLS handshake {} failed: {:?}", peer, e); return; }
                Err(_) => { sh.metrics.tls_handshake_fail(); tracing::debug!("TLS timeout {}", peer); return; }
            };
            sh.metrics.tls_handshake_ok();
            drop(_permit);
            let is_h2 = h2_enabled && tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
            // the mTLS client certificate has already been cryptographically validated by rustls against the
            // domain CA via the per-SNI config. Here we take the serial to check revocation.
            let client_serial: Option<String> = tls_stream.get_ref().1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|c| netutil::cert_serial_hex(c.as_ref()));
            let io = TokioIo::new(tls_stream);
            let m = sh.metrics.clone();
            m.conn_open();
            let service = service_fn(move |req| handle(req, sh.clone(), peer, true, client_serial.clone(), ja3.clone(), ja4.clone(), tls_grease));
            if is_h2 {
                if let Err(e) = http2::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service).await
                { tracing::debug!("HTTP/2 error {}: {:?}", peer, e); }
            } else {
                if let Err(e) = http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(std::time::Duration::from_secs(15))
                    .serve_connection(io, service).with_upgrades().await
                { tracing::debug!("HTTPS error {}: {:?}", peer, e); }
            }
            m.conn_close();
        });
    }
}

/// Metrics server: serves /metrics (Prometheus) and /stats (JSON) on an internal port.
async fn serve_metrics(
    addr: SocketAddr,
    shared: Arc<Shared>,
    token: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fn resp(status: StatusCode, ctype: &str, body: String) -> Response<BoxedBody> {
        Response::builder()
            .status(status)
            .header("content-type", ctype)
            .body(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed())
            .unwrap()
    }
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let sh = shared.clone();
        let tok = token.clone();
        tokio::task::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let sh = sh.clone();
                let tok = tok.clone();
                async move {
                    // authorisation, when a token is configured
                    if !tok.is_empty() {
                        let expected = format!("Bearer {}", tok);
                        let ok = req
                            .headers()
                            .get(hyper::header::AUTHORIZATION)
                            .and_then(|h| h.to_str().ok())
                            .map(|h| {
                                // constant-time comparison, guarding against a timing attack on the token
                                let (a, b) = (h.as_bytes(), expected.as_bytes());
                                if a.len() != b.len() { return false; }
                                let mut diff = 0u8;
                                for i in 0..a.len() { diff |= a[i] ^ b[i]; }
                                diff == 0
                            })
                            .unwrap_or(false);
                        if !ok {
                            return Ok::<Response<BoxedBody>, hyper::Error>(
                                resp(StatusCode::UNAUTHORIZED, "text/plain", "unauthorized".into()));
                        }
                    }
                    let path = req.uri().path();
                    match path {
                        "/metrics" => Ok(resp(StatusCode::OK, "text/plain; version=0.0.4; charset=utf-8", sh.metrics.prometheus(&sh.node_id, sh.body_buf.load(Ordering::Relaxed)))),
                        "/stats" => Ok(resp(StatusCode::OK, "application/json", sh.metrics.json(&sh.node_id).to_string())),
                        _ => Ok(resp(StatusCode::NOT_FOUND, "text/plain", "not found".into())),
                    }
                }
            });
            if let Err(e) = http1::Builder::new().timer(TokioTimer::new()).header_read_timeout(std::time::Duration::from_secs(15)).serve_connection(io, service).await {
                tracing::debug!("metrics connection error: {:?}", e);
            }
        });
    }
}

/// Request handling: route by Host, apply the WAF verdict, then proxy.
// Per-connection context that cannot live in Shared: peer address, TLS details
// and the fingerprints captured during the handshake.
#[allow(clippy::too_many_arguments)]
async fn handle(
    req: Request<Incoming>,
    shared: Arc<Shared>,
    peer: SocketAddr,
    is_tls: bool,
    client_serial: Option<String>,
    ja3: String,
    ja4: String,
    tls_grease: bool,
) -> Result<Response<BoxedBody>, hyper::Error> {
    // ACME HTTP-01: serve the challenge BEFORE any routing or HTTPS redirect.
    // Let's Encrypt fetches http://<domain>/.well-known/acme-challenge/<token> over plain HTTP.
    {
        let path = req.uri().path();
        if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
            if !token.is_empty() {
                let map = shared.acme.load();
                if let Some(key_auth) = map.get(token) {
                    return Ok(text_response(StatusCode::OK, key_auth));
                }
            }
            // unknown token: return 404 and do NOT redirect to HTTPS
            return Ok(text_response(StatusCode::NOT_FOUND, "not found"));
        }
    }

    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();

    // visitor language for the default pages, from Accept-Language; the country comes later.
    // accept_lang owns its string so it survives req.into_parts().
    let accept_lang: Option<String> = req
        .headers()
        .get("accept-language")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let req_lang = i18n::page_lang("", accept_lang.as_deref());

    let router = shared.router.load();
    let site = match router.match_host(&host) {
        Some(s) => s,
        None => return Ok(error_response(StatusCode::NOT_FOUND, "unknown host", req_lang)),
    };

    // force_https: on the HTTP listener, redirect to HTTPS with 301
    if site.force_https && !is_tls {
        let host_only = host.split(':').next().unwrap_or(&host);
        // Guard against Location header injection: the host must be a valid name
        // (letters, digits, dot, hyphen), otherwise we use the site's domain. hyper's path_and_query
        // already contains no raw CRLF, but we still build the response without unwrap so it cannot panic.
        let safe_host = if !host_only.is_empty()
            && host_only.len() <= 253
            && host_only.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        { host_only } else { site.domain.as_str() };
        let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let location = format!("https://{}{}", safe_host, pq);
        let resp = match Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(hyper::header::LOCATION, location)
            .body(Full::new(Bytes::new()).map_err(|never| match never {}).boxed())
        {
            Ok(r) => r,
            Err(_) => error_response(StatusCode::BAD_REQUEST, "bad request", req_lang),
        };
        return Ok(resp);
    }

    // parse the request; the body is buffered for inspection and subsequent proxying
    let (parts, incoming) = req.into_parts();

    // Anti header-bomb: generous global ceilings (a normal request has dozens of headers and a few KB).
    // hyper already limits header count while parsing; this is a second line of defence plus a total
    // size cap. Exceeding it yields 431. The limits sit well above legitimate traffic, so nothing breaks.
    {
        let hcount = parts.headers.len();
        let hbytes: usize = parts.headers.iter().map(|(n, v)| n.as_str().len() + v.len()).sum();
        if hcount > 150 || hbytes > 64 * 1024 {
            tracing::info!("HEADER-BOMB {} count={} bytes={}", site.domain, hcount, hbytes);
            return Ok(error_response(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "request header fields too large", req_lang));
        }
    }
    // A duplicated, conflicting or non-numeric Content-Length yields 400 (anti request smuggling).
    // Several DIFFERENT values, or an invalid number, means malformed. Identical duplicates and
    // a single number are fine and left alone.
    {
        let mut it = parts.headers.get_all("content-length").iter();
        if let Some(first) = it.next() {
            let first_s = first.to_str().unwrap_or("").trim();
            let conflict = it.any(|v| v.to_str().unwrap_or("").trim() != first_s);
            let bad_val = first_s.parse::<u64>().is_err();
            if conflict || bad_val {
                tracing::info!("BAD-CONTENT-LENGTH {} '{}'", site.domain, first_s);
                return Ok(error_response(StatusCode::BAD_REQUEST, "bad content-length", req_lang));
            }
        }
    }

    // URI length limit (414), when configured
    if site.max_uri_kb > 0 {
        let uri_len = parts.uri.to_string().len();
        if uri_len > site.max_uri_kb * 1024 {
            tracing::info!("URI-TOO-LONG {} len={}", site.domain, uri_len);
            return Ok(error_response(StatusCode::URI_TOO_LONG, "URI too long", req_lang));
        }
    }

    // File uploads are checked BELOW, after buffering, by request SHAPE (multipart with a file
    // part) rather than by path: detection via Content-Type, part-by-part parsing, per-file size limit.
    // The pre-buffer OOM guard is the ceiling (max_body_kb), so a separate path check is no longer needed.

    // BUFFER ceiling (anti-OOM): max_body_kb when set, otherwise a generous 64 MB default
    // (the whole body is proxied; exceeding it yields 413). This is NOT the inspection budget.
    let ceiling = if site.max_body_kb > 0 { site.max_body_kb * 1024 } else { 64 * 1024 * 1024 };
    // _buf_guard holds a reservation against the global RAM budget for the lifetime of body_bytes
    // (until handle returns, i.e. while the body is being forwarded). It is released automatically on exit.
    let (body_bytes, _buf_guard) = match tokio::time::timeout(
        std::time::Duration::from_secs(if site.body_read_timeout > 0 { site.body_read_timeout as u64 } else { 30 }),
        collect_limited(incoming, ceiling, shared.body_buf.clone(), shared.body_budget),
    ).await {
        Ok(Ok(Collected::Body(b, g))) => (b, g),
        Ok(Ok(Collected::TooLarge)) => {
            tracing::info!("BODY-TOO-LARGE {} > {} bytes", site.domain, ceiling);
            return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE, "payload too large", req_lang));
        }
        Ok(Ok(Collected::Overloaded)) => {
            // the global buffering budget is exhausted, so we shed load (503 plus Retry-After)
            // so an avalanche of large bodies cannot kill the node on memory.
            tracing::warn!("BODY-BUDGET node RAM budget exceeded — shedding {} (budget={}MB)",
                site.domain, shared.body_budget / (1024 * 1024));
            shared.metrics.record_overloaded();
            let mut r = error_response(StatusCode::SERVICE_UNAVAILABLE, "overloaded", req_lang);
            r.headers_mut().insert(hyper::header::RETRY_AFTER, hyper::header::HeaderValue::from_static("1"));
            return Ok(r);
        }
        Ok(Err(_)) => return Ok(error_response(StatusCode::BAD_REQUEST, "body read error", req_lang)),
        Err(_) => return Ok(error_response(StatusCode::REQUEST_TIMEOUT, "request timeout", req_lang)), // slow-body
    };

    // The INSPECTION budget (how much body rules and ML scan) is separate from the buffer ceiling.
    // Defaults to 1 MB (matching the UI's '0 = 1MB' and the control plane) or site.body_limit. It bounds
    // regex CPU predictably, while the body is still forwarded in full (see the ceiling above).
    let inspect_cap = if site.body_limit > 0 { site.body_limit } else { 1024 * 1024 };
    // request details for the log: headers as JSON, up to 32 KB of body, and the query
    let query_string = parts.uri.query().unwrap_or("").to_string();
    let req_headers = headers_to_json(&parts.headers);
    const BODY_CAP: usize = 32 * 1024;
    let req_body = {
        let n = body_bytes.len().min(BODY_CAP);
        String::from_utf8_lossy(&body_bytes[..n]).to_string()
    };
    let http_version = match parts.version {
        hyper::Version::HTTP_10 => "HTTP/1.0",
        hyper::Version::HTTP_11 => "HTTP/1.1",
        hyper::Version::HTTP_2 => "HTTP/2",
        hyper::Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    };
    let mut det = ReqDetail { query: query_string, headers: req_headers, body: req_body, req_len: body_bytes.len() as u64, ml_proba: 0.0, http_version };
    shared.metrics.record_method(parts.method.as_str());

    // client IP, honouring X-Forwarded-For from trusted proxies
    let conn_ip = peer.ip().to_string();
    let xff = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let client_ip = netutil::effective_ip(&conn_ip, xff, &site.trusted_proxies);

    // Behind a trusted CDN or proxy the node terminates TLS from the CDN edge, not the client. So:
    //  • the real IP comes from CF-Connecting-IP when present, which is more reliable than parsing XFF;
    //  • the client TLS fingerprint is read from the configured header when the CDN forwards it (e.g. a Cloudflare
    //    Transform Rule carrying cf.bot_management.ja3_hash);
    //  • the GREASE mismatch check is NOT applied (direct_tls=false), since GREASE cannot be recovered from a hash.
    let behind_proxy = !site.trusted_proxies.is_empty() && netutil::ip_in_list(&conn_ip, &site.trusted_proxies);
    let direct_tls = is_tls && !behind_proxy;
    let mut ja3 = ja3;
    let mut ja4 = ja4;
    let client_ip = if behind_proxy {
        if !site.cdn_ja3_header.is_empty() {
            if let Some(v) = parts.headers.get(site.cdn_ja3_header.as_str()).and_then(|h| h.to_str().ok()) {
                let v = v.trim(); if !v.is_empty() { ja3 = v.to_string(); }
            }
        }
        if !site.cdn_ja4_header.is_empty() {
            if let Some(v) = parts.headers.get(site.cdn_ja4_header.as_str()).and_then(|h| h.to_str().ok()) {
                let v = v.trim(); if !v.is_empty() { ja4 = v.to_string(); }
            }
        }
        match parts.headers.get("cf-connecting-ip").and_then(|h| h.to_str().ok()).map(|s| s.trim()).filter(|s| !s.is_empty() && s.parse::<std::net::IpAddr>().is_ok()) {
            Some(ip) => ip.to_string(),
            None => client_ip,
        }
    } else {
        client_ip
    };

    // secret for challenge tokens: the site's, falling back to node_id
    let chl_secret = if site.challenge_secret.is_empty() {
        shared.node_id.clone()
    } else {
        site.challenge_secret.clone()
    };
    // accept a PoW solution: a POST carrying __thwaf_nonce is verified, a cookie is issued, and we redirect to the same URL
    if parts.method == hyper::Method::POST && det.body.contains("__thwaf_nonce") {
        let form = parse_form(&det.body);
        let nonce = form.get("__thwaf_nonce").map(|s| s.as_str()).unwrap_or("");
        let prefix = form.get("__thwaf_prefix").map(|s| s.as_str()).unwrap_or("");
        let diff = if site.challenge_difficulty == 0 { 18 } else { site.challenge_difficulty };
        // the prefix must match the one expected for this IP and window, or the adjacent one
        let valid_prefix = challenge::prefix_valid(&chl_secret, &client_ip, prefix);
        if valid_prefix && challenge::verify_pow(prefix, nonce, diff) {
            shared.metrics.record_challenge(true);
            let token = challenge::issue_token(&chl_secret, &client_ip);
            let cookie = format!(
                "{}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax",
                challenge::COOKIE_NAME, token, challenge::TOKEN_TTL_SECS
            );
            tracing::info!("CHALLENGE-OK {} {}", site.domain, client_ip);
            let resp = match Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(hyper::header::LOCATION, parts.uri.path())
                .header(hyper::header::SET_COOKIE, cookie)
                .body(Full::new(Bytes::new()).map_err(|never| match never {}).boxed())
            {
                Ok(r) => r,
                Err(_) => error_response(StatusCode::SEE_OTHER, "", req_lang),
            };
            return Ok(resp);
        }
        // an incorrect solution: we show the challenge again below
    }
    // is there a valid challenge token, meaning the check was already passed?
    let chl_passed = parts
        .headers
        .get(hyper::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(challenge::token_from_cookies)
        .map(|t| challenge::verify_token(&chl_secret, &client_ip, &t))
        .unwrap_or(false);

    // country from the geo database: always resolved when the database is loaded, so it shows in logs and the UI.
    // Geo BLOCKING is a separate decision made by geo_mode below.
    let country = match shared.geo.load().as_ref() {
        Some(g) => g.country(&client_ip),
        None => String::new(),
    };
    tracing::info!("GEO {} ip={} country={:?} mode={}", site.domain, client_ip, country, site.geo_mode);
    // language for the block and challenge pages: country plus Accept-Language
    let vlang = i18n::page_lang(&country, accept_lang.as_deref());
    // Is the client a browser? We check for text/html in Accept. For non-browsers (mobile apps,
    // API clients) the challenge returns the site's block status instead of a PoW page they cannot execute.
    let wants_html = parts.headers.get(hyper::header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);
    // a single incident id per request, identical in the cloud event, the access log and
    // on the block page (X-THWAF-Incident), so the visitor and the administrator quote the same code.
    let inc = gen_incident_id();

    // prepare the data used for matching
    let uri_str = parts.uri.to_string();
    let args = parts.uri.query().unwrap_or("");
    let path = parts.uri.path();
    let location = verdict::normalize_location(path);

    // the user agent is needed both for the early lightweight geo-block log and in the main chain below.
    let ua = parts
        .headers
        .get(hyper::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();

    // The IP deny list is an explicit hard block, applied BEFORE inspection: there is no point parsing the payload
    // of an already-banned IP. It is always logged as an explicit block, but without body parsing.
    if netutil::ip_in_list(&client_ip, &site.ip_blacklist) {
        tracing::info!("IP-BLACKLIST {} {}", site.domain, client_ip);
        emit_raw(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", 3, "ip_blacklist", &country, &location, &ua, &inc, "", "", &ja3, &ja4);
        access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", "ip_blacklist", 3, &ua, 0, &det, &inc, 0);
        return Ok(block_response(&site, site.block_status, &inc, vlang));
    }

    // Geo is a cheap IP-to-country filter. We decide BEFORE heavy inspection (reading and parsing the body,
    // normalisation, classification) and WITHOUT recording a payload incident: geo-rejected traffic
    // needs no request parsing, so we spend no CPU and store no event. We record only the
    // aggregate (access_log feeding metrics, so the geo-block counter is visible). The IP allow list
    // takes precedence over geo, as it does in the main chain below.
    if !netutil::ip_in_list(&client_ip, &site.ip_whitelist) {
        let gmode = geo::GeoMode::from_str(&site.geo_mode);
        if geo::geo_blocked(gmode, &site.geo_countries, &country) {
            let code = if site.geo_status != 0 { site.geo_status } else { 403 };
            tracing::info!("GEO-BLOCK {} {} {}", site.domain, client_ip, country);
            // An incident event is recorded ONLY when the operator enabled geo_log, which is off by default.
            // No payload inspection (attack_type and body stay empty); JA3 and country are kept for visibility and the feed.
            if site.geo_log {
                emit_raw(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "geo", 2, "geo", &country, &location, &ua, &inc, "", "", &ja3, &ja4);
            }
            access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, code, "geo", "geo", 2, &ua, 0, &det, &inc, 0);
            return Ok(block_response(&site, code, &inc, vlang));
        }
    }

    let ct = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    // Whether this is an upload, judged by content type. Uploads are excluded from tail inspection and the oversized signal:
    // a large body is legitimate for files, and content type is a cheap, reliable indicator.
    let body_is_upload = {
        let c = ct.to_ascii_lowercase();
        c.contains("multipart/form-data") || c.starts_with("image/") || c.starts_with("video/")
            || c.starts_with("audio/") || c.starts_with("font/") || c.contains("application/pdf")
            || c.contains("zip") || c.starts_with("application/octet-stream")
    };
    // Content-Encoding on the REQUEST: a compressed body (gzip/deflate) means we inspect a DECOMPRESSED copy.
    // Otherwise signatures see binary noise while the backend decompresses and executes the payload, a universal
    // bypass of every signature via one gzip wrapper. Forwarding is left untouched (a detection blocks,
    // a clean body is forwarded as is). The decompressed-size limit guards against a decompression bomb.
    let req_ce = parts
        .headers
        .get(hyper::header::CONTENT_ENCODING)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let decoded_body;
    let body_for_inspect: &[u8] = if !body_bytes.is_empty()
        && (req_ce.contains("gzip") || req_ce.contains("deflate") || req_ce.contains("br"))
    {
        match inflate_for_inspection(&body_bytes, &req_ce, inspect_cap.saturating_add(64 * 1024)) {
            Some(v) => {
                decoded_body = v;
                decoded_body.as_slice()
            }
            None => &body_bytes, // decompression failed, so we inspect it as is, which is no worse than before
        }
    } else {
        &body_bytes
    };
    let body_extracted = if body_for_inspect.is_empty() {
        String::new()
    } else if body_for_inspect.len() <= inspect_cap {
        verdict::extract_body(body_for_inspect, ct)
    } else {
        // The body exceeds the inspection window. Prefix plus, for non-uploads, the TAIL, which catches a payload pushed
        // past the limit by leading junk (nowafpls). The tail is fixed-size, so CPU stays O(1).
        let mut ex = verdict::extract_body(&body_for_inspect[..inspect_cap], ct);
        let tail = site.body_tail_kb * 1024;
        if !body_is_upload && tail > 0 {
            let start = body_for_inspect.len().saturating_sub(tail).max(inspect_cap);
            ex.push('\n');
            ex.push_str(&verdict::extract_body(&body_for_inspect[start..], ct));
        }
        ex
    };
    let scheme = if is_tls { "https" } else { "http" };
    // Normalise ONCE per request (multi-layer decode: percent plus \u and \x, and comment removal).
    let uri_norm = verdict::normalize_match(uri_str.as_bytes());
    let args_norm = verdict::normalize_match(args.as_bytes());
    let body_norm = verdict::normalize_match(body_extracted.as_bytes());
    // the attack vector is classified from NORMALISED content (URI plus body), otherwise obfuscated
    // payloads (\u escapes, percent encoding) go unlabelled. A truncated payload feeds the incident view.
    let attack_type = attack::classify(&uri_norm, &body_norm);
    let body_snip = attack::truncate_chars(&body_extracted, 512);
    // "any" means uri plus body plus key headers (UA, Referer, Cookie), all normalised as well.
    let hv = |n: hyper::header::HeaderName| parts.headers.get(n).and_then(|h| h.to_str().ok()).unwrap_or("");
    let any_norm = format!(
        "{}\n{}\n{}\n{}\n{}",
        uri_norm,
        body_norm,
        verdict::normalize_match(hv(hyper::header::USER_AGENT).as_bytes()),
        verdict::normalize_match(hv(hyper::header::REFERER).as_bytes()),
        verdict::normalize_match(hv(hyper::header::COOKIE).as_bytes()),
    );
    let view = verdict::ReqView {
        args,
        method: parts.method.as_str(),
        ip: &client_ip,
        country: &country,
        location: location.clone(),
        body: body_extracted,
        uri_norm,
        args_norm,
        body_norm,
        any_norm,
        headers: &parts.headers,
        scheme,
        http_version: det.http_version,
        ja3: &ja3,
        ja4: &ja4,
    };

    let mode = site.mode.as_str();

    // ML context features (stage 1): stateless fingerprint and header signals. Computed once and
    // stored with samples and review entries for future training. They do NOT enter inference until the version bump
    // in stage 2; for now they merely accumulate in the dataset.
    let ml_ctx: Vec<f32> = {
        let (ua_empty, ua_tool, no_bh, no_ref) = bot::header_signals(&parts.headers);
        features::context(!ja3.is_empty(), bot::tls_ua_mismatch(&ua, &ja3, tls_grease),
                          ua_empty, ua_tool, no_bh, no_ref).to_vec()
    };

    // Exceptions carrying no_log suppress event recording for matching requests WITHOUT removing
    // protection. The emit closure shadows emit_raw and silently skips recording when no_log applies,
    // so every existing emit(...) call below works unchanged.
    let no_log = verdict::eval_no_log(&site.exceptions, &view);
    let emit = |shared: &Shared, site: &Site, ip: &str, method: &str, uri: &str, action: &str, sev: i32, sig: &str, country: &str, location: &str, ua: &str, incident_id: &str, attack_type: &str, body: &str| {
        // learn is quiet training: no events are written, so the feed stays silent. There is no blocking in learn
        // either (all blocking sits behind mode == "protect"), while the normal-traffic ML profile accumulates regardless of
        // mode (see anomaly::observe below). The node builds a baseline while the operator watches
        // progress in the dashboard before promoting the site to detect or protect.
        if !no_log && site.mode != "learn" {
            emit_raw(shared, site, ip, method, uri, action, sev, sig, country, location, ua, incident_id, attack_type, body, &ja3, &ja4);
        }
    };

    // The IP deny list is handled ABOVE, before inspection. The allow list passes immediately, below.
    // 0.1) path traversal: ".." in the decoded path blocks BEFORE rules and exceptions.
    // traversal_logonly logs only, for a trial rollout, and does not block.
    if verdict::has_traversal(&view.uri_norm) {
        if site.traversal_logonly {
            tracing::info!("PATH-TRAVERSAL-LOG {} {} {}", site.domain, client_ip, uri_str);
            emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 3, "path_traversal", &country, &location, &ua, &inc, attack_type, &body_snip);
        } else {
            tracing::info!("PATH-TRAVERSAL {} {} {}", site.domain, client_ip, uri_str);
            emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", 3, "path_traversal", &country, &location, &ua, &inc, attack_type, &body_snip);
            access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, 400, "blocked", "path_traversal", 3, &ua, 0, &det, &inc, 0);
            return Ok(block_response(&site, 400, &inc, vlang));
        }
    }

    // 0.2) per-site IPv6: when disabled we reject genuine IPv6 (IPv4-mapped does not count).
    // ipv6_logonly logs only.
    let real_ipv6 = matches!(client_ip.parse::<std::net::IpAddr>(), Ok(std::net::IpAddr::V6(a)) if a.to_ipv4_mapped().is_none());
    if !site.ipv6_enabled && real_ipv6 {
        if site.ipv6_logonly {
            tracing::info!("IPV6-DISABLED-LOG {} {}", site.domain, client_ip);
            emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 2, "ipv6_disabled", &country, &location, &ua, &inc, attack_type, &body_snip);
        } else {
            tracing::info!("IPV6-DISABLED {} {}", site.domain, client_ip);
            emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", 2, "ipv6_disabled", &country, &location, &ua, &inc, attack_type, &body_snip);
            access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", "ipv6_disabled", 2, &ua, 0, &det, &inc, 0);
            return Ok(block_response(&site, site.block_status, &inc, vlang));
        }
    }

    // 0.3) method allow list: empty means unrestricted. method_logonly logs only.
    if !site.allowed_methods.is_empty() {
        let m = parts.method.as_str();
        if !site.allowed_methods.iter().any(|a| a.eq_ignore_ascii_case(m)) {
            if site.method_logonly {
                tracing::info!("METHOD-BLOCK-LOG {} {} {}", site.domain, client_ip, m);
                emit(&shared, &site, &client_ip, m, &uri_str, "detected", 2, "method_blocked", &country, &location, &ua, &inc, attack_type, &body_snip);
            } else {
                let allow = site.allowed_methods.join(", ");
                tracing::info!("METHOD-BLOCK {} {} {}", site.domain, client_ip, m);
                emit(&shared, &site, &client_ip, m, &uri_str, "blocked", 2, "method_blocked", &country, &location, &ua, &inc, attack_type, &body_snip);
                access_log(&shared, &site, &client_ip, m, &uri_str, &location, &country, 405, "blocked", "method_blocked", 2, &ua, 0, &det, &inc, 0);
                return Ok(method_not_allowed(&allow, vlang));
            }
        }
    }

    let ip_whitelisted = netutil::ip_in_list(&client_ip, &site.ip_whitelist);

    // 0.5) mTLS: when the path requires a client certificate, validate it.
    if !site.mtls_locations.is_empty() {
        let p = parts.uri.path();
        let needs_mtls = site.mtls_locations.iter().any(|loc| {
            let loc = loc.trim();
            !loc.is_empty() && p.starts_with(loc)
        });
        if needs_mtls {
            // a valid client certificate must be presented, with a serial that is not revoked.
            // The CA signature is checked at the TLS layer (a verifier with the site CA); here we check presence and revocation.
            let ok = match &client_serial {
                Some(serial) => {
                    let s = serial.trim_start_matches('0').to_ascii_lowercase();
                    // O(1) lookup in the prebuilt revocation set
                    !site.mtls_revoked_set.contains(&s)
                }
                None => false,
            };
            if !ok {
                tracing::info!("MTLS-DENY {} {} {} (no valid client cert)", site.domain, client_ip, p);
                emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", 3, "mtls", &country, &location, &ua, &inc, attack_type, &body_snip);
                access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", "mtls", 3, &ua, 0, &det, &inc, 0);
                return Ok(block_response(&site, site.block_status, &inc, vlang));
            }
        }
    }

    // 1) exceptions: a full allow, OR targeted suppression of individual signals
    let mut excepted = ip_whitelisted;
    let mut threat: u32 = 0; // the aggregated threat score
    let mut score_sig: Vec<(String, u32)> = Vec::new(); // (signal, points) pairs, powering the itemised 'why' breakdown
    // Whether an attack signature fired (rule/sqli/xss). Such requests seed the quarantine for
    // labelling, since they are confident positive examples for bootstrapping ML.
    let mut sig_attack = false;
    // A trusted reference IP for the site: its traffic is normal, trained with weight x5 and written to
    // ml_samples with label=0. Such IPs are NOT quarantined for labelling, as they are already normal.
    // Computed early, because rule-driven seeding happens before the ML section.
    let ml_trusted = netutil::ip_in_list(&client_ip, &site.ml_trusted_ips);
    // Deferred bot action (challenge or block). Bot detection happens early, contributing to the
    // score and emitting an event, but the ACTION is applied AFTER the threat score so a confirmed
    // attack takes precedence over a bot challenge. None in detect mode.
    let mut bot_action: Option<&'static str> = None;
    // Crawler verification (FCrDNS): handled=true means verified or spoofed, so bot detection is skipped.
    let mut verbot_handled = false;
    let mut verbot_action: Option<&'static str> = None;
    let mut ato_action: Option<&'static str> = None;
    let (full_allow, suppressed) = verdict::eval_exceptions(&site.exceptions, &view);
    if full_allow { excepted = true; }
    let sup = |name: &str| suppressed.iter().any(|s| s.as_str() == name);

    if !excepted {
        // 1.5) auto-ban: a hard early block for a banned IP, before geo, rules and ML, which cheaply shuts
        // down the source. The ban is site-wide, from the cloud feed; allow-list and allow exceptions bypass it.
        // 1.5) IP auto-ban (as before, under autoban_enabled) shuts the source down early. Plus a ban by
        // JA3 fingerprint from the cloud feed: a manual ban that survives IP rotation, since the same TLS stack
        // is cut off regardless of IP and regardless of autoban_enabled, which is a separate capability.
        // Early ban from the feed (automatic and manual): by IP, JA3 or JA4, for the site domain OR the "*" wildcard
        // (a manual ban across all sites). Checked unconditionally, because the feed contains only active,
        // deliberately created bans; autoban_enabled governs the CREATION of auto-bans, not their enforcement.
        let d = site.domain.as_str();
        let banned_subj = |s: &str| !s.is_empty()
            && (shared.ipban.is_banned(d, s) || shared.ipban.is_banned("*", s));
        let ip_banned = banned_subj(&client_ip);
        let ja3_banned = banned_subj(&ja3);
        let ja4_banned = banned_subj(&ja4);
        if ip_banned || ja3_banned || ja4_banned {
            tracing::info!("BANNED {} {} {} (ip={} ja3={} ja4={})", site.domain, client_ip, location, ip_banned, ja3_banned, ja4_banned);
            emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "banned", 4, "autoban", &country, &location, &ua, &inc, attack_type, &body_snip);
            access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "banned", "autoban", 4, &ua, 0, &det, &inc, 0);
            return Ok(block_response(&site, site.block_status, &inc, vlang));
        }
        // 2) Geo policy is an access filter and does NOT depend on learn/detect/protect mode.
        // The hard geo block is handled ABOVE, before inspection; only non-blocked traffic reaches here.
        // grey-listed countries do not block but do contribute to the threat score
        if site.score_enabled && !sup("geo") && !site.score_grey_countries.is_empty()
            && site.score_grey_countries.iter().any(|c| c.eq_ignore_ascii_case(&country)) {
            threat += site.score_w_geo;
            score_sig.push(("geo".into(), site.score_w_geo));
        }

        // 2.2) IP reputation (the cloud threat-intel list), after geo, since there is no point checking
        // reputation for traffic from already-rejected countries. Blocking only in protect; detect logs and scores.
        if site.iprep_enabled {
            let rep = shared.iprep.load();
            if !rep.is_empty() && rep.is_bad(&client_ip) && !sup("ip_reputation") {
                tracing::info!("IP-REPUTATION {} {}", site.domain, client_ip);
                if mode == "protect" {
                    emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", 3, "ip_reputation", &country, &location, &ua, &inc, attack_type, &body_snip);
                    access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", "ip_reputation", 3, &ua, 0, &det, &inc, 0);
                    return Ok(block_response(&site, site.block_status, &inc, vlang));
                } else {
                    emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 3, "ip_reputation", &country, &location, &ua, &inc, attack_type, &body_snip);
                    if site.score_enabled { threat += site.score_w_bot; score_sig.push(("ip_reputation".into(), site.score_w_bot)); }
                }
            }
        }

        // 2.2b) Collective defence: the cross-tenant attacker IP feed (tenant opt-in).
        // The action is governed by collective_defense_action (detect, challenge or block).
        if site.collective_defense_enabled {
            let feed = shared.collective.load();
            if !feed.is_empty() && feed.is_bad(&client_ip) && !sup("collective_threat") {
                tracing::info!("COLLECTIVE {} {} action={}", site.domain, client_ip, site.collective_defense_action);
                if mode == "protect" && site.collective_defense_action == "block" {
                    emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", 3, "collective_threat", &country, &location, &ua, &inc, attack_type, &body_snip);
                    access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", "collective_threat", 3, &ua, 0, &det, &inc, 0);
                    return Ok(block_response(&site, site.block_status, &inc, vlang));
                } else if mode == "protect" && site.collective_defense_action == "challenge" && !chl_passed {
                    access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, 503, "challenge", "collective_threat", 2, &ua, 0, &det, "", 0);
                    return Ok(challenge_response(&site, &chl_secret, &client_ip, vlang, wants_html));
                } else {
                    // detect (pre-warning), or the fallback when mode is detect
                    emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 2, "collective_threat", &country, &location, &ua, &inc, attack_type, &body_snip);
                    if site.score_enabled { threat += site.score_w_bot; score_sig.push(("collective_threat".into(), site.score_w_bot)); }
                }
            }
        }

        // 2.3) API protection: structural JWT plus JSON hygiene (phase 1), then the positive
        // OpenAPI model (phase 2). This runs AFTER geo and IP reputation, since validating the API of a
        // request already rejected by an access filter is pointless and would double up events.
        if site.api_sec.any_enabled() {
            let auth_h = parts.headers.get("authorization").and_then(|h| h.to_str().ok());
            let ct_h = parts.headers.get("content-type").and_then(|h| h.to_str().ok()).unwrap_or("");
            // JWKS keys (RS*/ES*) from the background cache, only when signature verification is enabled
            let jwks_set = if site.api_sec.jwt_verify_sig && !site.api_sec.jwt_jwks_url.is_empty() {
                crate::jwks::get(&site.api_sec.jwt_jwks_url)
            } else {
                None
            };
            if let Some(hit) = crate::apisec::check(parts.uri.path(), parts.method.as_str(), auth_h, ct_h, &body_bytes, &site.api_sec, jwks_set.as_deref()) {
                match hit.sev {
                    crate::apisec::Sev::Detect => {
                        tracing::info!("APISEC-LOG {} {} {} {}", site.domain, client_ip, hit.sig, hit.reason);
                        emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 2, hit.sig, &country, &location, &ua, &inc, attack_type, &body_snip);
                    }
                    crate::apisec::Sev::Block => {
                        tracing::info!("APISEC-BLOCK {} {} {} {}", site.domain, client_ip, hit.sig, hit.reason);
                        emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", 2, hit.sig, &country, &location, &ua, &inc, attack_type, &body_snip);
                        access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", hit.sig, 2, &ua, 0, &det, &inc, 0);
                        return Ok(block_response(&site, site.block_status, &inc, vlang));
                    }
                }
            }
        }
        if site.openapi.active() {
            let ct_h = parts.headers.get("content-type").and_then(|h| h.to_str().ok()).unwrap_or("");
            if let Some(hit) = site.openapi.check(parts.method.as_str(), parts.uri.path(), parts.uri.query().unwrap_or(""), ct_h, &body_bytes) {
                match hit.sev {
                    crate::apisec::Sev::Detect => {
                        tracing::info!("OPENAPI-LOG {} {} {} {}", site.domain, client_ip, hit.sig, hit.reason);
                        emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 2, hit.sig, &country, &location, &ua, &inc, attack_type, &body_snip);
                    }
                    crate::apisec::Sev::Block => {
                        tracing::info!("OPENAPI-BLOCK {} {} {} {}", site.domain, client_ip, hit.sig, hit.reason);
                        emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", 2, hit.sig, &country, &location, &ua, &inc, attack_type, &body_snip);
                        access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", hit.sig, 2, &ua, 0, &det, &inc, 0);
                        return Ok(block_response(&site, site.block_status, &inc, vlang));
                    }
                }
            }
        }

        // 2.36) ATO and credential stuffing on login endpoints, based on the request body.
        if site.ato_enabled && !site.ato_login_paths.is_empty() {
            let m = parts.method.as_str();
            let p = parts.uri.path();
            let is_login = (m == "POST" || m == "PUT")
                && site.ato_login_paths.iter().any(|lp| !lp.is_empty() && p.starts_with(lp.as_str()));
            if is_login {
                let ct = parts.headers.get("content-type").and_then(|h| h.to_str().ok()).unwrap_or("");
                let default_fields;
                let fields: &[String] = if site.ato_user_fields.is_empty() {
                    default_fields = vec!["username".to_string(), "email".to_string(), "login".to_string(), "user".to_string()];
                    &default_fields
                } else {
                    &site.ato_user_fields
                };
                let login = ato::extract_login(ct, &body_bytes, fields).unwrap_or_default();
                let cfg = ato::AtoCfg {
                    window_secs: site.ato_window,
                    ip_attempts: site.ato_ip_attempts,
                    ip_users: site.ato_ip_users,
                    user_ips: site.ato_user_ips,
                };
                if let Some(reason) = shared.ato.observe(&client_ip, &login, &cfg) {
                    if !(sup("ato") || sup(reason)) {
                        tracing::info!("ATO {} {} {} reason={}", site.domain, client_ip, location, reason);
                        emit(&shared, &site, &client_ip, m, &uri_str, "detected", 3, reason, &country, &location, &ua, &inc, attack_type, &body_snip);
                        if site.score_enabled { threat += site.score_w_bot; score_sig.push((reason.into(), site.score_w_bot)); }
                        if !excepted && (site.ato_action == "block" || site.ato_action == "challenge") {
                            ato_action = Some(reason);
                        }
                    }
                }
            }
        }

        // 2.35) Search crawler verification (FCrDNS), which catches User-Agent forgery.
        // Verified means bot detection is skipped for this request: it is a real Googlebot or Bingbot.
        // Spoofed means it claims to be a crawler but rDNS did not confirm it, a strong malicious signal.
        if site.verbot_enabled {
            if let (Some(def), Ok(ipp)) = (verbot::claimed_crawler(&ua), client_ip.parse::<std::net::IpAddr>()) {
                match verbot::cached(&ipp) {
                    Some(verbot::Verdict::Verified(_)) => {
                        verbot_handled = true; // a verified crawler is not treated as a bot
                    }
                    Some(verbot::Verdict::Spoofed(name)) => {
                        verbot_handled = true;
                        if !(sup("bot") || sup("bot_spoofed_crawler")) {
                            tracing::info!("VERBOT-SPOOF {} {} claims={}", site.domain, client_ip, name);
                            emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 3, "bot_spoofed_crawler", &country, &location, &ua, &inc, attack_type, &body_snip);
                            if site.score_enabled { threat += site.score_w_bot; score_sig.push(("bot_spoofed_crawler".into(), site.score_w_bot)); }
                            if !excepted && (site.verbot_spoof_action == "block" || site.verbot_spoof_action == "challenge") {
                                verbot_action = Some("bot_spoofed_crawler");
                            }
                        }
                    }
                    Some(verbot::Verdict::Pending) => { /* a check is already in flight, so take the normal path */ }
                    None => { verbot::spawn_verify(ipp, def); } // first visit: start the background check
                }
            }
        }

        // 2.4) Bot protection operates INDEPENDENTLY of the site mode (detect or protect)
        // and is governed ONLY by bot_mode. This allows blocking bots even while the WAF itself
        // is in detect, so traffic can be cleaned up for ML training. bot_mode=off disables it entirely.
        if site.bot_mode != "off" && !site.bot_mode.is_empty() && !verbot_handled {
            let mut reason: Option<&'static str> = None;
            // a) explicit JA3/JA4 fingerprint deny list, including the client value from a header behind a CDN
            if (!ja3.is_empty() && site.ja3_blacklist.iter().any(|h| h.eq_ignore_ascii_case(&ja3)))
                || (!ja4.is_empty() && site.ja4_blacklist.iter().any(|h| h.eq_ignore_ascii_case(&ja4)))
            {
                reason = Some("tls_fingerprint");
            }
            // a2) the central fingerprint feed from the cloud, gated by the per-site flag
            if reason.is_none() && site.fpfeed_enabled {
                let feed = shared.fpfeed.load();
                if !feed.is_empty() && (feed.contains(&ja3) || feed.contains(&ja4)) {
                    reason = Some("tls_fingerprint");
                }
            }
            // b) header heuristics: an empty or tool-like user agent, or a fake browser
            if reason.is_none() {
                reason = bot::detect(&parts.headers);
            }
            // c) TLS fingerprint mismatch against the claimed browser, ONLY under direct TLS termination
            // (behind a CDN the fingerprint is not the client's, or arrives as a GREASE-free hash, so the check does not apply)
            if reason.is_none() && site.bot_tls_check && direct_tls && bot::tls_ua_mismatch(&ua, &ja3, tls_grease) {
                reason = Some("ua_tls_mismatch");
            }
            // d) behavioural analysis: we observe EVERY request to build the window, and use the reason
            // as a fallback when the static signals did not fire.
            if site.bot_behavior {
                let full_hdr = parts.headers.get("accept").is_some()
                    && parts.headers.get("accept-language").is_some();
                let beh = shared.behavior.observe(&client_ip, parts.uri.path(), &ua, full_hdr, &site.bot_behavior_sens);
                if reason.is_none() { reason = beh; }
            }
            // targeted operator suppression: mute the 'bot' signal, or one specific reason
            if let Some(r) = reason {
                if sup("bot") || sup(r) { reason = None; }
            }
            if let Some(reason) = reason {
                tracing::info!("BOT {} {} {} reason={}", site.domain, client_ip, location, reason);
                emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 2, "bot", &country, &location, &ua, &inc, attack_type, &body_snip);
                if site.score_enabled { threat += site.score_w_bot; score_sig.push((reason.into(), site.score_w_bot)); }
                // The ACTION (challenge or block) is DEFERRED until AFTER the threat score, so that a
                // confirmed attack blocks before a mere bot. In detect there is only
                // logging plus the score contribution above, with no action.
                if site.bot_mode == "block" || site.bot_mode == "challenge" {
                    bot_action = Some(reason);
                }
            }
        }

        // 3) custom rules, where declaration order is priority
        match verdict::eval_rules_sig(&site.custom_rules, &view) {
            Some((verdict::Decision::Block(code), rsig)) => {
                if sup(&rsig) || sup("rule") {
                    // this rule's signal was suppressed by the operator to clear a false positive, so skip it
                } else if mode == "protect" {
                    tracing::info!("BLOCK {} {} {} rule={}", site.domain, client_ip, location, rsig);
                    emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", 3, &rsig, &country, &location, &ua, &inc, attack_type, &body_snip);
                    access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, code, "blocked", &rsig, 3, &ua, 0, &det, &inc, 0);
                    return Ok(block_response(&site, code, &inc, vlang));
                } else {
                    tracing::info!("DETECT(rule) {} {} {} sig={}", site.domain, client_ip, location, rsig);
                    emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 3, &rsig, &country, &location, &ua, &inc, attack_type, &body_snip);
                    if site.score_enabled { threat += site.score_w_rule; score_sig.push((rsig.clone(), site.score_w_rule)); }
                    sig_attack = true;
                }
            }
            Some((verdict::Decision::Detect, rsig)) => {
                if !(sup(&rsig) || sup("rule")) {
                    tracing::info!("DETECT {} {} {} sig={}", site.domain, client_ip, location, rsig);
                    emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 2, &rsig, &country, &location, &ua, &inc, attack_type, &body_snip);
                    if site.score_enabled { threat += site.score_w_rule; score_sig.push((rsig.clone(), site.score_w_rule)); }
                    sig_attack = true;
                }
            }
            Some((verdict::Decision::Allow, _)) => {
                // an explicit allow rule: pass the request, bypassing rate limiting and ML
                tracing::info!("ALLOW(rule) {} {} {}", site.domain, client_ip, location);
                excepted = true;
            }
            Some((verdict::Decision::Challenge, _))
                // the rule demands a browser check, unless one has already been passed
                if mode == "protect" && !chl_passed => {
                    tracing::info!("CHALLENGE(rule) {} {} {}", site.domain, client_ip, location);
                    access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, 503, "challenge", "rule", 2, &ua, 0, &det, "", 0);
                    return Ok(challenge_response(&site, &chl_secret, &client_ip, vlang, wants_html));
                }
            // Skip: rule evaluation ends but the normal pipeline (rate limiting, ML) continues
            _ => {}
        }

        // 3b) Managed rules (virtual patching): the central set from the cloud.
        // They behave like ordinary rules but are limited to block and detect, labelled by CVE or name.
        if site.managed_rules_enabled {
            let mrules = shared.mrules.load();
            if !mrules.is_empty() {
                match verdict::eval_rules_sig(mrules.as_slice(), &view) {
                    Some((verdict::Decision::Block(code), rsig)) => {
                        if !(sup(&rsig) || sup("rule") || sup("managed_rule")) {
                            if mode == "protect" {
                                tracing::info!("MANAGED-BLOCK {} {} {} sig={}", site.domain, client_ip, location, rsig);
                                emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", 3, &rsig, &country, &location, &ua, &inc, attack_type, &body_snip);
                                access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, code, "blocked", &rsig, 3, &ua, 0, &det, &inc, 0);
                                return Ok(block_response(&site, code, &inc, vlang));
                            } else {
                                tracing::info!("MANAGED-DETECT {} {} {} sig={}", site.domain, client_ip, location, rsig);
                                emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 3, &rsig, &country, &location, &ua, &inc, attack_type, &body_snip);
                                if site.score_enabled { threat += site.score_w_rule; score_sig.push((rsig.clone(), site.score_w_rule)); }
                                sig_attack = true;
                            }
                        }
                    }
                    Some((verdict::Decision::Detect, rsig))
                        if !(sup(&rsig) || sup("rule") || sup("managed_rule")) => {
                            tracing::info!("MANAGED-DETECT {} {} {} sig={}", site.domain, client_ip, location, rsig);
                            emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 2, &rsig, &country, &location, &ua, &inc, attack_type, &body_snip);
                            if site.score_enabled { threat += site.score_w_rule; score_sig.push((rsig.clone(), site.score_w_rule)); }
                            sig_attack = true;
                        }
                    _ => {}
                }
            }
        }

        // 3.4) The libinjection-style signal: high-precision SQLi/XSS detection by tokenising, not by regex.
        // It contributes to the threat score, where the threshold rather than a single signal decides. This is the
        // 'option 2' approach: precise detection with minimal false positives, blocking only when the threat score is enabled.
        if site.siginj_enabled {
            let kind = if siginj::is_sqli(&view.any_norm).is_some() {
                Some("sqli")
            } else if siginj::is_xss(&view.any_norm).is_some() {
                Some("xss")
            } else if siginj::is_xxe(&view.any_norm).is_some() {
                Some("xxe")
            } else {
                None
            };
            if let Some(kind) = kind {
                if !sup(kind) {
                    tracing::info!("SIGINJ {} {} {} kind={}", site.domain, client_ip, location, kind);
                    emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 3, kind, &country, &location, &ua, &inc, attack_type, &body_snip);
                    if site.score_enabled { threat += site.score_w_rule; score_sig.push((kind.into(), site.score_w_rule)); }
                    sig_attack = true;
                }
            }
        }

        // File uploads are detected by request SHAPE (multipart with a file part, or a write method
        // with a file-like Content-Type or filename), NOT by path. upload_paths, when set, is an optional
        // additional scope. Multipart is parsed PART BY PART and the size limit is per file.
        {
            let path_u = parts.uri.path();
            let scope_ok = site.upload_paths.is_empty()
                || site.upload_paths.iter().any(|pref| path_u.starts_with(pref.as_str()));
            let ctl = ct.to_ascii_lowercase();
            let is_multipart = ctl.contains("multipart/form-data");
            let hdr_fname = parts.headers
                .get("x-upload-content-name")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
                .or_else(|| {
                    parts.headers
                        .get(hyper::header::CONTENT_DISPOSITION)
                        .and_then(|h| h.to_str().ok())
                        .and_then(|cd| cd.split("filename=").nth(1))
                        .map(|f| f.trim().trim_matches('"').to_string())
                })
                .unwrap_or_default();
            let is_write = matches!(parts.method.as_str(), "POST" | "PUT" | "PATCH");
            let file_ish = ctl.starts_with("image/") || ctl.starts_with("video/")
                || ctl.starts_with("audio/") || ctl.starts_with("font/")
                || ctl.contains("application/pdf") || ctl.contains("zip")
                || ctl.starts_with("application/octet-stream");
            let is_upload = scope_ok && (is_multipart || (is_write && (!hdr_fname.is_empty() || file_ish)));
            if is_upload {
                let (up_threat, max_file) = if is_multipart {
                    let sc = verdict::scan_multipart_upload(ct, &body_bytes);
                    (sc.threat, sc.max_file)
                } else {
                    (verdict::upload_threat(ct, &hdr_fname, &body_bytes), body_bytes.len())
                };
                // per-file size limit (the maximum size of a single file)
                if site.upload_max_kb > 0 && max_file > site.upload_max_kb * 1024 {
                    tracing::info!("UPLOAD-TOO-LARGE {} {} {} bytes > {} KB", site.domain, path_u, max_file, site.upload_max_kb);
                    return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE, "upload too large", req_lang));
                }
                if let Some(uk) = up_threat {
                    if !sup("upload") {
                        tracing::info!("UPLOAD {} {} {} kind={}", site.domain, client_ip, location, uk);
                        // a hard block (the upload_block option) in protect; otherwise it only contributes to the score
                        if site.upload_block && mode == "protect" && !excepted {
                            emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", 3, uk, &country, &location, &ua, &inc, attack_type, &body_snip);
                            access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", uk, 3, &ua, 0, &det, &inc, 0);
                            return Ok(block_response(&site, site.block_status, &inc, vlang));
                        }
                        emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 3, uk, &country, &location, &ua, &inc, attack_type, &body_snip);
                        if site.score_enabled {
                            threat += site.score_w_rule;
                            score_sig.push((uk.into(), site.score_w_rule));
                        }
                        sig_attack = true;
                    }
                }
            }
        }

        // The oversized-body signal: an uninspected gap remains between the inspected prefix and the
        // tail (body larger than inspect_cap plus tail) and this is NOT an upload. It counters
        // nowafpls padding at both ends, which hides the payload in the middle.
        if site.body_oversized > 0 && !body_is_upload && !excepted
            && body_bytes.len() > inspect_cap.saturating_add(site.body_tail_kb * 1024) {
            let uk = "oversized_body";
            tracing::info!("OVERSIZED {} {} {} {}B (cap {}B + tail {}KB)",
                site.domain, client_ip, location, body_bytes.len(), inspect_cap, site.body_tail_kb);
            if site.body_oversized == 2 && mode == "protect" {
                emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", 3, uk, &country, &location, &ua, &inc, attack_type, &body_snip);
                access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", uk, 3, &ua, 0, &det, &inc, 0);
                return Ok(block_response(&site, site.block_status, &inc, vlang));
            }
            emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 2, uk, &country, &location, &ua, &inc, attack_type, &body_snip);
            if site.score_enabled {
                threat += site.score_w_rule;
                score_sig.push((uk.into(), site.score_w_rule));
            }
            sig_attack = true;
        }

        // 3.5) Seed the quarantine from confident signatures (rule/sqli/xss). Attacks caught by
        // rules or the tokeniser are the best positive examples for labelling and training the
        // model; otherwise the quarantine fills only with the ML grey zone and outright attacks never
        // reach training. Only when ML is enabled for the site, and never for excepted traffic.
        // Deduplicated by (host, method, path, query) over a TTL so that one payload, or a WAF test in a loop,
        // does not flood the quarantine; distinct payloads, as from a test suite, still get through for labelling.
        if sig_attack && site.ml_enabled && !excepted && !ml_trusted {
            let pat = review_pattern(&site.domain, parts.method.as_str(), parts.uri.path(), parts.uri.query().unwrap_or(""), "a");
            if review_dedup(&pat) {
                shared.reviews.push(review_item(&site.domain, &client_ip, &country, parts.method.as_str(), &uri_str, parts.uri.path(), parts.uri.query().unwrap_or(""), &body_snip, 1.0, &ml_ctx, &pat));
            }
        }

        // 3) Per-location rate limiting (token bucket), skipped when an allow rule matched.
        // Extensions: keying per IP, token, header or cookie; adaptive tightening under load;
        // and challenge instead of block, so humans solve the PoW and automation does not.
        if !excepted {
          // adaptive site load (rps), measured once per request when enabled
          let under_load = if site.adaptive_rl_enabled && site.adaptive_rl_threshold > 0 {
              let rps = shared.load.observe(ratelimit::str_key(&site.domain), site.adaptive_rl_window);
              rps >= site.adaptive_rl_threshold
          } else { false };
          if let Some((idx, rule)) = ratelimit::pick_rule(&site.rate_rules, &location) {
            // the rule's extra condition, when set: the limit applies only on a match
            let cond_ok = match &rule.when {
                Some(c) => verdict::cond_matches_pub(c, &view),
                None => true,
            };
            // key material for the limit: ip (default) | token | header:Name | cookie:name
            let key_material = match rule.key.as_str() {
                "token" => {
                    parts.headers.get("authorization").and_then(|v| v.to_str().ok()).map(|a| a.trim())
                        .and_then(|a| if a.len() > 7 && a[..7].eq_ignore_ascii_case("bearer ") { Some(a[7..].trim().to_string()) }
                                      else if !a.is_empty() { Some(a.to_string()) } else { None })
                        .or_else(|| parts.headers.get("x-api-key").and_then(|v| v.to_str().ok())
                                     .map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
                        .map(|t| format!("t:{}", t)).unwrap_or_else(|| client_ip.clone())
                }
                k if k.starts_with("header:") => {
                    parts.headers.get(&k[7..]).and_then(|v| v.to_str().ok()).map(|s| s.trim())
                        .filter(|s| !s.is_empty()).map(|v| format!("h:{}", v)).unwrap_or_else(|| client_ip.clone())
                }
                k if k.starts_with("cookie:") => {
                    let name = &k[7..];
                    parts.headers.get("cookie").and_then(|v| v.to_str().ok())
                        .and_then(|c| c.split(';').map(|s| s.trim())
                            .find_map(|kv| kv.strip_prefix(&format!("{}=", name)).filter(|v| !v.is_empty()).map(|v| format!("c:{}", v))))
                        .unwrap_or_else(|| client_ip.clone())
                }
                // Limiting by TLS fingerprint counters botnet IP rotation: the same client
                // stack shares one bucket regardless of IP. Falls back to IP when no fingerprint exists
                // (behind a CDN or without direct TLS, ja3 and ja4 are empty).
                "ja3" => if !ja3.is_empty() { format!("j3:{}", ja3) } else { client_ip.clone() },
                "ja4" => if !ja4.is_empty() { format!("j4:{}", ja4) } else { client_ip.clone() },
                _ => client_ip.clone(),
            };
            let key = ratelimit::rate_key(&key_material, idx);
            // effective rps: under load it is reduced by adaptive_rl_factor per cent
            let eff_rps = if under_load && site.adaptive_rl_factor < 100 {
                ((rule.rps as u64 * site.adaptive_rl_factor as u64) / 100).max(1) as u32
            } else { rule.rps };
            if cond_ok && shared.rl.limited(key, eff_rps, rule.burst) {
                // challenge instead of block: when the rule asks for it, OR adaptively under load
                let want_challenge = rule.action == "challenge" || (under_load && site.adaptive_rl_challenge);
                if want_challenge && mode == "protect" && !chl_passed {
                    tracing::info!("RATELIMIT-CHALLENGE {} {} {}", site.domain, client_ip, location);
                    access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, 503, "challenge", "ratelimit", 2, &ua, 0, &det, "", 0);
                    return Ok(challenge_response(&site, &chl_secret, &client_ip, vlang, wants_html));
                }
                if mode == "protect" {
                    tracing::info!("RATELIMIT {} {} {}", site.domain, client_ip, location);
                    emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "ratelimited", 2, "ratelimit", &country, &location, &ua, &inc, attack_type, &body_snip);
                    let code = if rule.status != 0 { rule.status } else { site.ratelimit_status };
                    access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, code, "ratelimited", "ratelimit", 2, &ua, 0, &det, &inc, 0);
                    return Ok(block_response(&site, code, &inc, vlang));
                } else {
                    tracing::info!("RATELIMIT-DETECT {} {} {}", site.domain, client_ip, location);
                    emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 2, "ratelimit", &country, &location, &ua, &inc, attack_type, &body_snip);
                }
            }
          }
        }
    }

    // ---- Unsupervised ML: profile training and anomaly scoring ----
    // Reset the anomaly profile on a dashboard signal (the epoch in policy). Cheap: a get plus a comparison,
    // with an actual reset only when the epoch advanced.
    shared.ml.maybe_reset(&site.domain, site.ml_reset_epoch);
    // Whether the supervised model is active: the toggle is on AND a model is actually loaded. If it is enabled
    // but no model file exists, supervised scoring does not run and anomaly acts as the FALLBACK rather than falling silent.
    let ml_model = if site.ml_enabled && !excepted {
        // this asset's model, by domain, otherwise the tenant-wide model under the '' key
        let map = shared.ml_models.load();
        map.get(&site.domain).or_else(|| map.get("")).cloned()
    } else {
        None
    };
    let ml_active = ml_model.is_some();
    let mut anom_score: f64 = 0.0; // the retained anomaly score, for the ensemble with LightGBM
    // a NORMAL sample from a trusted IP goes to the buffer and periodically to the cloud (ml_samples, label=0).
    // We do NOT send a request that tripped an attack signature (rule/sqli/xss) as normal:
    // even from a trusted IP it is not a baseline, and it would poison supervised label=0.
    if ml_trusted && !sig_attack {
        shared.samples.record(&site.domain, path, parts.uri.query().unwrap_or(""), &body_snip, &ml_ctx);
    }
    // Baseline: trusted IPs (ml_trusted_ips) are fed into training EVEN when excepted
    // via the allow list, so one IP can be both legitimate (rules never fire) and a reference
    // for the model. Ordinary traffic trains only when not excepted, and so do scoring and blocking.
    // CRITICAL: requests carrying an attack signature (sig_attack) are NOT trained as normal, otherwise the
    // baseline drifts toward attacks during a WAF test or a real attack, and anomaly detection goes blind.
    if (ml_trusted || !excepted) && !sig_attack {
        let feats = anomaly::extract_features(args, &view.body);
        // requests from trusted IPs are reinforced more strongly, counting as several observations.
        let weight = if ml_trusted { 5 } else { 1 };
        for _ in 0..weight {
            shared.ml.observe(&site.domain, &location, &client_ip, &feats, now_unix());
        }
        // anomaly scoring applies only to non-excepted traffic, since excepted traffic goes no further
        if !excepted && shared.ml.ready(&site.domain) {
            let score = shared.ml.score(&site.domain, &location, &feats);
            anom_score = score; // retained for the ensemble with LightGBM
            let thr = anomaly::threshold(&site.anomaly_sens);
            // When supervised ML is ACTIVE (enabled AND a model is loaded), anomaly does NOT act on
            // its own; its contribution enters the ensemble below. If ML is enabled but no model exists,
            // ml_active is false and anomaly works as the fallback for detection, blocking and scoring.
            if !ml_active && !sup("anomaly") {
                // Cold start: while there is no supervised model, quarantine candidates come from
                // anomaly. Everything above the lower review threshold (score >= lo) is sent for labelling,
                // so both borderline and clearly suspicious requests reach the quarantine.
                // Otherwise the quarantine stays empty until a model exists, and a model cannot be trained without labels.
                if site.ml_enabled && !ml_trusted {
                    let lo = if site.ml_review_low > 0.0 { site.ml_review_low } else { 0.4 };
                    if score >= lo {
                        det.ml_proba = score as f32;
                        let pat = review_pattern(&site.domain, parts.method.as_str(), parts.uri.path(), parts.uri.query().unwrap_or(""), "g");
                        if review_dedup(&pat) {
                            shared.reviews.push(review_item(&site.domain, &client_ip, &country, parts.method.as_str(), &uri_str, parts.uri.path(), parts.uri.query().unwrap_or(""), &body_snip, score as f32, &ml_ctx, &pat));
                        }
                    }
                }
                if score >= thr {
                    let sev: u8 = if score >= 0.95 { 4 } else if score >= 0.88 { 3 } else { 2 };
                    if mode == "protect" && site.anomaly_block {
                        tracing::info!("ANOMALY-BLOCK {} {} {} score={:.2}", site.domain, client_ip, location, score);
                        emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", sev.into(), "anomaly", &country, &location, &ua, &inc, attack_type, &body_snip);
                        access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, 403, "anomaly", "anomaly", sev, &ua, 0, &det, &inc, 0);
                        return Ok(block_response(&site, site.block_status, &inc, vlang));
                    } else {
                        tracing::info!("ANOMALY {} {} {} score={:.2}", site.domain, client_ip, location, score);
                        emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", sev.into(), "anomaly", &country, &location, &ua, &inc, attack_type, &body_snip);
                        if site.score_enabled {
                            let pts = (site.score_w_anomaly as f64 * score).round() as u32;
                            threat += pts;
                            score_sig.push(("anomaly".into(), pts));
                        }
                    }
                }
            }
        }
    }

    // ---- Supervised ML (LightGBM): contributes to the threat score and does NOT block directly ----
    // One scale: ML is a weighted signal like siginj or rules. The blocking decision is made
    // ONLY by the threat score from the points total; the ML weight is visible in the calculator and honestly
    // reflects its contribution. There is no longer a direct ML block bypassing the threshold.
    // An explanation of the ML contribution (top Saabas features plus the family), so the
    // threat_score event shows WHAT the model reacted to rather than just 'score=N (ml:N)'.
    let mut ml_score_why = String::new();
    if let Some(model) = ml_model {
        let qs = parts.uri.query().unwrap_or("");
        let path = parts.uri.path();
        let feats = features::extract(path, qs, &det.body);
        let proba = model.predict(&feats);
        det.ml_proba = proba as f32; // retained for the access log, used by quarantine and analysis
        let thr_for_metric = if site.ml_threshold > 0.0 { site.ml_threshold } else { 0.8 };
        shared.metrics.record_ml(proba, proba >= thr_for_metric);
        // ENSEMBLE: supervised (attacks) plus unsupervised (the site's normal). Agreement between the models
        // raises confidence. anom_score is 0 when the anomaly profile is not ready yet.
        let conf = if anom_score > 0.0 {
            let mix = 0.7 * proba + 0.3 * anom_score;
            let agree = if proba > 0.6 && anom_score > 0.6 { 0.1 } else { 0.0 };
            (mix + agree).min(1.0)
        } else {
            proba
        };
        let thr = if site.ml_threshold > 0.0 { site.ml_threshold } else { 0.8 };
        let lo = if site.ml_review_low > 0.0 { site.ml_review_low } else { 0.4 };
        if conf >= lo && !sup("ml") {
            let ml_sev = ml_band(conf);
            let min_sev = site.ml_min_severity.max(1); // 0 or 1 means low, the current behaviour
            // Contributes to the threat score in proportion to confidence, like siginj and rules,
            // but ONLY when the severity band reaches the operator's configured minimum.
            // Contributes to the threat score ONLY in score mode, where ML does not block directly,
            // and only once the configured severity level is reached.
            if !site.ml_severity_block && site.score_enabled && ml_sev >= min_sev {
                let pts = (site.score_w_ml as f64 * conf).round() as u32;
                threat += pts;
                // The label carries the ensemble composition, ml(s=supervised, a=anomaly), so the
                // score=N (...) breakdown shows who contributed what. With no anomaly profile ready, only s appears.
                let label = if anom_score > 0.0 {
                    format!("ml(s{:.2}+a{:.2})", proba, anom_score)
                } else {
                    format!("ml(s{:.2})", proba)
                };
                score_sig.push((label, pts));
                // what pushed the score: the top Saabas features, plus the family on a clear signature hit
                let tf = model.top_features(&feats, 3).join(",");
                let fam = features::dominant_family(&feats);
                ml_score_why = if fam == "structural" || fam.is_empty() { tf }
                    else if tf.is_empty() { fam.to_string() }
                    else { format!("{},{}", fam, tf) };
            }

            let acts = ml_sev >= min_sev; // the band reaches the operator's configured level
            let is_hit = conf >= thr; // a confident ML detection
            // Direct blocking from a given level upwards happens only under ml_severity_block combined with protect.
            let block_now = site.ml_severity_block && mode == "protect" && !excepted && is_hit && acts;
            // Detection: in block mode we also log hits BELOW the level; in score mode only from the level upwards.
            let detect_now = is_hit && !block_now && (acts || site.ml_severity_block);
            if block_now || detect_now {
                let sev: u8 = ml_sev.max(1);
                // Attack family: signature-based classify, or when that is empty (ML caught something obfuscated or novel)
                // an estimate from the model's feature vector. Explainability (top Saabas features) reaches the incident view via |ml_why:.
                let ml_type = if attack_type.is_empty() { features::dominant_family(&feats) } else { attack_type };
                let why = model.top_features(&feats, 3).join(",");
                let fam = if ml_type.is_empty() { "ml" } else { ml_type };
                let ml_at = if why.is_empty() { ml_type.to_string() } else { format!("{}|ml_why:{}", fam, why) };
                if block_now {
                    tracing::info!("ML-BLOCK {} {} {} conf={:.3} sev={} type={} why={}", site.domain, client_ip, location, conf, sev, if ml_type.is_empty() { "?" } else { ml_type }, why);
                    emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", sev.into(), "ml", &country, &location, &ua, &inc, &ml_at, &body_snip);
                    access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", "ml", sev, &ua, 0, &det, &inc, 0);
                    return Ok(block_response(&site, site.block_status, &inc, vlang));
                }
                tracing::info!("ML-DETECT {} {} {} conf={:.3} (ml={:.3} anom={:.3}) type={} why={}", site.domain, client_ip, location, conf, proba, anom_score, if ml_type.is_empty() { "?" } else { ml_type }, why);
                emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", sev.into(), "ml", &country, &location, &ua, &inc, &ml_at, &body_snip);
            } else if !ml_trusted {
                // the grey zone: the model is unsure, so the request is quarantined for human labelling.
                // Trusted IPs are not labelled, since their traffic already counts as normal.
                let pat = review_pattern(&site.domain, parts.method.as_str(), parts.uri.path(), parts.uri.query().unwrap_or(""), "g");
                if review_dedup(&pat) {
                    tracing::info!("ML-REVIEW {} {} {} conf={:.3}", site.domain, client_ip, location, conf);
                    shared.reviews.push(review_item(&site.domain, &client_ip, &country, parts.method.as_str(), &uri_str, parts.uri.path(), parts.uri.query().unwrap_or(""), &body_snip, det.ml_proba, &ml_ctx, &pat));
                }
            }
        }
    }

    // ---- Threat Score: the final decision based on the aggregated total ----
    if site.score_enabled && !excepted && threat > 0 {
        shared.metrics.record_threat_level(threat);
    }
    // The 'why': the final score plus a per-signal breakdown, so an operator can tune the threshold.
    // For example "score=7 (sqli:3, bot:2, ml:2)". Identical signals are summed.
    let why = {
        let mut agg: Vec<(String, u32)> = Vec::new();
        for (label, pts) in &score_sig {
            if let Some(e) = agg.iter_mut().find(|(l, _)| l == label) { e.1 += *pts; }
            else { agg.push((label.clone(), *pts)); }
        }
        if agg.is_empty() {
            attack_type.to_string()
        } else {
            let parts: Vec<String> = agg.iter().map(|(l, p)| format!("{}:{}", l, p)).collect();
            format!("score={} ({})", threat, parts.join(", "))
        }
    };
    // append the ML explanation behind the |ml_why: marker, so the threat_score event shows what
    // the model reacted to; the dashboard parses it and renders the 'why blocked' chips.
    let why = if ml_score_why.is_empty() { why } else { format!("{}|ml_why:{}", why, ml_score_why) };
    if site.score_enabled && site.score_threshold > 0 && !excepted && threat >= site.score_threshold {
        if mode == "protect" {
            tracing::info!("THREAT-BLOCK {} {} {} score={} [{}]", site.domain, client_ip, location, threat, why);
            emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "blocked", 4, "threat_score", &country, &location, &ua, &inc, &why, &body_snip);
            access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", "threat_score", 4, &ua, 0, &det, &inc, 0);
            return Ok(block_response(&site, site.block_status, &inc, vlang));
        } else {
            // detect and learn: log as detected only, never block
            tracing::info!("THREAT-DETECT {} {} {} score={} [{}]", site.domain, client_ip, location, threat, why);
            emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "detected", 3, "threat_score", &country, &location, &ua, &inc, &why, &body_snip);
        }
    } else if site.score_enabled && site.score_challenge > 0 && !excepted && !chl_passed
        && threat >= site.score_challenge
        && mode == "protect" {
            // a mid-range score: serve the proof-of-work challenge
            tracing::info!("CHALLENGE(score) {} {} score={} [{}]", site.domain, client_ip, threat, why);
            emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "challenge", 3, "threat_score", &country, &location, &ua, &inc, &why, &body_snip);
            access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, 503, "challenge", "threat_score", 3, &ua, 0, &det, "", 0);
            return Ok(challenge_response(&site, &chl_secret, &client_ip, vlang, wants_html));
        }
    // Sub-threshold score: the request scored points but reached neither block nor challenge.
    // A separate low-importance event, so that during tuning the score of EVERY request is visible
    // with its breakdown (e.g. "score=5 (sqli:3, bot:2)"), not just for blocked ones.
    if site.score_enabled && !excepted && threat > 0
        && (site.score_threshold == 0 || threat < site.score_threshold) {
        emit(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, "scored", 1, "threat_score", &country, &location, &ua, &inc, &why, &body_snip);
    }

    // Deferred bot action: applied ONLY when no block or challenge was already returned above
    // by rules, ML or the threat score, since a confirmed attack would have responded already. What remains is
    // a plain bot with no attack: challenge or block per bot_mode. We honour `excepted`: an explicit allow rule or allow list
    // takes precedence over a bot challenge, because allow means a trusted client.
    if let Some(reason) = bot_action {
        if !excepted && site.bot_mode == "block" {
            tracing::info!("BOT-BLOCK {} {} {} reason={}", site.domain, client_ip, location, reason);
            access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", reason, 3, &ua, 0, &det, &inc, 0);
            return Ok(block_response(&site, site.block_status, &inc, vlang));
        }
        if !excepted && site.bot_mode == "challenge" && !chl_passed {
            tracing::info!("CHALLENGE(bot) {} {}", site.domain, client_ip);
            access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, 503, "challenge", reason, 2, &ua, 0, &det, "", 0);
            return Ok(challenge_response(&site, &chl_secret, &client_ip, vlang, wants_html));
        }
    }

    // Deferred action for a SPOOFED crawler (verbot), governed by verbot_spoof_action
    // independently of bot_mode. Like the bot action it runs after the threat score, so an attack blocks first.
    if let Some(reason) = verbot_action {
        if !excepted && site.verbot_spoof_action == "block" {
            tracing::info!("VERBOT-BLOCK {} {} {} reason={}", site.domain, client_ip, location, reason);
            access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", reason, 3, &ua, 0, &det, &inc, 0);
            return Ok(block_response(&site, site.block_status, &inc, vlang));
        }
        if !excepted && site.verbot_spoof_action == "challenge" && !chl_passed {
            tracing::info!("VERBOT-CHALLENGE {} {}", site.domain, client_ip);
            access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, 503, "challenge", reason, 2, &ua, 0, &det, "", 0);
            return Ok(challenge_response(&site, &chl_secret, &client_ip, vlang, wants_html));
        }
    }

    // Deferred action for ATO and credential stuffing, governed by ato_action independently of bot_mode.
    if let Some(reason) = ato_action {
        if !excepted && site.ato_action == "block" {
            tracing::info!("ATO-BLOCK {} {} {} reason={}", site.domain, client_ip, location, reason);
            access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, site.block_status, "blocked", reason, 3, &ua, 0, &det, &inc, 0);
            return Ok(block_response(&site, site.block_status, &inc, vlang));
        }
        if !excepted && site.ato_action == "challenge" && !chl_passed {
            tracing::info!("ATO-CHALLENGE {} {}", site.domain, client_ip);
            access_log(&shared, &site, &client_ip, parts.method.as_str(), &uri_str, &location, &country, 503, "challenge", reason, 2, &ua, 0, &det, "", 0);
            return Ok(challenge_response(&site, &chl_secret, &client_ip, vlang, wants_html));
        }
    }

    // proxy with the buffered body
    let method_s = parts.method.as_str().to_string();
    // Cache: the key is computed BEFORE parts are moved out; the lookup happens HERE, that is
    // AFTER every WAF check (rules, geo, limits, bots, ML). A hit saves only the backend round-trip.
    let cache_key = cacheable_request(&parts, &site).map(|enc| cache_key_of(&host, &parts, enc));
    if let Some(ref key) = cache_key {
        if let Some(hit) = shared.cache.get(key) {
            let st = hit.status;
            let bytes_out = hit.body.len() as u64;
            shared.metrics.record(st);
            shared.metrics.inc_passed();
            access_log(&shared, &site, &client_ip, &method_s, &uri_str, &location,
                &country, st, "cache_hit", "", 0, &ua, 0, &det, "", bytes_out);
            return Ok(build_from_cache(hit));
        }
    }
    let t0 = std::time::Instant::now();
    match proxy(parts, body_bytes, &site, &shared, &client_ip, is_tls).await {
        Ok(resp) => {
            // ── DLP: RESPONSE body inspection, buffered when the type and size are suitable ──
            let resp = if site.dlp_enabled {
                let ct = resp.headers().get(hyper::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let clen = resp.headers().get(hyper::header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<usize>().ok());
                let ce = resp.headers().get(hyper::header::CONTENT_ENCODING).is_some();
                let cap = if site.dlp_max_scan == 0 { 1024 * 1024 } else { site.dlp_max_scan };
                // Scanning happens only with a KNOWN Content-Length at or below the cap. Without a length
                // (chunked or streaming) we do NOT buffer, otherwise a large response would be held in memory
                // in full and risk OOM. Such a response passes without a DLP scan, a deliberate anti-OOM trade-off.
                if crate::dlp::scannable(&ct) && !ce && clen.map(|n| n <= cap).unwrap_or(false) {
                    let (mut rp, body) = resp.into_parts();
                    match body.collect().await {
                        Ok(col) => {
                            let bytes = col.to_bytes();
                            let cfg = crate::dlp::DlpCfg {
                                max_scan: cap, secrets: site.dlp_secrets, pii: site.dlp_pii,
                                errors: site.dlp_errors, patterns: site.dlp_patterns.clone(),
                            };
                            let (findings, redacted) = crate::dlp::scan(&bytes, &ct, &cfg, site.dlp_action == "redact");
                            if !findings.is_empty() {
                                let kinds = findings.iter().map(|f| format!("{}×{}", f.kind, f.count)).collect::<Vec<_>>().join(",");
                                tracing::info!("DLP {} {} action={} {}", site.domain, client_ip, site.dlp_action, kinds);
                                let act = if site.dlp_action == "block" { "blocked" } else { "detected" };
                                emit(&shared, &site, &client_ip, &method_s, &uri_str, act, 2, "dlp_leak", &country, &location, &ua, &inc, &kinds, "");
                                if site.dlp_action == "block" {
                                    access_log(&shared, &site, &client_ip, &method_s, &uri_str, &location, &country, site.block_status, "blocked", "dlp_leak", 2, &ua, 0, &det, &inc, 0);
                                    return Ok(block_response(&site, site.block_status, &inc, vlang));
                                }
                            }
                            let out = redacted.map(Bytes::from).unwrap_or(bytes);
                            rp.headers.remove(hyper::header::CONTENT_LENGTH);
                            rp.headers.insert(hyper::header::CONTENT_LENGTH, hyper::header::HeaderValue::from(out.len()));
                            Response::from_parts(rp, Full::new(out).map_err(|never| match never {}).boxed())
                        }
                        Err(_) => return Ok(error_response(StatusCode::BAD_GATEWAY, "upstream error", req_lang)),
                    }
                } else {
                    resp
                }
            } else {
                resp
            };
            let lat = t0.elapsed().as_millis() as u32;
            let st = resp.status().as_u16();
            // response size, taken from Content-Length when present
            let bytes_out = resp.headers()
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            // EVERY proxied request reaches the access log, including passes
            let action = if st >= 500 { "upstream_error" } else { "pass" };
            shared.metrics.record(st);
            shared.metrics.inc_passed();
            access_log(&shared, &site, &client_ip, &method_s, &uri_str, &location,
                &country, st, action, "", 0, &ua, lat, &det, "", bytes_out);
            // cache store, only on a miss and only after the WAF: retain a cacheable response
            if let Some(key) = cache_key {
                if let Some(ttl) = cache_ttl_of(resp.headers(), st, &site) {
                    if (1..=4 * 1024 * 1024).contains(&bytes_out) {
                        let (mut rp, body) = resp.into_parts();
                        match body.collect().await {
                            Ok(col) => {
                                let bytes = col.to_bytes();
                                shared.cache.put(key, st, cache_headers(&rp.headers), bytes.clone(), ttl);
                                rp.headers.insert("x-cache", hyper::header::HeaderValue::from_static("MISS"));
                                return Ok(Response::from_parts(rp, Full::new(bytes).map_err(|never| match never {}).boxed()));
                            }
                            Err(_) => return Ok(error_response(StatusCode::BAD_GATEWAY, "upstream error", req_lang)),
                        }
                    }
                }
            }
            Ok(resp)
        }
        Err(e) => {
            tracing::warn!("proxy error for {}: {:?}", site.domain, e);
            // a backend timeout yields 504; unreachability or a connection error yields 502
            let es = format!("{:?}", e).to_lowercase();
            let (code, st_enum) = if es.contains("timeout") || es.contains("timed out") || es.contains("elapsed") {
                (504u16, StatusCode::GATEWAY_TIMEOUT)
            } else {
                (502u16, StatusCode::BAD_GATEWAY)
            };
            shared.metrics.record(code);
            access_log(&shared, &site, &client_ip, &method_s, &uri_str, &location,
                &country, code, "upstream_error", "proxy", 1, &ua, t0.elapsed().as_millis() as u32, &det, "", 0);
            Ok(error_response(st_enum, "upstream error", req_lang))
        }
    }
}

/// Read the body under a limit, cutting off enormous bodies before inspection.
/// RAII reservation against the global body-buffering RAM budget. On Drop it returns
/// the held bytes to the shared counter. The caller keeps it alive as long as body_bytes lives.
struct BufReservation {
    counter: Arc<AtomicUsize>,
    held: usize,
}
impl BufReservation {
    /// Reserve n bytes in the global budget. false means the budget is exhausted. It is a soft limit:
    /// a small overshoot is possible under a race, which is fine since the OOM protection still holds.
    fn reserve(&mut self, n: usize, budget: usize) -> bool {
        let prev = self.counter.fetch_add(n, Ordering::Relaxed);
        if prev + n > budget {
            self.counter.fetch_sub(n, Ordering::Relaxed);
            false
        } else {
            self.held += n;
            true
        }
    }
}
impl Drop for BufReservation {
    fn drop(&mut self) {
        if self.held > 0 {
            self.counter.fetch_sub(self.held, Ordering::Relaxed);
        }
    }
}

/// Result of reading a body: the body plus its memory reservation, the per-request ceiling exceeded (413),
/// or the node's global RAM budget exhausted (503, shedding load to avoid OOM).
enum Collected {
    Body(Bytes, BufReservation),
    TooLarge,
    Overloaded,
}

async fn collect_limited(
    mut body: Incoming,
    limit: usize,
    counter: Arc<AtomicUsize>,
    budget: usize,
) -> Result<Collected, Box<dyn std::error::Error + Send + Sync>> {
    use bytes::BytesMut;
    // Accumulate frames as they stream in. Two safeguards:
    //  - the per-request ceiling `limit` (max_body_kb, or 64 MB) yields TooLarge (413);
    //  - the node's global RAM budget yields Overloaded (503), so an avalanche of large POSTs cannot cause OOM.
    let mut buf = BytesMut::new();
    let mut res = BufReservation { counter, held: 0 };
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Ok(data) = frame.into_data() {
            if buf.len() + data.len() > limit {
                return Ok(Collected::TooLarge); // dropping res returns the reservation
            }
            if !res.reserve(data.len(), budget) {
                return Ok(Collected::Overloaded); // dropping res returns the reservation
            }
            buf.extend_from_slice(&data);
        }
    }
    Ok(Collected::Body(buf.freeze(), res))
}

/// Pick a backend for the site, round-robin when there are several.
// ── Passive circuit breaker for backends ──────────────────────────────────────
// Health per backend URL: consecutive failures plus the time the circuit stays open.
// The hot path is lock-free: the map is read via ArcSwap and fields are atomics. State
// survives a policy update, since the map is rebuilt carrying the same Arcs across.
const BREAKER_FAILS: u32 = 5;     // consecutive transport errors before the circuit opens
const BREAKER_COOLDOWN: u64 = 10; // seconds the backend is excluded from rotation

struct BackendHealth {
    fails: AtomicU32,
    open_until: AtomicU64, // unix seconds; a value greater than now means open, i.e. excluded from rotation
}
impl BackendHealth {
    fn new() -> Self { Self { fails: AtomicU32::new(0), open_until: AtomicU64::new(0) } }
    fn is_open(&self, now: u64) -> bool { self.open_until.load(Ordering::Relaxed) > now }
    fn record_ok(&self) {
        // success (any HTTP response) means the backend is alive, so reset
        self.fails.store(0, Ordering::Relaxed);
        self.open_until.store(0, Ordering::Relaxed);
    }
    /// A transport error or timeout. true means the circuit transitioned closed to open right now, for the metric.
    fn record_fail(&self, now: u64) -> bool {
        let n = self.fails.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= BREAKER_FAILS {
            self.open_until.swap(now + BREAKER_COOLDOWN, Ordering::Relaxed) <= now
        } else {
            false
        }
    }
}

struct Breaker {
    map: ArcSwap<std::collections::HashMap<String, Arc<BackendHealth>>>,
}
impl Breaker {
    fn new() -> Self { Self { map: ArcSwap::from_pointee(std::collections::HashMap::new()) } }
    fn health(&self, backend: &str) -> Arc<BackendHealth> {
        if let Some(h) = self.map.load().get(backend) {
            return h.clone();
        }
        // a miss (new backend) triggers a copy-on-write insert, which is rare; existing Arcs are carried over
        let cur = self.map.load();
        let mut m = (**cur).clone();
        let h = m.entry(backend.to_string()).or_insert_with(|| Arc::new(BackendHealth::new())).clone();
        self.map.store(Arc::new(m));
        h
    }
}

// ── Backend anti-SSRF (node side) ──────────────────────────────────────────
// Closes the gap left by the control-side check: a hostname resolving to a private or metadata IP.
// We ALWAYS block link-local (169.254/16, the cloud metadata range, and fe80::/10) plus
// unspecified and broadcast, since no legitimate origin points there. Private RFC1918 and
// loopback are blocked ONLY under THREATAIL_BLOCK_PRIVATE_BACKENDS=1, which would otherwise break
// a co-located origin and a dashboard on 127.0.0.1. Resolution is cached with a TTL and read lock-free.
struct ResolveGuard {
    cache: ArcSwap<std::collections::HashMap<String, (Vec<std::net::IpAddr>, i64)>>,
    block_private: bool,
    ttl: i64,
}
impl ResolveGuard {
    fn new() -> Self {
        let block_private = std::env::var("THREATAIL_BLOCK_PRIVATE_BACKENDS").ok().as_deref() == Some("1");
        Self { cache: ArcSwap::from_pointee(std::collections::HashMap::new()), block_private, ttl: 30 }
    }
    /// allow_private=false also blocks private and loopback addresses; a per-site opt-out.
    /// The global THREATAIL_BLOCK_PRIVATE_BACKENDS=1 is a hard override for every site.
    /// Metadata, link-local, unspecified and broadcast are ALWAYS blocked, regardless of the flag.
    fn ip_blocked(&self, ip: std::net::IpAddr, allow_private: bool) -> bool {
        let block_priv = self.block_private || !allow_private;
        match ip {
            std::net::IpAddr::V4(a) => {
                if a.is_link_local() || a.is_unspecified() || a.is_broadcast() { return true; } // always
                if block_priv && (a.is_loopback() || a.is_private()) { return true; }
                false
            }
            std::net::IpAddr::V6(a) => {
                if let Some(v4) = a.to_ipv4_mapped() { return self.ip_blocked(std::net::IpAddr::V4(v4), allow_private); }
                let s0 = a.segments()[0];
                if (s0 & 0xffc0) == 0xfe80 || a.is_unspecified() { return true; } // link-local fe80::/10
                if block_priv && (a.is_loopback() || (s0 & 0xfe00) == 0xfc00) { return true; }
                false
            }
        }
    }
    /// true means the backend host is acceptable. A literal IP is checked synchronously; a name is resolved via the TTL cache.
    /// allow_private is the per-site 'Allow private backend' flag, true by default.
    async fn allowed(&self, host: &str, port: u16, allow_private: bool) -> bool {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return !self.ip_blocked(ip, allow_private);
        }
        let now = now_unix();
        if let Some((ips, exp)) = self.cache.load().get(host) {
            if *exp > now { return !ips.iter().any(|ip| self.ip_blocked(*ip, allow_private)); }
        }
        let ips: Vec<std::net::IpAddr> = match tokio::net::lookup_host((host, port)).await {
            Ok(it) => it.map(|sa| sa.ip()).collect(),
            Err(_) => return false, // does not resolve, so we reject it (fail closed)
        };
        if ips.is_empty() { return false; }
        let ok = !ips.iter().any(|ip| self.ip_blocked(*ip, allow_private));
        let cur = self.cache.load();
        let mut m = (**cur).clone();
        if m.len() > 4096 { m.retain(|_, (_, e)| *e > now); }
        m.insert(host.to_string(), (ips, now + self.ttl));
        self.cache.store(Arc::new(m));
        ok
    }
}

fn pick_backend<'a>(site: &'a Site, shared: &Shared) -> Option<&'a str> {
    let n = site.backends.len();
    if n == 0 {
        return None;
    }
    let start = shared.rr.fetch_add(1, Ordering::Relaxed);
    let now = now_unix() as u64;
    // round-robin, skipping backends whose circuit is open (unhealthy)
    for k in 0..n {
        let b = site.backends[(start + k) % n].as_str();
        if !shared.breaker.health(b).is_open(now) {
            return Some(b);
        }
    }
    // all circuits are open, so we fail open and try the next in rotation, which doubles as the half-open probe:
    // an attempt beats a guaranteed failure for everyone.
    Some(site.backends[start % n].as_str())
}

/// Proxy to the backend, setting the X-Forwarded-* headers.
async fn proxy(
    mut parts: hyper::http::request::Parts,
    body_bytes: Bytes,
    site: &Site,
    shared: &Shared,
    client_ip: &str,
    is_tls: bool,
) -> Result<Response<BoxedBody>, Box<dyn std::error::Error + Send + Sync>> {
    let backend = pick_backend(site, shared).ok_or("no backend for site")?;

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let upstream_uri: hyper::Uri = format!("{}{}", backend, path_and_query).parse()?;

    parts.headers.insert(
        "x-real-ip",
        hyper::header::HeaderValue::from_str(client_ip)?,
    );
    set_forwarded_for(&mut parts.headers, client_ip)?;
    // the real scheme (https when the client arrived over TLS); otherwise the application assumes
    // the connection is insecure, which breaks redirects and absolute links.
    parts.headers.insert(
        "x-forwarded-proto",
        hyper::header::HeaderValue::from_static(if is_tls { "https" } else { "http" }),
    );
    parts.uri = upstream_uri;
    // The node terminates HTTP/2 from the client, but the backend connector speaks HTTP/1.1 only.
    // Without resetting the request version (HTTP/2 arrives from a CDN or browser) the hyper client
    // conflicts with the HTTP/1 connection. We therefore force HTTP/1.1 toward the backend.
    parts.version = hyper::Version::HTTP_11;

    // Rewrite Host to the backend host when the backend is given as a DOMAIN rather than an IP. Otherwise
    // a remote vhost on a different domain will not recognise the original Host and will return
    // 404. For IP origins we keep the original Host, which vhost routing often depends on.
    // For an HTTPS backend hyper takes SNI from the URI authority, which already holds the backend host.
    if let Some(auth) = parts.uri.authority().cloned() {
        let is_ip = auth.host().parse::<std::net::IpAddr>().is_ok();
        if !is_ip {
            if let Ok(hv) = hyper::header::HeaderValue::from_str(auth.as_str()) {
                parts.headers.insert(hyper::header::HOST, hv);
            }
        }
    }

    // Anti-SSRF: the backend host must never resolve to link-local or metadata addresses, and under
    // THREATAIL_BLOCK_PRIVATE_BACKENDS=1 not to private or loopback ones either. This closes the bypass of the
    // control-side check via a hostname. Resolution is cached, so DNS is not queried per request.
    {
        let host = parts.uri.host().unwrap_or("").to_string();
        let port = parts.uri.port_u16()
            .unwrap_or(if parts.uri.scheme_str() == Some("https") { 443 } else { 80 });
        if !host.is_empty() && !shared.ssrf.allowed(&host, port, site.allow_private_backend).await {
            tracing::warn!("SSRF-BLOCK backend host {} for site {}", host, site.domain);
            return Err("backend address blocked".into());
        }
    }

    // Whatever we need from the client headers is taken before parts are moved out.
    let client_ae = parts.headers.get(hyper::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    let is_ws = site.websocket
        && parts.headers.get(hyper::header::UPGRADE).and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket")).unwrap_or(false);

    // ── WebSocket: the handshake already passed the WAF (rules, geo, limits). The body is empty, so tunnel. ──
    if is_ws {
        let client_upgrade = parts.extensions.remove::<hyper::upgrade::OnUpgrade>();
        let upstream_req = Request::from_parts(parts, Full::new(Bytes::new()));
        let backend_resp_r = if site.insecure_backend {
            shared.client_insecure.request(upstream_req).await
        } else {
            shared.client.request(upstream_req).await
        };
        let mut backend_resp = match backend_resp_r {
            Ok(r) => { shared.breaker.health(backend).record_ok(); r }
            Err(e) => {
                shared.metrics.record_upstream_error();
                if shared.breaker.health(backend).record_fail(now_unix() as u64) { shared.metrics.record_breaker_open(); }
                return Err(e.into());
            }
        };
        if backend_resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            if let Some(client_up) = client_upgrade {
                let backend_up = hyper::upgrade::on(&mut backend_resp);
                tokio::spawn(async move {
                    if let (Ok(c), Ok(b)) = (client_up.await, backend_up.await) {
                        let _ = tokio::io::copy_bidirectional(
                            &mut TokioIo::new(c), &mut TokioIo::new(b)).await;
                    }
                });
            }
        }
        let (rp, rb) = backend_resp.into_parts();
        return Ok(Response::from_parts(rp, rb.boxed()));
    }

    // Non-WebSocket forwarding: strip hop-by-hop and framing headers (Connection, Transfer-Encoding,
    // Content-Length and so on) so the client cannot smuggle a request and so hop-by-hop headers
    // do not leak to the backend. Done AFTER the WebSocket branch, which needs Upgrade and Connection.
    strip_hop_by_hop(&mut parts.headers);

    // Retain the request parts so we can retry on a keep-alive race (IncompleteMessage).
    // We retry ONLY idempotent methods: when a reused connection drops, the backend
    // never processed the request, so retrying is safe.
    let idempotent = matches!(parts.method, hyper::Method::GET | hyper::Method::HEAD | hyper::Method::OPTIONS);
    let r_method = parts.method.clone();
    let r_uri = parts.uri.clone();
    let r_version = parts.version;
    let r_headers = parts.headers.clone();
    let make_req = |b: Bytes| {
        let mut rb = Request::builder().method(r_method.clone()).uri(r_uri.clone()).version(r_version);
        if let Some(h) = rb.headers_mut() { *h = r_headers.clone(); }
        rb.body(Full::new(b))
    };
    let upstream_req = Request::from_parts(parts, Full::new(body_bytes.clone()));
    let up_t0 = std::time::Instant::now();
    // Backend response timeout (per site, 0 means the 30 s default). Exceeding it produces a "timeout" error,
    // which the caller renders as 504.
    let dur = std::time::Duration::from_secs(if site.upstream_timeout > 0 { site.upstream_timeout as u64 } else { 30 });
    let fut1 = if site.insecure_backend { shared.client_insecure.request(upstream_req) } else { shared.client.request(upstream_req) };
    let mut resp = match tokio::time::timeout(dur, fut1).await {
        Ok(r) => r,
        Err(_) => { shared.metrics.record_upstream_error(); if shared.breaker.health(backend).record_fail(now_unix() as u64) { shared.metrics.record_breaker_open(); } return Err("upstream timeout".into()); }
    };
    if idempotent && matches!(&resp, Err(e) if format!("{:?}", e).contains("IncompleteMessage")) {
        tracing::debug!("upstream retry after IncompleteMessage for {}", site.domain);
        if let Ok(req2) = make_req(body_bytes.clone()) {
            let fut2 = if site.insecure_backend { shared.client_insecure.request(req2) } else { shared.client.request(req2) };
            resp = match tokio::time::timeout(dur, fut2).await {
                Ok(r) => r,
                Err(_) => { shared.metrics.record_upstream_error(); if shared.breaker.health(backend).record_fail(now_unix() as u64) { shared.metrics.record_breaker_open(); } return Err("upstream timeout".into()); }
            };
        }
    }
    let resp = match resp {
        Ok(r) => r,
        Err(e) => { shared.metrics.record_upstream_error(); if shared.breaker.health(backend).record_fail(now_unix() as u64) { shared.metrics.record_breaker_open(); } return Err(e.into()); }
    };
    shared.breaker.health(backend).record_ok(); // we got a response, so the backend is alive
    shared.metrics.record_upstream_latency(up_t0.elapsed().as_millis() as u32);

    let (mut rparts, body) = resp.into_parts();
    // hop-by-hop headers from the backend response must not leak to the client; with sec_headers we also
    // hide the Server and X-Powered-By banners, reducing fingerprinting.
    strip_resp_hop_by_hop(&mut rparts.headers, site.sec_headers);
    if site.sec_headers { apply_security_headers(&mut rparts.headers, is_tls); }

    // ── gzip response compression, when enabled, supported by the client, of a compressible type and within the size window ──
    // With DLP enabled we skip internal compression, because body inspection happens in the handler
    // over the UNCOMPRESSED body; otherwise there would be nothing to scan.
    if site.compression
        && !site.dlp_enabled
        && client_ae.contains("gzip")
        && rparts.headers.get(hyper::header::CONTENT_ENCODING).is_none()
        && is_compressible(&rparts.headers)
    {
        let clen = rparts.headers.get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<usize>().ok());
        // compress only at a known, reasonable size; streams and enormous bodies are not buffered
        if matches!(clen, Some(n) if (256..=4 * 1024 * 1024).contains(&n)) {
            let bytes = match body.collect().await { Ok(c) => c.to_bytes(), Err(e) => return Err(e.into()) };
            let out = match gzip_bytes(&bytes) {
                Ok(gz) => {
                    rparts.headers.remove(hyper::header::CONTENT_LENGTH);
                    rparts.headers.insert(hyper::header::CONTENT_LENGTH, hyper::header::HeaderValue::from(gz.len()));
                    rparts.headers.insert(hyper::header::CONTENT_ENCODING, hyper::header::HeaderValue::from_static("gzip"));
                    rparts.headers.insert(hyper::header::VARY, hyper::header::HeaderValue::from_static("accept-encoding"));
                    Bytes::from(gz)
                }
                Err(_) => bytes,
            };
            return Ok(Response::from_parts(rparts, Full::new(out).map_err(|never| match never {}).boxed()));
        }
    }

    Ok(Response::from_parts(rparts, body.boxed()))
}

/// Whether the response type is worth compressing (text and structured formats).
fn is_compressible(h: &hyper::HeaderMap) -> bool {
    match h.get(hyper::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
        Some(ct) => {
            let ct = ct.to_ascii_lowercase();
            ct.starts_with("text/") || ct.contains("json") || ct.contains("javascript")
                || ct.contains("xml") || ct.contains("svg") || ct.contains("css") || ct.contains("html")
        }
        None => false,
    }
}

/// gzip a buffer at the fast level.
fn gzip_bytes(data: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    let mut e = GzEncoder::new(Vec::new(), Compression::fast());
    e.write_all(data)?;
    e.finish()
}

/// Whether THIS request is cacheable (a GET without authorisation). Returns the encoding for the key.
fn cacheable_request(parts: &hyper::http::request::Parts, site: &Site) -> Option<&'static str> {
    if !site.cache || parts.method != hyper::Method::GET { return None; }
    if parts.headers.contains_key(hyper::header::AUTHORIZATION) { return None; }
    let gz = site.compression
        && parts.headers.get(hyper::header::ACCEPT_ENCODING).and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("gzip")).unwrap_or(false);
    Some(if gz { "gz" } else { "id" })
}

fn cache_key_of(host: &str, parts: &hyper::http::request::Parts, enc: &str) -> String {
    let pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    format!("{}|GET|{}|{}", host, pq, enc)
}

fn parse_maxage(cc: &str, key: &str) -> Option<u64> {
    let i = cc.find(key)?;
    let rest = cc[i + key.len()..].trim_start_matches([' ', '=']);
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

/// Cache TTL derived from the response headers; None means it must not be cached. site.cache_ttl is the ceiling.
fn cache_ttl_of(headers: &hyper::HeaderMap, status: u16, site: &Site) -> Option<std::time::Duration> {
    if status != 200 || headers.contains_key(hyper::header::SET_COOKIE) { return None; }
    let cc = headers.get(hyper::header::CACHE_CONTROL).and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    if cc.contains("no-store") || cc.contains("no-cache") || cc.contains("private") { return None; }
    let mut ttl = parse_maxage(&cc, "s-maxage").or_else(|| parse_maxage(&cc, "max-age"))?;
    if ttl == 0 { return None; }
    if site.cache_ttl > 0 { ttl = ttl.min(site.cache_ttl as u64); }
    Some(std::time::Duration::from_secs(ttl))
}

/// Headers safe to cache and replay, excluding hop-by-hop ones and Set-Cookie.
fn cache_headers(h: &hyper::HeaderMap) -> Vec<(String, String)> {
    const KEEP: &[&str] = &["content-type", "content-encoding", "content-language",
                            "cache-control", "etag", "last-modified", "expires", "vary"];
    h.iter().filter_map(|(k, v)| {
        let name = k.as_str();
        if KEEP.contains(&name) { v.to_str().ok().map(|s| (name.to_string(), s.to_string())) } else { None }
    }).collect()
}

fn build_from_cache(hit: cache::Hit) -> Response<BoxedBody> {
    let mut b = Response::builder().status(hit.status);
    for (k, v) in &hit.headers { b = b.header(k.as_str(), v.as_str()); }
    b = b.header("age", hit.age.to_string()).header("x-cache", "HIT")
         .header(hyper::header::CONTENT_LENGTH, hit.body.len().to_string());
    b.body(Full::new(hit.body).map_err(|never| match never {}).boxed())
        .unwrap_or_else(|_| text_response(StatusCode::BAD_GATEWAY, "cache error"))
}

/// X-Forwarded-For: we set the REAL client IP, the effective_ip already resolved with
/// trusted proxies in mind. We do NOT append to the value the client sent, otherwise a client-spoofed
/// XFF would reach the backend, and many applications take the leftmost address from the chain.
/// Global ceiling for body buffering in RAM. To avoid proliferating environment variables it is
/// determined AUTOMATICALLY: about 25% of the node's total memory (from /proc/meminfo), but never below 64 MB.
/// The optional THREATAIL_BODY_BUDGET_MB environment variable overrides it when set.
fn detect_body_budget() -> usize {
    if let Some(mb) = std::env::var("THREATAIL_BODY_BUDGET_MB").ok()
        .and_then(|s| s.parse::<usize>().ok()).filter(|&n| n > 0)
    {
        return mb.saturating_mul(1024 * 1024);
    }
    let total_kb = std::fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
        s.lines()
            .find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<usize>().ok())
    });
    match total_kb {
        Some(kb) => (kb / 4).saturating_mul(1024).max(64 * 1024 * 1024), // 25% of RAM, at least 64 MB
        None => 256 * 1024 * 1024, // /proc is unavailable, so use a sensible fallback
    }
}

fn set_forwarded_for(
    headers: &mut hyper::HeaderMap,
    client_ip: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    headers.insert(
        "x-forwarded-for",
        hyper::header::HeaderValue::from_str(client_ip)?,
    );
    Ok(())
}

/// Strip hop-by-hop and framing headers before forwarding to the backend (anti-smuggling).
/// The body is sent as Full, so hyper sets a correct Content-Length itself.
/// Headers listed in Connection are hop-by-hop too, so we remove them by name.
fn strip_hop_by_hop(h: &mut hyper::HeaderMap) {
    let conn_tokens: Vec<String> = h.get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|c| c.split(',').map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty()).collect())
        .unwrap_or_default();
    for name in ["connection","keep-alive","proxy-connection","transfer-encoding",
                 "te","trailer","upgrade","proxy-authorization","proxy-authenticate","content-length"] {
        h.remove(name);
    }
    for t in conn_tokens {
        if let Ok(hn) = hyper::header::HeaderName::from_bytes(t.as_bytes()) {
            h.remove(hn);
        }
    }
}

/// Send an event to the control plane when connected. Generates the uid.
/// Write to the ClickHouse access log (ALL requests, when ClickHouse is enabled).
#[allow(clippy::too_many_arguments)]
fn access_log(
    shared: &Shared,
    site: &Site,
    ip: &str,
    method: &str,
    uri: &str,
    location: &str,
    country: &str,
    status: u16,
    action: &str,
    sig: &str,
    severity: u8,
    ua: &str,
    latency_ms: u32,
    det: &ReqDetail,
    incident_id: &str,
    bytes_out: u64,
) {
    // metrics: pass and upstream are already counted on the proxy path; here we count blocks, challenges and detections
    match action {
        "pass" | "upstream_error" => {}
        "review" => {} // quarantine: the request was passed, so the block metrics are left alone
        "challenge" => { shared.metrics.record(status); shared.metrics.inc_challenged(); }
        "detected" => { shared.metrics.record(status); shared.metrics.inc_detected(); }
        _ => { shared.metrics.record(status); shared.metrics.inc_blocked(); shared.metrics.record_block_source(sig); }
    }
    shared.metrics.add_bytes(det.req_len, bytes_out);
    // per-site metrics (host label) for filtering by site in Grafana.
    // up_lat: for a pass the total latency is roughly the backend's, since WAF overhead is small; otherwise 0.
    let up_for_host = if action == "pass" { latency_ms } else { 0 };
    shared.metrics.record_host(&site.domain, action, latency_ms, up_for_host);

    // Auto-ban: we count terminal blocks of ATTACKS, excluding geo policy, the deny list, mTLS and IP reputation,
    // which are already filtered statically. Once the threshold is reached within the window we send an autoban event (with until in
    // attack_type); the cloud records the ban and distributes it via the feed to every node of the site.
    if site.autoban_enabled
        && matches!(action, "blocked" | "anomaly")
        && !matches!(sig, "ip_blacklist" | "ip_reputation" | "mtls" | "banned" | "autoban")
    {
        if let Some(until) = shared.ipban.strike(
            &site.domain, ip, site.autoban_threshold,
            site.autoban_window as u64, site.autoban_duration as u64,
        ) {
            tracing::info!("AUTOBAN {} {} until={} (after {} blocks)", site.domain, ip, until, site.autoban_threshold);
            try_emit(&shared.events, cloud::CloudEvent {
                host: site.domain.clone(), client_ip: ip.to_string(), method: method.to_string(),
                uri: uri.to_string(), action: "autoban".to_string(), severity: 4,
                sig: "autoban".to_string(), country: country.to_string(), ua: ua.to_string(),
                incident_id: incident_id.to_string(), attack_type: until.to_string(), body: String::new(),
                ja3: String::new(), ja4: String::new(),
            });
        }
    }
    if latency_ms > 0 { shared.metrics.record_latency(latency_ms); }
    // aggregate for the cloud, per host and per minute
    if let Some(acc) = &shared.metric_acc {
        acc.record(&site.domain, action, latency_ms as f64, up_for_host as f64);
    }
    // The targeted 'log every request' mode: pass and upstream_error normally do NOT reach
    // the cloud, only metrics do. It is enabled selectively, either on the node (a cloud flag set by a superadmin)
    // OR on the site (config.log_all_requests). Then an event is sent for every
    // request, including legitimate traffic and the request body, for debugging and auditing.
    let log_all_on = shared.log_all.load(std::sync::atomic::Ordering::Relaxed) || site.log_all_requests;
    if log_all_on && matches!(action, "pass" | "upstream_error") {
        try_emit(&shared.events, cloud::CloudEvent {
            host: site.domain.clone(),
            client_ip: ip.to_string(),
            method: method.to_string(),
            uri: uri.to_string(),
            action: action.to_string(),
            severity: severity as i32,
            sig: "access".to_string(),
            country: country.to_string(),
            ua: ua.to_string(),
            incident_id: incident_id.to_string(),
            attack_type: String::new(),
            body: det.body.clone(), // include the request body; the snapshot is already truncated
            ja3: String::new(),
            ja4: String::new(),
        });
    }
    // V2: we do not write a full access log to ClickHouse. Details of notable requests
    // (quarantined or blocked) go to the cloud via events and the review and samples channels.
    let _ = (ip, &det.query, &det.headers, &det.body, incident_id, location, country,
             method, uri, ua, sig, severity);
}

/// Request details for the log, prepared once.
struct ReqDetail {
    query: String,
    headers: String,
    body: String,
    req_len: u64, // full request body size, untruncated
    ml_proba: f32, // ML attack probability, filled in during inference
    http_version: &'static str, // protocol version (HTTP/1.1, HTTP/2, ...)
}

/// Headers as a compact JSON string.
fn headers_to_json(h: &hyper::HeaderMap) -> String {
    let mut map = serde_json::Map::new();
    for (k, v) in h.iter() {
        let val = v.to_str().unwrap_or("").to_string();
        map.insert(k.as_str().to_string(), serde_json::Value::String(val));
    }
    serde_json::Value::Object(map).to_string()
}

/// Push an event into the bounded channel. On overflow (a slow or unreachable cloud) the
/// event is DROPPED rather than blocking the hot path or growing memory: telemetry must not
/// affect traffic serving. Drops are counted and logged periodically.
fn try_emit(events: &Option<cloud::EventTx>, ev: cloud::CloudEvent) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static DROPPED: AtomicU64 = AtomicU64::new(0);
    if let Some(tx) = events {
        match tx.try_send(ev) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                let n = DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_power_of_two() || n.is_multiple_of(1000) {
                    tracing::warn!("event channel full — dropped {} events total", n);
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

// One incident record. Every argument is a distinct field of the event as the
// cloud stores it; bundling them would only relocate the list.
#[allow(clippy::too_many_arguments)]
fn emit_raw(
    shared: &Shared,
    site: &Site,
    ip: &str,
    method: &str,
    uri: &str,
    action: &str,
    sev: i32,
    sig: &str,
    country: &str,
    location: &str,
    ua: &str,
    incident_id: &str,
    attack_type: &str,
    body: &str,
    ja3: &str,
    ja4: &str,
) {
    try_emit(&shared.events, cloud::CloudEvent {
        host: site.domain.clone(),
        client_ip: ip.to_string(),
        method: method.to_string(),
        uri: uri.to_string(),
        action: action.to_string(),
        severity: sev,
        sig: sig.to_string(),
        country: country.to_string(),
        ua: ua.to_string(),
        incident_id: incident_id.to_string(),
        attack_type: attack_type.to_string(),
        body: body.to_string(),
        ja3: ja3.to_string(),
        ja4: ja4.to_string(),
    });
    let _ = location; // in V2 the event carries no location; the cloud enriches it from geo data
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}


/// Generate an incident UID that is short and easy to copy: INC-<time36>-<seq36>.
fn gen_incident_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    format!("INC-{}-{}", to_base36(t), to_base36(n & 0xffffff))
}

fn to_base36(mut v: u64) -> String {
    const D: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if v == 0 {
        return "0".to_string();
    }
    let mut s = Vec::new();
    while v > 0 {
        s.push(D[(v % 36) as usize]);
        v /= 36;
    }
    s.reverse();
    String::from_utf8(s).unwrap_or_default()
}

/// The block response: the site's custom page (with {incident_id} substituted)
/// or the default one. The X-THWAF-Incident header carries the UID.
/// Parse an application/x-www-form-urlencoded body into a map.
fn parse_form(body: &str) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    for pair in body.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        m.insert(urldecode(k), urldecode(v));
    }
    m
}

fn urldecode(s: &str) -> String {
    let s = s.replace('+', " ");
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// The challenge response: a proof-of-work page returned with 503, so bots do not read it as 200.
/// For non-browsers (no text/html in Accept, i.e. mobile apps and API clients) the JavaScript PoW
/// cannot run, so instead of broken HTML we return the site's block status configured in the dashboard.
fn challenge_response(site: &Site, secret: &str, ip: &str, lang: &str, wants_html: bool) -> Response<BoxedBody> {
    if !wants_html {
        let code = StatusCode::from_u16(site.block_status).unwrap_or(StatusCode::FORBIDDEN);
        let body = Full::new(Bytes::new()).map_err(|never| match never {}).boxed();
        return Response::builder()
            .status(code)
            .header("cache-control", "no-store")
            .body(body)
            .unwrap_or_else(|_| error_response(StatusCode::FORBIDDEN, "", lang));
    }
    let diff = if site.challenge_difficulty == 0 { 18 } else { site.challenge_difficulty };
    let prefix = challenge::pow_prefix(secret, ip);
    let page = challenge::challenge_page(&prefix, diff, lang);
    let body = Full::new(Bytes::from(page)).map_err(|never| match never {}).boxed();
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(body)
        .unwrap()
}

/// Add safe security headers to the response, only when the backend has not set them already.
/// HSTS is added ONLY over HTTPS; over plain HTTP it is harmful.
fn apply_security_headers(h: &mut hyper::HeaderMap, is_tls: bool) {
    use hyper::header::{HeaderName, HeaderValue};
    let mut add = |name: &'static str, val: &'static str| {
        let hn = HeaderName::from_static(name);
        if !h.contains_key(&hn) {
            h.insert(hn, HeaderValue::from_static(val));
        }
    };
    add("x-content-type-options", "nosniff");
    add("x-frame-options", "SAMEORIGIN");
    add("referrer-policy", "strict-origin-when-cross-origin");
    if is_tls {
        add("strict-transport-security", "max-age=31536000; includeSubDomains");
    }
}

/// Strip hop-by-hop headers from the backend RESPONSE before serving the client. Content-Length is kept
/// and hyper picks correct framing. drop_fp=true removes the Server and X-Powered-By banners.
fn strip_resp_hop_by_hop(h: &mut hyper::HeaderMap, drop_fp: bool) {
    let conn_tokens: Vec<String> = h.get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|c| c.split(',').map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty()).collect())
        .unwrap_or_default();
    for name in ["connection","keep-alive","proxy-connection","transfer-encoding","te","trailer","upgrade"] {
        h.remove(name);
    }
    for t in conn_tokens {
        if let Ok(hn) = hyper::header::HeaderName::from_bytes(t.as_bytes()) { h.remove(hn); }
    }
    if drop_fp {
        h.remove("server");
        h.remove("x-powered-by");
    }
}

/// Decompress a compressed REQUEST body (Content-Encoding gzip, deflate or br) for inspection.
/// `cap` is a hard limit on the decompressed size, guarding against a decompression bomb: output is truncated
/// and CPU and memory stay O(cap). Returns None when decompression fails, in which case we inspect as is.
fn inflate_for_inspection(body: &[u8], encoding: &str, cap: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let limit = cap as u64;
    let mut out = Vec::new();
    if encoding.contains("gzip") {
        let d = flate2::read::GzDecoder::new(body);
        d.take(limit).read_to_end(&mut out).ok()?;
    } else if encoding.contains("deflate") {
        // HTTP 'deflate' comes both zlib-wrapped and raw. We try zlib first, then raw.
        let z = flate2::read::ZlibDecoder::new(body);
        if z.take(limit).read_to_end(&mut out).is_ok() && !out.is_empty() {
            return Some(out);
        }
        out.clear();
        let r = flate2::read::DeflateDecoder::new(body);
        r.take(limit).read_to_end(&mut out).ok()?;
    } else if encoding.contains("br") {
        // brotli: the universal signature bypass via a single br wrapper is closed. The decoder is pure
        // Rust, so it builds against static musl. The same anti-bomb limit applies via take(cap).
        let d = brotli::Decompressor::new(body, 4096);
        d.take(limit).read_to_end(&mut out).ok()?;
    } else {
        return None;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn block_response(site: &Site, status: u16, incident_id: &str, lang: &str) -> Response<BoxedBody> {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
    let reason = i18n::block_reason(status, lang);
    let (body, ctype) = if !site.block_body.is_empty() {
        // custom page: substitute the placeholders
        let b = site.block_body
            .replace("{incident_id}", incident_id)
            .replace("{status}", &status.to_string())
            .replace("{reason}", reason);
        let ct = if site.block_content_type.is_empty() {
            "text/html; charset=utf-8".to_string()
        } else {
            site.block_content_type.clone()
        };
        (b, ct)
    } else {
        (default_block_page(status, lang, incident_id), "text/html; charset=utf-8".to_string())
    };
    let body = Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed();
    let mut builder = Response::builder()
        .status(code)
        .header("content-type", ctype)
        .header("X-THWAF-Incident", incident_id);
    // Rate limit (429): tell the client when to retry. The token bucket refills at roughly
    // rps per second, so one second is a correct lower bound.
    if status == 429 {
        builder = builder.header("retry-after", "1");
    }
    builder.body(body).unwrap()
}

/// A light HTML page for infrastructure errors (502, 404 and so on), styled like the block page.
/// No incident code, since this is a processing or availability error rather than a block by the protection system.
fn error_page(status: u16, lang: &str, _msg: &str) -> String {
    let reason = i18n::block_reason(status, lang);
    let desc = i18n::error_desc(status, lang);
    format!(
        "<!doctype html><html lang=\"{lang}\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{status} — {reason}</title>\
<style>\
*{{box-sizing:border-box}}\
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;\
background:#f6f8fa;color:#1c1e21;margin:0;min-height:100vh;display:flex;flex-direction:column}}\
.wrap{{flex:1;display:flex;align-items:center;justify-content:center;padding:24px}}\
.card{{background:#fff;border:1px solid #e3e6ea;border-radius:14px;box-shadow:0 4px 24px rgba(0,0,0,.06);\
max-width:560px;width:100%;padding:48px 40px;text-align:center}}\
.code{{font-size:64px;font-weight:800;line-height:1;color:#6b7280;letter-spacing:-2px;margin:0}}\
.reason{{font-size:22px;font-weight:600;margin:12px 0 0}}\
.desc{{color:#5b6470;line-height:1.6;margin:16px 0 8px;font-size:15px}}\
.foot{{padding:16px;text-align:center;color:#9aa0aa;font-size:12px}}\
</style></head>\
<body><div class=\"wrap\"><div class=\"card\">\
<p class=\"code\">{status}</p>\
<div class=\"reason\">{reason}</div>\
<p class=\"desc\">{desc}</p>\
</div></div>\
<div class=\"foot\">Threatail WAF</div>\
</body></html>",
        lang = lang, status = status, reason = reason, desc = desc
    )
}

/// A light, Cloudflare-style block page localised to the visitor's language.
fn default_block_page(status: u16, lang: &str, incident_id: &str) -> String {
    let reason = i18n::block_reason(status, lang);
    let desc = i18n::block_desc(lang);
    let inc_label = i18n::incident_label(lang);
    format!(
        "<!doctype html><html lang=\"{lang}\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{status} — {reason}</title>\
<style>\
*{{box-sizing:border-box}}\
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;\
background:#f6f8fa;color:#1c1e21;margin:0;min-height:100vh;display:flex;flex-direction:column}}\
.wrap{{flex:1;display:flex;align-items:center;justify-content:center;padding:24px}}\
.card{{background:#fff;border:1px solid #e3e6ea;border-radius:14px;box-shadow:0 4px 24px rgba(0,0,0,.06);\
max-width:560px;width:100%;padding:48px 40px;text-align:center}}\
.code{{font-size:64px;font-weight:800;line-height:1;color:#d6332f;letter-spacing:-2px;margin:0}}\
.reason{{font-size:22px;font-weight:600;margin:12px 0 0}}\
.desc{{color:#5b6470;line-height:1.6;margin:16px 0 28px;font-size:15px}}\
.inc{{background:#f6f8fa;border:1px solid #e3e6ea;border-radius:10px;padding:16px 18px;text-align:left}}\
.inc .lbl{{font-size:12px;color:#8a929c;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}}\
.inc code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:16px;color:#1c1e21;\
user-select:all;word-break:break-all}}\
.foot{{padding:16px;text-align:center;color:#9aa0aa;font-size:12px}}\
</style></head>\
<body><div class=\"wrap\"><div class=\"card\">\
<p class=\"code\">{status}</p>\
<div class=\"reason\">{reason}</div>\
<p class=\"desc\">{desc}</p>\
<div class=\"inc\"><div class=\"lbl\">{inc_label}</div><code>{inc}</code></div>\
</div></div>\
</body></html>",
        lang = lang, status = status, reason = reason, desc = desc, inc_label = inc_label, inc = incident_id
    )
}

/// Download the geo database (.mmdb or .mmdb.gz) and write it atomically to path.
async fn update_geoip(client: &reqwest::Client, url: &str, path: &str) -> Result<(), String> {
    let resp = client.get(url).send().await.map_err(|e| format!("request: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let bytes = resp.bytes().await.map_err(|e| format!("read: {}", e))?;
    write_geoip(&bytes, path)
}

/// Decompress when the magic bytes indicate gzip, check the size and write the mmdb atomically to path.
fn write_geoip(bytes: &[u8], path: &str) -> Result<(), String> {
    let is_gz = bytes.len() > 2 && bytes[0] == 0x1f && bytes[1] == 0x8b;
    let data: Vec<u8> = if is_gz {
        use std::io::Read;
        let d = flate2::read::GzDecoder::new(bytes);
        let mut out = Vec::new();
        // a 64 MB decompression limit guards against a gzip bomb if the URL is compromised
        d.take(64 * 1024 * 1024).read_to_end(&mut out).map_err(|e| format!("gunzip: {}", e))?;
        out
    } else {
        bytes.to_vec()
    };
    if data.len() < 100_000 {
        return Err(format!("file too small ({} bytes), skipping", data.len()));
    }
    let tmp = format!("{}.tmp", path);
    std::fs::write(&tmp, &data).map_err(|e| format!("write: {}", e))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename: {}", e))?;
    Ok(())
}

/// A plain text response; the ACME challenge requires plain text rather than HTML.
fn text_response(status: StatusCode, body: &str) -> Response<BoxedBody> {
    let b = Full::new(Bytes::from(body.to_string()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .header("cache-control", "no-store")
        .body(b)
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).map_err(|never| match never {}).boxed()))
}

/// 405 Method Not Allowed with an Allow header listing the permitted methods.
fn method_not_allowed(allow: &str, lang: &str) -> Response<BoxedBody> {
    let html = error_page(405, lang, "method not allowed");
    let body = Full::new(Bytes::from(html)).map_err(|never| match never {}).boxed();
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .header("allow", allow)
        .body(body)
        .unwrap_or_else(|_| error_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed", lang))
}

fn error_response(status: StatusCode, msg: &str, lang: &str) -> Response<BoxedBody> {
    // A proper HTML page instead of bare text, as nginx and Cloudflare do.
    // For infrastructure errors (502, 404, 400, 413, 414) there is no incident code.
    let code = status.as_u16();
    let html = error_page(code, lang, msg);
    let body = Full::new(Bytes::from(html))
        .map_err(|never| match never {})
        .boxed();
    match Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(body)
    {
        Ok(r) => r,
        Err(_) => {
            // last-resort fallback if the builder fails: an empty response carrying the status
            Response::builder().status(status)
                .body(Full::new(Bytes::new()).map_err(|never| match never {}).boxed())
                .unwrap_or_default()
        }
    }
}

#[cfg(test)]
mod review_pattern_tests {
    use super::{template_path, template_query, review_pattern, seg_is_id};

    #[test]
    fn path_ids_collapse() {
        assert_eq!(template_path("/api/orders/12"), "/api/orders/{id}");
        assert_eq!(template_path("/api/orders/99"), "/api/orders/{id}");
        assert_eq!(template_path("/v2/users/42/posts/7"), "/v2/users/{id}/posts/{id}");
        assert_eq!(template_path("/p/item-12345"), "/p/{id}");
        assert_eq!(template_path("/files/a1b2c3d4e5f6"), "/files/{id}");
        assert_eq!(
            template_path("/u/550e8400-e29b-41d4-a716-446655440000"),
            "/u/{id}"
        );
    }

    #[test]
    fn path_static_kept() {
        assert_eq!(template_path("/search"), "/search");
        assert_eq!(template_path("/blog/hello-world"), "/blog/hello-world");
        assert_eq!(template_path("/blog/top10things"), "/blog/top10things"); // a run shorter than 3
        assert_eq!(template_path("/static/app.css"), "/static/app.css");
        // The root path templates to "/" rather than "": the pattern is one field
        // among five, so an empty component is never what distinguishes a group,
        // and "/" stays distinguishable from "no path at all".
        assert_eq!(template_path("/"), "/");
    }

    #[test]
    fn seg_heuristics() {
        assert!(seg_is_id("12345"));
        assert!(seg_is_id("winter2024sale")); // a run of 4 digits
        assert!(!seg_is_id("top10things"));    // a run of 2
        assert!(!seg_is_id("hello-world"));
        assert!(!seg_is_id("app.css"));
    }

    #[test]
    fn query_order_and_values_ignored() {
        assert_eq!(template_query("a=1&b=2"), "a&b");
        assert_eq!(template_query("b=2&a=1"), "a&b");
        assert_eq!(template_query("a=1&b=2&utm_source=x&a=9"), "a&b&utm_source");
        assert_eq!(template_query("q=<script>alert(1)</script>"), "q");
        assert_eq!(template_query(""), "");
    }

    #[test]
    fn pattern_collapses_id_variants_and_separates_buckets() {
        let p1 = review_pattern("ex.com", "GET", "/api/orders/12", "token=aaa", "g");
        let p2 = review_pattern("ex.com", "GET", "/api/orders/99", "token=bbb", "g");
        assert_eq!(p1, p2, "ID- и value-варианты одного эндпоинта должны схлопываться");
        // the bucket separates a confirmed attack from the grey zone
        let attack = review_pattern("ex.com", "GET", "/api/orders/12", "token=aaa", "a");
        assert_ne!(p1, attack);
    }
}
