// Stage 5: integration with the Go control plane.
// A V3 node pulls policy (long-poll GET /api/nodes/<id>/policy?ver=N) and sends
// events (POST /api/ingest). Authorisation is Bearer <node_token> plus the
// X-Node-Hostname and X-Node-Version headers. Policy arrives as {version, assets:[Asset]}
// in the Go format and is mapped onto our Site type.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

use crate::config::Site;
use crate::ratelimit::RateRule;

/// Control-plane connection settings, taken from the config file.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct CentralCfg {
    #[serde(default)]
    pub url: String, // e.g. http://10.90.90.4:8766
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub node_token: String,
}

impl CentralCfg {
    pub fn enabled(&self) -> bool {
        !self.url.is_empty() && !self.node_id.is_empty() && !self.node_token.is_empty()
    }
}

// ---- The Go Asset format, as served by the control plane ----
fn default_true() -> bool { true }

#[derive(Debug, Deserialize)]
pub struct GoAsset {
    domain: String,
    #[serde(default)]
    node_id: String,
    #[serde(default)]
    backends: Vec<String>,
    #[serde(default)]
    origin_url: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    geo_mode: String,
    #[serde(default)]
    geo_countries: Vec<String>,
    #[serde(default)]
    geo_status: u16,
    #[serde(default)]
    trusted_proxies: Vec<String>,
    #[serde(default)]
    trusted_ips: Vec<String>,
    #[serde(default)]
    custom_rules: Vec<GoRule>,
    #[serde(default)]
    exceptions: Vec<GoRule>,
    #[serde(default)]
    rate_rules: Vec<GoRateRule>,
    #[serde(default)]
    anomaly_block: bool,
    #[serde(default)]
    anomaly_sens: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    tls_mode: String,
    #[serde(default)]
    tls_cert: String,
    #[serde(default)]
    tls_key: String,
    #[serde(default)]
    force_https: bool,
    #[serde(default)]
    insecure_backend: bool,
    #[serde(default)]
    retention_days: u16,
    #[serde(default)]
    ml_trusted_ips: Vec<String>,
    #[serde(default)]
    log_full: bool,
    #[serde(default)]
    block_body: String,
    #[serde(default)]
    block_content_type: String,
    #[serde(default)]
    ip_whitelist: Vec<String>,
    #[serde(default)]
    ip_blacklist: Vec<String>,
    #[serde(default)]
    bot_mode: String,
    #[serde(default)]
    score_enabled: bool,
    #[serde(default)]
    iprep: bool,
    #[serde(default)]
    score_threshold: u32,
    #[serde(default)]
    score_w_bot: u32,
    #[serde(default)]
    score_w_anomaly: u32,
    #[serde(default)]
    score_w_rule: u32,
    #[serde(default)]
    score_w_geo: u32,
    #[serde(default)]
    score_grey_countries: Vec<String>,
    #[serde(default)]
    score_challenge: u32,
    #[serde(default)]
    challenge_difficulty: u32,
    #[serde(default)]
    challenge_secret: String,
    #[serde(default)]
    max_body_kb: usize,
    #[serde(default)]
    max_uri_kb: usize,
    #[serde(default = "default_true")]
    ml_enabled: bool,
    #[serde(default)]
    ml_threshold: f64,
    #[serde(default)]
    ml_weight: u32,
    #[serde(default)]
    ml_review_low: f64,
    #[serde(default)]
    mtls_locations: Vec<String>,
    #[serde(default)]
    mtls_ca: String,
    #[serde(default)]
    mtls_revoked: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GoRule {
    #[serde(default)]
    field: String,
    #[serde(default)]
    operator: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    status: u16,
    #[serde(default)]
    sig: String,
    /// Composite condition tree. When present it replaces the flat condition.
    #[serde(default)]
    when: Option<crate::verdict::Cond>,
    /// Exceptions only: suppress a single signal instead of allowing the whole request.
    #[serde(default)]
    suppress: Option<String>,
}

/// Build a verdict::Rule from a GoRule (flat or composite condition).
fn go_rule_to_rule(r: &GoRule) -> crate::verdict::Rule {
    let mut rule = if r.when.is_some() {
        crate::verdict::Rule {
            field: crate::verdict::Field::Uri,
            operator: crate::verdict::Operator::Contains,
            value: String::new(),
            header_name: String::new(),
            when: r.when.clone(),
            action: crate::verdict::parse_action(&r.action),
            status: r.status,
            sig: r.sig.clone(),
            enabled: true,
            suppress: None,
            no_log: false,
        }
    } else {
        crate::verdict::rule_from_raw(&r.field, &r.operator, &r.value, &r.action, r.status, &r.sig)
    };
    rule.suppress = r.suppress.clone().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    rule
}

#[derive(Debug, Deserialize)]
struct GoRateRule {
    #[serde(default)]
    location: String,
    #[serde(default)]
    operator: String,
    #[serde(default)]
    rps: u32,
    #[serde(default)]
    burst: u32,
    #[serde(default)]
    status: u16,
    #[serde(default)]
    when: Option<crate::verdict::Cond>,
}

#[derive(Debug, Deserialize)]
struct PolicyResp {
    version: u64,
    assets: Vec<GoAsset>,
}

/// Convert a Go Asset into our Site. Returns None when the asset has no backend,
/// since V3 is a reverse proxy and has nowhere to forward to.
pub fn go_asset_to_site(a: GoAsset) -> Option<Site> {
    if !a.enabled {
        return None;
    }
    let mut backends = a.backends.clone();
    if backends.is_empty() && !a.origin_url.is_empty() {
        backends.push(a.origin_url.clone());
    }
    if backends.is_empty() {
        return None; // nothing to proxy to
    }
    let custom_rules = a
        .custom_rules
        .iter()
        .map(go_rule_to_rule)
        .collect();
    let exceptions = a
        .exceptions
        .iter()
        .map(go_rule_to_rule)
        .collect();
    let rate_rules = a
        .rate_rules
        .iter()
        .map(|r| RateRule {
            location: r.location.clone(),
            operator: if r.operator.is_empty() { "prefix".into() } else { r.operator.clone() },
            rps: r.rps,
            burst: r.burst,
            status: r.status,
            when: r.when.clone(),
            key: String::new(),      // V1 format: default limit key (ip)
            action: String::new(),   // V1 format: default action (block/429)
        })
        .collect();

    // TLS certificates are now applied in memory (cert_store); nothing is written to disk
    Some(Site {
        api_sec: Default::default(),
        openapi: Default::default(),
        domain: a.domain,
        backends,
        force_https: a.force_https,
        insecure_backend: a.insecure_backend,
        allow_private_backend: true,
        retention_days: if a.retention_days == 0 { 30 } else { a.retention_days },
        ml_trusted_ips: a.ml_trusted_ips.clone(),
        log_full: a.log_full,
        block_body: a.block_body.clone(),
        block_content_type: a.block_content_type.clone(),
        ip_whitelist: a.ip_whitelist.clone(),
        ip_blacklist: a.ip_blacklist.clone(),
        bot_mode: if a.bot_mode.is_empty() { "off".into() } else { a.bot_mode.clone() },
        verbot_enabled: false,
        verbot_spoof_action: "detect".into(),
        ato_enabled: false,
        ato_login_paths: Vec::new(),
        ato_action: "detect".into(),
        ato_window: 300,
        ato_ip_attempts: 0,
        ato_ip_users: 0,
        ato_user_ips: 0,
        ato_user_fields: Vec::new(),
        dlp_enabled: false,
        dlp_action: "detect".into(),
        dlp_secrets: true,
        dlp_pii: false,
        dlp_errors: true,
        dlp_patterns: Vec::new(),
        dlp_max_scan: 0,
        managed_rules_enabled: false,
        collective_defense_enabled: false,
        collective_defense_action: "detect".into(),
        adaptive_rl_enabled: false,
        adaptive_rl_threshold: 0,
        adaptive_rl_factor: 50,
        adaptive_rl_window: 10,
        adaptive_rl_challenge: false,
        bot_tls_check: false,
        bot_behavior: false,
        bot_behavior_sens: "medium".to_string(),
        siginj_enabled: false,
        fpfeed_enabled: false,
        log_all_requests: false,
        autoban_enabled: false,
        autoban_threshold: 10,
        autoban_window: 60,
        autoban_duration: 3600,
        ja3_blacklist: Vec::new(),
        ja4_blacklist: Vec::new(),
        cdn_ja3_header: String::new(),
        cdn_ja4_header: String::new(),
        score_enabled: a.score_enabled,
        iprep_enabled: a.iprep,
        score_threshold: a.score_threshold,
        score_w_bot: if a.score_w_bot == 0 { 30 } else { a.score_w_bot },
        score_w_anomaly: if a.score_w_anomaly == 0 { 40 } else { a.score_w_anomaly },
        score_w_rule: if a.score_w_rule == 0 { 30 } else { a.score_w_rule },
        score_w_geo: if a.score_w_geo == 0 { 20 } else { a.score_w_geo },
        score_w_ml: 4,
        score_grey_countries: a.score_grey_countries.clone(),
        score_challenge: a.score_challenge,
        challenge_difficulty: if a.challenge_difficulty == 0 { 18 } else { a.challenge_difficulty },
        challenge_secret: a.challenge_secret.clone(),
        max_body_kb: a.max_body_kb,
        upload_max_kb: 0,
        upload_paths: Vec::new(),
        upload_block: false,
        upstream_timeout: 0,
        body_read_timeout: 0,
        allowed_methods: Vec::new(),
        sec_headers: false,
        traversal_logonly: false,
        method_logonly: false,
        ipv6_logonly: false,
        max_uri_kb: a.max_uri_kb,
        ml_enabled: a.ml_enabled,
        ml_threshold: a.ml_threshold,
        ml_weight: a.ml_weight,
        ml_review_low: a.ml_review_low,
        ml_min_severity: 0,
        ml_severity_block: false,
        ml_reset_epoch: 0,
        // Standalone-only: in cloud mode the CA arrives inline as `a.mtls_ca`
        // and is consumed directly when the per-SNI config is built, so there
        // is no file to point at.
        mtls_ca_file: String::new(),
        mtls_locations: a.mtls_locations,
        mtls_revoked_set: a.mtls_revoked.iter()
            .map(|s| s.trim_start_matches('0').to_ascii_lowercase())
            .collect(),
        mtls_revoked: a.mtls_revoked,
        mode: if a.mode.is_empty() { "detect".into() } else { a.mode },
        custom_rules,
        exceptions,
        rate_rules,
        trusted_proxies: if !a.trusted_proxies.is_empty() { a.trusted_proxies.clone() } else { a.trusted_ips.clone() },
        geo_mode: if a.geo_mode.is_empty() { "off".into() } else { a.geo_mode.clone() },
        geo_countries: a.geo_countries.clone(),
        geo_status: a.geo_status,
        geo_log: false,
        http2: true,
        ipv6_enabled: true,
        block_status: 403,
        ratelimit_status: 429,
        body_limit: if a.max_body_kb > 0 { a.max_body_kb * 1024 } else { 65536 },
        body_tail_kb: 32,
        body_oversized: 1, // default: the uninspected gap in large bodies is visible in the threat score
        anomaly_block: a.anomaly_block,
        anomaly_sens: if a.anomaly_sens.is_empty() { "medium".into() } else { a.anomaly_sens },
        websocket: true,
        compression: true,
        cache: false,
        cache_ttl: 0,
    })
}

/// An event to send to the control plane (the Go Event format).
#[derive(Debug, Serialize, Clone)]
pub struct Event {
    pub uid: String,
    pub ts: i64,
    pub host: String,
    pub ip: String,
    pub method: String,
    pub uri: String,
    pub action: String,
    pub sev: i32,
    pub sig: String,
    #[serde(default)]
    pub ua: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub country: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub location: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub node: String,
}

/// Event channel: handlers push here and the sender batches to the control plane.
pub type EventTx = tokio::sync::mpsc::UnboundedSender<Event>;

/// Start the background tasks: policy polling and event delivery.
/// `router` is the live ArcSwap handle to the router that we update.
pub fn spawn(
    cfg: CentralCfg,
    router: Arc<ArcSwap<crate::config::Router>>,
    cert_store: crate::tls::CertStore,
    config_store: crate::tls::ConfigStore,
    http2: bool,
) -> EventTx {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Event>();

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(35))
        .build()
        .expect("reqwest client");

    // policy polling
    {
        let cfg = cfg.clone();
        let http = http.clone();
        let router = router.clone();
        let cert_store = cert_store.clone();
        let config_store = config_store.clone();
        tokio::spawn(async move {
            poll_policy(cfg, http, router, cert_store, config_store, http2).await;
        });
    }
    // event delivery
    {
        let cfg = cfg.clone();
        let http = http.clone();
        tokio::spawn(async move {
            send_events(cfg, http, rx).await;
        });
    }

    tx
}

async fn poll_policy(
    cfg: CentralCfg,
    http: reqwest::Client,
    router: Arc<ArcSwap<crate::config::Router>>,
    cert_store: crate::tls::CertStore,
    config_store: crate::tls::ConfigStore,
    http2: bool,
) {
    let mut ver: u64 = 0;
    let hostname = hostname();
    loop {
        let url = format!("{}/api/nodes/{}/policy?ver={}", cfg.url, cfg.node_id, ver);
        let res = http
            .get(&url)
            .bearer_auth(&cfg.node_token)
            .header("X-Node-Hostname", &hostname)
            .header("X-Node-Version", "v3-0.1")
            .send()
            .await;
        match res {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<PolicyResp>().await {
                    Ok(p) => {
                        if p.version != ver {
                            // filter the assets belonging to this node
                            let assets: Vec<GoAsset> = p
                                .assets
                                .into_iter()
                                .filter(|a| a.node_id.is_empty() || a.node_id == cfg.node_id)
                                .collect();
                            // live TLS swap: collect certificates from policy into memory
                            let mut certs: std::collections::HashMap<String, std::sync::Arc<rustls::sign::CertifiedKey>> = std::collections::HashMap::new();
                            for a in &assets {
                                if a.tls_mode == "manual" && !a.tls_cert.is_empty() && !a.tls_key.is_empty() {
                                    match crate::tls::certified_key_from_pem(&a.tls_cert, &a.tls_key) {
                                        Ok(ck) => { certs.insert(a.domain.to_ascii_lowercase(), ck); }
                                        Err(e) => tracing::warn!("TLS {}: cannot parse cert: {:?}", a.domain, e),
                                    }
                                }
                            }
                            let cert_n = certs.len();
                            // per-SNI configs for mTLS domains (full client certificate
                            // validation against the domain CA during the handshake).
                            let mut mtls_cfgs: std::collections::HashMap<String, std::sync::Arc<rustls::ServerConfig>> = std::collections::HashMap::new();
                            for a in &assets {
                                let has_mtls = !a.mtls_locations.is_empty() && !a.mtls_ca.is_empty();
                                if has_mtls {
                                    let dom = a.domain.to_ascii_lowercase();
                                    if let Some(ck) = certs.get(&dom) {
                                        match crate::tls::mtls_server_config(ck.clone(), &a.mtls_ca, http2) {
                                            Ok(c) => { mtls_cfgs.insert(dom, c); }
                                            Err(e) => tracing::warn!("mTLS {}: cannot build config: {:?}", a.domain, e),
                                        }
                                    } else {
                                        tracing::warn!("mTLS {}: no TLS cert for domain — mTLS not activated", a.domain);
                                    }
                                }
                            }
                            let mtls_n = mtls_cfgs.len();
                            config_store.store(std::sync::Arc::new(mtls_cfgs));
                            cert_store.store(std::sync::Arc::new(certs));
                            if mtls_n > 0 { tracing::info!("mTLS active for {} domain(s)", mtls_n); }
                            // assemble the sites
                            let sites: Vec<Site> = assets.into_iter().filter_map(go_asset_to_site).collect();
                            let n = sites.len();
                            router.store(Arc::new(crate::config::Router::from_sites(sites)));
                            ver = p.version;
                            tracing::info!("policy updated from central: version={} sites={} certs={}", ver, n, cert_n);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("central: policy parse error: {:?}", e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
            Ok(resp) => {
                tracing::warn!("central: policy status {}", resp.status());
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => {
                tracing::debug!("central unavailable: {:?}", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn send_events(
    cfg: CentralCfg,
    http: reqwest::Client,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Event>,
) {
    let hostname = hostname();
    let url = format!("{}/api/ingest", cfg.url);
    let mut batch: Vec<Event> = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(mut ev) => {
                        ev.node = cfg.node_id.clone();
                        batch.push(ev);
                        if batch.len() >= 100 {
                            flush(&http, &url, &cfg, &hostname, &mut batch).await;
                        }
                    }
                    None => break,
                }
            }
            _ = tick.tick() => {
                if !batch.is_empty() {
                    flush(&http, &url, &cfg, &hostname, &mut batch).await;
                }
            }
        }
    }
}

async fn flush(
    http: &reqwest::Client,
    url: &str,
    cfg: &CentralCfg,
    hostname: &str,
    batch: &mut Vec<Event>,
) {
    let res = http
        .post(url)
        .bearer_auth(&cfg.node_token)
        .header("X-Node-Hostname", hostname)
        .header("X-Node-Version", "v3-0.1")
        .json(&batch)
        .send()
        .await;
    match res {
        Ok(r) if r.status().as_u16() == 204 => batch.clear(),
        Ok(r) => tracing::warn!("central ingest status {}", r.status()),
        Err(e) => tracing::debug!("central ingest error: {:?}", e),
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "threatail".to_string())
}

/// Build a Site from V2 cloud policy. The config format is what the dashboard stores:
///   { backend, blocked_paths:[regex], rate_limit:{enabled,rps},
///     geo:{mode,countries}, mtls_enabled, ml_trusted_ips,
///     optional: mode, force_https, ip_whitelist, ip_blacklist }
/// This is NOT a V1 GoAsset; it maps directly onto Site.
// Field-by-field on purpose: Site has dozens of fields, so a struct literal here
// would still need ..Default::default() while being much harder to review when a
// field is added.
#[allow(clippy::field_reassign_with_default)]
pub fn site_from_policy(domain: String, config: serde_json::Value) -> Option<crate::config::Site> {
    use crate::verdict::{Rule, Field, Operator, Action};

    let backend = config.get("backend").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if backend.is_empty() {
        tracing::warn!("site {}: no backend set — skipped", domain);
        return None;
    }

    let mut site = crate::config::Site::default();
    site.domain = domain;
    site.backends = vec![backend];
    // mode: protect by default (block rules only really block in protect)
    site.mode = config.get("mode").and_then(|v| v.as_str()).unwrap_or("protect").to_string();
    site.force_https = config.get("force_https").and_then(|v| v.as_bool()).unwrap_or(true);
    site.insecure_backend = config.get("insecure_backend").and_then(|v| v.as_bool()).unwrap_or(false);
    // per-site 'Allow private backend': absent or true means allowed, for compatibility
    site.allow_private_backend = config.get("allow_private_backend").and_then(|v| v.as_bool()).unwrap_or(true);
    site.websocket = config.get("websocket").and_then(|v| v.as_bool()).unwrap_or(true);
    site.compression = config.get("compression").and_then(|v| v.as_bool()).unwrap_or(true);
    site.cache = config.get("cache").and_then(|v| v.as_bool()).unwrap_or(false);
    site.cache_ttl = config.get("cache_ttl").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    site.iprep_enabled = config.get("iprep").and_then(|v| v.as_bool()).unwrap_or(false);
    site.retention_days = config.get("retention_days").and_then(|v| v.as_u64()).unwrap_or(30) as u16;
    let valid_code = |v: Option<&serde_json::Value>, def: u16| -> u16 {
        v.and_then(|x| x.as_u64()).map(|n| n as u16).filter(|n| *n >= 100 && *n < 600).unwrap_or(def)
    };
    site.geo_status = valid_code(config.get("geo_code"), 403);
    site.http2 = config.get("http2").and_then(|v| v.as_bool()).unwrap_or(true);
    site.ipv6_enabled = config.get("ipv6").and_then(|v| v.as_bool()).unwrap_or(true);
    site.block_status = valid_code(config.get("block_code"), 403);
    site.ratelimit_status = valid_code(config.get("ratelimit_code"), 429);
    site.body_limit = config.get("body_limit").and_then(|v| v.as_u64()).unwrap_or(1_048_576) as usize;
    site.body_tail_kb = config.get("body_tail_kb").and_then(|v| v.as_u64()).unwrap_or(32) as usize;
    // Defaults to 1 (score) when policy omits the field, so the gap inside large bodies stays visible.
    // An explicit 0 from policy is honoured. Note: for cloud nodes the dashboard also sets a default,
    // so if it always sends body_oversized, change the default there too.
    site.body_oversized = config.get("body_oversized").and_then(|v| v.as_u64()).unwrap_or(1).min(2) as u8;
    site.max_body_kb = config.get("max_body_kb").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    site.upload_max_kb = config.get("upload_max_kb").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    site.upload_paths = json_str_array(config.get("upload_paths"));
    site.upload_block = config.get("upload_block").and_then(|v| v.as_bool()).unwrap_or(false);
    site.upstream_timeout = config.get("upstream_timeout").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    site.body_read_timeout = config.get("body_read_timeout").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    site.allowed_methods = config.get("allowed_methods").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.trim().to_uppercase()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    site.sec_headers = config.get("sec_headers").and_then(|v| v.as_bool()).unwrap_or(false);
    site.traversal_logonly = config.get("traversal_logonly").and_then(|v| v.as_bool()).unwrap_or(false);
    site.method_logonly = config.get("method_logonly").and_then(|v| v.as_bool()).unwrap_or(false);
    site.ipv6_logonly = config.get("ipv6_logonly").and_then(|v| v.as_bool()).unwrap_or(false);

    // blocked_paths becomes block rules matching the path by regex (a quick shortcut)
    if let Some(arr) = config.get("blocked_paths").and_then(|v| v.as_array()) {
        for p in arr {
            if let Some(rx) = p.as_str() {
                let rx = rx.trim();
                if rx.is_empty() { continue; }
                site.custom_rules.push(Rule {
                    field: Field::Path,
                    operator: Operator::Regex,
                    value: rx.to_string(),
                    header_name: String::new(),
                    when: None,
                    action: Action::Block,
                    status: 403,
                    sig: "blocked-path".into(),
                    enabled: true,
                    suppress: None,
                    no_log: false,
                });
            }
        }
    }

    // full rules and exceptions from the dashboard rule builder:
    //   [{ field, operator, value, action, status }]
    for r in rules_from_json(config.get("custom_rules")) { site.custom_rules.push(r); }
    for r in rules_from_json(config.get("exceptions"))   { site.exceptions.push(r); }

    // bot mode: off|detect|block|challenge
    site.bot_mode = config.get("bot_mode").and_then(|v| v.as_str()).unwrap_or("off").to_string();
    site.verbot_enabled = config.get("verbot_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    site.verbot_spoof_action = config.get("verbot_spoof_action").and_then(|v| v.as_str()).unwrap_or("detect").to_string();
    site.ato_enabled = config.get("ato_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    site.ato_login_paths = config.get("ato_login_paths").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    site.ato_action = config.get("ato_action").and_then(|v| v.as_str()).unwrap_or("detect").to_string();
    site.ato_window = config.get("ato_window").and_then(|v| v.as_u64()).filter(|&n| n > 0).unwrap_or(300);
    site.ato_ip_attempts = config.get("ato_ip_attempts").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    site.ato_ip_users = config.get("ato_ip_users").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    site.ato_user_ips = config.get("ato_user_ips").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    site.ato_user_fields = config.get("ato_user_fields").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    site.dlp_enabled = config.get("dlp_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    site.dlp_action = config.get("dlp_action").and_then(|v| v.as_str()).unwrap_or("detect").to_string();
    site.dlp_secrets = config.get("dlp_secrets").and_then(|v| v.as_bool()).unwrap_or(true);
    site.dlp_pii = config.get("dlp_pii").and_then(|v| v.as_bool()).unwrap_or(false);
    site.dlp_errors = config.get("dlp_errors").and_then(|v| v.as_bool()).unwrap_or(true);
    site.dlp_patterns = config.get("dlp_patterns").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    site.dlp_max_scan = config.get("dlp_max_scan").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    site.managed_rules_enabled = config.get("managed_rules_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    site.collective_defense_enabled = config.get("collective_defense_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    site.collective_defense_action = config.get("collective_defense_action").and_then(|v| v.as_str()).unwrap_or("detect").to_string();
    site.adaptive_rl_enabled = config.get("adaptive_rl_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    site.adaptive_rl_threshold = config.get("adaptive_rl_threshold").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    site.adaptive_rl_factor = config.get("adaptive_rl_factor").and_then(|v| v.as_u64()).unwrap_or(50) as u32;
    site.adaptive_rl_window = config.get("adaptive_rl_window").and_then(|v| v.as_u64()).filter(|&n| n > 0).unwrap_or(10);
    site.adaptive_rl_challenge = config.get("adaptive_rl_challenge").and_then(|v| v.as_bool()).unwrap_or(false);
    site.bot_tls_check = config.get("bot_tls_check").and_then(|v| v.as_bool()).unwrap_or(false);
    site.bot_behavior = config.get("bot_behavior").and_then(|v| v.as_bool()).unwrap_or(false);
    site.bot_behavior_sens = config.get("bot_behavior_sens").and_then(|v| v.as_str()).unwrap_or("medium").to_string();
    site.siginj_enabled = config.get("siginj_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    site.fpfeed_enabled = config.get("fpfeed_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    site.log_all_requests = config.get("log_all_requests").and_then(|v| v.as_bool()).unwrap_or(false);
    site.api_sec = crate::apisec::ApiSecCfg::from_config(&config);
    site.openapi = crate::openapi::OpenApiGate::from_config(&config);
    site.autoban_enabled = config.get("autoban_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    site.autoban_threshold = config.get("autoban_threshold").and_then(|v| v.as_u64()).unwrap_or(10) as u32;
    site.autoban_window = config.get("autoban_window").and_then(|v| v.as_u64()).unwrap_or(60) as u32;
    site.autoban_duration = config.get("autoban_duration").and_then(|v| v.as_u64()).unwrap_or(3600) as u32;
    site.ja3_blacklist = json_str_array(config.get("ja3_blacklist"));
    site.ja4_blacklist = json_str_array(config.get("ja4_blacklist"));
    site.cdn_ja3_header = config.get("cdn_ja3_header").and_then(|v| v.as_str()).unwrap_or("").trim().to_ascii_lowercase();
    site.cdn_ja4_header = config.get("cdn_ja4_header").and_then(|v| v.as_str()).unwrap_or("").trim().to_ascii_lowercase();

    // rate_limit:{enabled,rps} becomes a single prefix rule on "/"
    if let Some(rl) = config.get("rate_limit") {
        if rl.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
            let rps = rl.get("rps").and_then(|v| v.as_u64()).unwrap_or(50) as u32;
            // burst is set in the UI as extra capacity above rps. When unset it equals rps
            // (bucket capacity = rps + burst = 2x rps), which tolerates browser bursts
            // without being too lax. burst=0 gives a hard limit of exactly rps.
            let burst = rl.get("burst").and_then(|v| v.as_u64()).map(|b| b as u32).unwrap_or(rps);
            site.rate_rules.push(RateRule {
                location: "/".into(),
                operator: "prefix".into(),
                rps,
                burst,
                status: 429,
                when: None,
                key: String::new(),
                action: String::new(),
            });
        }
    }

    // rate_rules:[{location,operator,rps,burst,status}] are per-path, per-IP limits.
    // They come AFTER the generic rule: pick_rule takes the longest match (equals > longer prefix),
    // so a specific path such as /api/v2/auth overrides the generic "/".
    if let Some(arr) = config.get("rate_rules").and_then(|v| v.as_array()) {
        for r in arr {
            let location = r.get("location").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let rps = r.get("rps").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            if location.is_empty() || rps == 0 { continue; }
            let operator = r.get("operator").and_then(|v| v.as_str()).unwrap_or("prefix").to_string();
            let burst = r.get("burst").and_then(|v| v.as_u64()).map(|b| b as u32)
                .unwrap_or_else(|| rps.saturating_mul(2).max(rps + 10));
            let status = r.get("status").and_then(|v| v.as_u64()).unwrap_or(429) as u16;
            let key = r.get("key").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let action = r.get("action").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            site.rate_rules.push(RateRule { location, operator, rps, burst, status, when: None, key, action });
        }
    }

    // geo:{mode,countries,log}; the allow|deny|off modes map onto GeoMode
    if let Some(g) = config.get("geo") {
        let mode = g.get("mode").and_then(|v| v.as_str()).unwrap_or("off");
        if mode == "allow" || mode == "deny" {
            site.geo_mode = mode.to_string();
            site.geo_countries = json_str_array(g.get("countries"));
        }
        // log geo blocks as events (off by default, counter only)
        site.geo_log = g.get("log").and_then(|v| v.as_bool()).unwrap_or(false);
    }

    site.ml_trusted_ips = json_str_array(config.get("ml_trusted_ips"));
    // CRITICAL: the ML toggle from the dashboard. Without this ml_enabled stayed at its default (false), so
    // supervised ML, anomaly review and signature-driven quarantine seeding did not work in production.
    site.ml_enabled = config.get("ml_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    // anomaly profile reset epoch, bumped by 'reset training' in the dashboard
    site.ml_reset_epoch = config.get("ml_reset_epoch").and_then(|v| v.as_i64()).unwrap_or(0);
    // Quarantine threshold: the ML probability at which a request enters the labelling queue. 0 = default
    // (the node applies 0.4). Without parsing this, the threshold could not be raised from the dashboard.
    site.ml_review_low = config.get("ml_review_low").and_then(|v| v.as_f64()).unwrap_or(0.0);
    // Minimum ML severity at which ML takes effect (scoring/detection): low|medium|high|critical
    // (or a number 1..4). Below that it only quarantines. 0 = default (low).
    site.ml_min_severity = config
        .get("ml_min_severity")
        .map(|v| {
            if let Some(n) = v.as_u64() {
                n as u8
            } else if let Some(s) = v.as_str() {
                match s.to_ascii_lowercase().as_str() {
                    "medium" => 2,
                    "high" => 3,
                    "critical" => 4,
                    _ => 1,
                }
            } else {
                0
            }
        })
        .unwrap_or(0);
    site.ml_severity_block = config.get("ml_severity_block").and_then(|v| v.as_bool()).unwrap_or(false);
    site.ip_whitelist   = json_str_array(config.get("ip_whitelist"));
    site.ip_blacklist   = json_str_array(config.get("ip_blacklist"));
    site.trusted_proxies = json_str_array(config.get("trusted_proxies"));
    site.block_body         = config.get("block_body").and_then(|v| v.as_str()).unwrap_or("").to_string();
    site.block_content_type = config.get("block_content_type").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // threat score (composite scoring): threshold plus per-source weights
    if let Some(sc) = config.get("score") {
        site.score_enabled   = sc.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
        site.score_threshold = sc.get("threshold").and_then(|v| v.as_u64()).unwrap_or(5) as u32;
        site.score_w_bot     = sc.get("w_bot").and_then(|v| v.as_u64()).unwrap_or(2) as u32;
        site.score_w_anomaly = sc.get("w_anomaly").and_then(|v| v.as_u64()).unwrap_or(2) as u32;
        site.score_w_rule    = sc.get("w_rule").and_then(|v| v.as_u64()).unwrap_or(3) as u32;
        site.score_w_geo     = sc.get("w_geo").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
        site.score_w_ml      = sc.get("w_ml").and_then(|v| v.as_u64()).unwrap_or(4) as u32;
        site.score_challenge = sc.get("challenge").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        // CRITICAL: the grey-country list for the score signal. Without it the 'grey country' signal
        // never fired in production, because the list was always empty.
        site.score_grey_countries = json_str_array(sc.get("grey_countries"));
    }

    // mTLS: when enabled in the dashboard we require a client certificate. Paths come from the dashboard
    // (per-path mTLS, e.g. /api/v1/mob), otherwise the whole domain ("/"). The CA and per-SNI config are built in main.
    if config.get("mtls_enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
        let locs = json_str_array(config.get("mtls_locations"));
        site.mtls_locations = if locs.is_empty() {
            vec!["/".to_string()]
        } else {
            locs
        };
    }

    Some(site)
}

/// Helper: a JSON array of strings -> Vec<String>, dropping empties.
fn json_str_array(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(|x| x.as_array())
        .map(|a| a.iter()
            .filter_map(|e| e.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect())
        .unwrap_or_default()
}

/// Helper: the dashboard's rule array [{field,operator,value,action,status,header_name?}]
/// -> Vec<verdict::Rule>. Uses the same string parsers as the engine.
fn rules_from_json(v: Option<&serde_json::Value>) -> Vec<crate::verdict::Rule> {
    let arr = match v.and_then(|x| x.as_array()) { Some(a) => a, None => return Vec::new() };
    let mut out = Vec::new();
    for r in arr {
        let value = r.get("value").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let field_str = r.get("field").and_then(|x| x.as_str()).unwrap_or("uri");
        // header_name: either explicit, or taken from a field like "header:User-Agent"
        let (field, hdr) = crate::verdict::parse_field(field_str);
        let header_name = r.get("header_name").and_then(|x| x.as_str())
            .map(|s| s.to_string()).filter(|s| !s.is_empty()).unwrap_or(hdr);
        let operator = crate::verdict::parse_operator(
            r.get("operator").and_then(|x| x.as_str()).unwrap_or("contains"));
        let action = crate::verdict::parse_action(
            r.get("action").and_then(|x| x.as_str()).unwrap_or("block"));
        let status = r.get("status").and_then(|x| x.as_u64()).unwrap_or(403) as u16;
        let suppress = r.get("suppress").and_then(|x| x.as_str())
            .map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        // per-rule enable toggle (defaults to true for backward compatibility)
        let enabled = r.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true);
        // composite condition tree (AND/OR/NOT) from the UI; when present it replaces the flat form
        let when = r.get("when")
            .filter(|w| !w.is_null())
            .and_then(|w| serde_json::from_value::<crate::verdict::Cond>(w.clone()).ok());
        // detect_sqli and detect_xss carry no value, so they must not be skipped
        let valueless = matches!(operator, crate::verdict::Operator::DetectSqli | crate::verdict::Operator::DetectXss);
        // an empty value is valid for value-less rules (method, detect_*) OR when a tree is present
        if when.is_none() && value.is_empty() && !matches!(field, crate::verdict::Field::Method) && !valueless { continue; }
        out.push(crate::verdict::Rule {
            field, operator, value, header_name, when, action, status,
            sig: "rule".into(),
            enabled,
            suppress,
            no_log: false,
        });
    }
    out
}

/// Parse centrally managed rules (virtual patching) from a JSON array.
/// Like rules_from_json, but sig comes from the rule's cve/name/sig for readable events,
/// defaulting to "managed_rule". Ordinary custom rules are unaffected.
pub(crate) fn managed_rules_from_json(v: &serde_json::Value) -> Vec<crate::verdict::Rule> {
    let arr = match v.as_array() { Some(a) => a, None => return Vec::new() };
    let mut out = Vec::new();
    for r in arr {
        // disabled rules are not loaded
        if !r.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true) { continue; }
        let value = r.get("value").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let field_str = r.get("field").and_then(|x| x.as_str()).unwrap_or("uri");
        let (field, hdr) = crate::verdict::parse_field(field_str);
        let header_name = r.get("header_name").and_then(|x| x.as_str())
            .map(|s| s.to_string()).filter(|s| !s.is_empty()).unwrap_or(hdr);
        let operator = crate::verdict::parse_operator(
            r.get("operator").and_then(|x| x.as_str()).unwrap_or("contains"));
        // managed rules only protect: block/detect. allow, challenge and skip from the feed are ignored.
        let action = match r.get("action").and_then(|x| x.as_str()).unwrap_or("block") {
            "detect" => crate::verdict::Action::Detect,
            _ => crate::verdict::Action::Block,
        };
        let status = r.get("status").and_then(|x| x.as_u64()).unwrap_or(403) as u16;
        let when = r.get("when").filter(|w| !w.is_null())
            .and_then(|w| serde_json::from_value::<crate::verdict::Cond>(w.clone()).ok());
        let valueless = matches!(operator, crate::verdict::Operator::DetectSqli | crate::verdict::Operator::DetectXss);
        if when.is_none() && value.is_empty() && !matches!(field, crate::verdict::Field::Method) && !valueless { continue; }
        // event label: cve, then name, then sig, then "managed_rule"
        let sig = r.get("cve").and_then(|x| x.as_str())
            .or_else(|| r.get("name").and_then(|x| x.as_str()))
            .or_else(|| r.get("sig").and_then(|x| x.as_str()))
            .map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
            .unwrap_or_else(|| "managed_rule".into());
        out.push(crate::verdict::Rule {
            field, operator, value, header_name, when,
            action,
            status,
            sig,
            enabled: true,
            suppress: None,
            no_log: false,
        });
    }
    out
}
