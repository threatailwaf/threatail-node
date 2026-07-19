// Threatail configuration. Read from a JSON file whose path is the first argument, or
// /etc/threatail/config.json. The structure mirrors the Go control plane's asset so that
// policy can be synchronised easily later.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

/// A TLS certificate loaded from disk. Used when the node runs standalone: in
/// cloud mode certificates arrive through policy instead.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct CertFile {
    /// Domains this certificate serves. SNI matching is exact and lower-cased.
    /// `*.example.com` is matched by the wildcard entry in the certificate itself,
    /// so list the names as they appear in the SAN.
    pub domains: Vec<String>,
    /// Path to the PEM certificate chain (leaf first, then intermediates).
    pub cert_file: String,
    /// Path to the PEM private key. Keep it readable only by the node's user.
    pub key_file: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct Config {
    /// HTTP listener address, e.g. "0.0.0.0:8080".
    #[serde(default = "default_http")]
    pub listen_http: String,
    /// HTTPS listener address, e.g. "0.0.0.0:8443". Empty disables HTTPS.
    #[serde(default)]
    pub listen_https: String,
    /// Metrics server address (/metrics, /stats). Empty disables it. Bind to an INTERNAL interface only.
    #[serde(default)]
    pub metrics_listen: String,
    /// Bearer token for metrics access. Empty means no auth, which is safe only on an internal port.
    #[serde(default)]
    pub metrics_token: String,
    /// HTTP/2 support (ALPN h2) on the HTTPS listener. Defaults to false (HTTP/1.1 only).
    #[serde(default)]
    pub http2_enabled: bool,
    /// Path to the supervised ML model (model.json). Empty disables ML detection.
    #[serde(default)]
    pub ml_model_path: String,
    /// Sites: domain -> settings.
    /// TLS certificates read from disk. Required for HTTPS when running without
    /// the cloud: with this empty and `listen_https` set, the node accepts
    /// connections but has no certificate to present and every handshake fails.
    #[serde(default)]
    pub certs: Vec<CertFile>,
    /// Malicious IP list, one address or CIDR per line. Applied to sites that set
    /// `iprep_enabled`.
    #[serde(default)]
    pub iprep_file: String,
    /// Managed rules as a JSON array, in the same shape the cloud distributes.
    /// Applied to sites that set `managed_rules_enabled`.
    #[serde(default)]
    pub managed_rules_file: String,
    /// Malicious TLS fingerprints, one JA3 or JA4 per line. Applied to sites that
    /// set `fpfeed_enabled`.
    #[serde(default)]
    pub fpfeed_file: String,
    pub sites: Vec<Site>,
    /// Path to GeoLite2-Country.mmdb. Empty disables geo globally.
    #[serde(default)]
    pub geoip_db: String,
    /// URL for geo database auto-updates (.mmdb or .mmdb.gz). Empty disables auto-updates.
    #[serde(default)]
    pub geoip_update_url: String,
    /// Geo database auto-update interval in hours (0 disables it; defaults to 24 when a URL is set).
    #[serde(default)]
    pub geoip_update_hours: u64,
    /// Path to the ML profile file. Empty defaults to /var/lib/threatail/model.json.
    #[serde(default)]
    pub model_path: String,
    /// Connection to the Go control plane. Empty means the node runs purely from the local config.
    #[serde(default)]
    pub central: crate::central::CentralCfg,
    /// Logging of all traffic to ClickHouse (option A: directly).
    #[serde(default)]
    pub clickhouse: crate::clickhouse::ClickhouseCfg,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct Site {
    pub domain: String,
    /// Backend addresses (http://ip:port). Several are load-balanced round-robin.
    pub backends: Vec<String>,
    /// Mode: learn|detect|protect (defaults to detect).
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Custom rules.
    #[serde(default)]
    pub custom_rules: Vec<crate::verdict::Rule>,
    /// Exceptions (action=pass override).
    #[serde(default)]
    pub exceptions: Vec<crate::verdict::Rule>,
    /// Per-location rate limits.
    #[serde(default)]
    pub rate_rules: Vec<crate::ratelimit::RateRule>,
    /// Trusted proxies (CIDR) for X-Forwarded-For. Empty means the peer address is used.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Geo mode: off|allow|deny.
    #[serde(default = "default_geo")]
    pub geo_mode: String,
    /// Countries (ISO codes) for the geo policy.
    #[serde(default)]
    pub geo_countries: Vec<String>,
    /// Response code for a geo block (0 = 403).
    #[serde(default)]
    pub geo_status: u16,
    /// Log geo blocks as events (an incident in the cloud). Off by default, since a geo
    /// block merely returns a status code and bumps a counter, without spending resources on an event.
    #[serde(default)]
    pub geo_log: bool,
    /// Front-side HTTP/2 (ALPN h2) for this site. Globally gated by cfg.http2_enabled.
    #[serde(default = "default_true")]
    pub http2: bool,
    /// Serve this site over IPv6. When off, IPv6 clients are blocked for this site.
    #[serde(default = "default_true")]
    pub ipv6_enabled: bool,
    /// HTTP code for general blocks (rules, bots, reputation, ML, score). 0 defaults to 403.
    #[serde(default)]
    pub block_status: u16,
    /// HTTP code when a rate limit trips. 0 defaults to 429.
    #[serde(default)]
    pub ratelimit_status: u16,
    /// Body inspection limit in bytes (0 defaults to 65536).
    #[serde(default)]
    pub body_limit: usize,
    /// Tail inspection against nowafpls: how many KB of the END of the body to scan additionally when it exceeds
    /// the inspection window (body_limit). Catches a payload pushed past the limit by leading padding. Not applied to
    /// uploads (detected by content type). 0 disables it. Defaults to 32 KB.
    #[serde(default = "default_tail_kb")]
    pub body_tail_kb: usize,
    /// Signal for 'body larger than the inspection window', i.e. an uninspected gap on a non-upload:
    /// 0 = off, 1 = contribute to the threat score (DEFAULT), 2 = block in protect. The default is 1 because the middle
    /// of large bodies is not inspected (only the prefix and tail), so the gap is made visible
    /// in the score. An explicit 0 from policy is a deliberate operator choice. Uploads are excluded.
    #[serde(default = "default_oversized")]
    pub body_oversized: u8,
    /// Backend response timeout in seconds (0 defaults to 30). Exceeding it yields 504.
    #[serde(default)]
    pub upstream_timeout: u32,
    /// Request body READ timeout in seconds (0 defaults to 30). Raise it for large, slow
    /// uploads over poor links, so the connection is not torn down prematurely.
    #[serde(default)]
    pub body_read_timeout: u32,
    /// Allowed HTTP methods (upper case). Empty means no restriction. Otherwise a method outside
    /// the list yields 405 (always a hard gate). This also covers exotica such as TRACE, CONNECT and non-standard verbs.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// API protection (phase 1): structural JWT gate plus JSON hygiene. NOT deserialised from
    /// JSON directly (ApiSecCfg is not Deserialize); it is populated in central::site_from_policy
    /// via ApiSecCfg::from_config. serde(skip) means deserialisation yields Default.
    #[serde(skip)]
    pub api_sec: crate::apisec::ApiSecCfg,
    /// API protection (phase 2): a positive model from OpenAPI (method, path, parameters). #[serde(skip)]
    /// yields Default on deserialisation; it is populated in central::site_from_policy via from_config.
    #[serde(skip)]
    pub openapi: crate::openapi::OpenApiGate,
    /// Add safe security headers to the response when the backend omits them:
    /// nosniff, X-Frame-Options, Referrer-Policy and HSTS (HTTPS only).
    #[serde(default)]
    pub sec_headers: bool,
    /// Log-only mode for hard gates: the gate fires and is logged as detected but does NOT
    /// block, which is useful for a safe rollout. Defaults to false, meaning block.
    #[serde(default)]
    pub traversal_logonly: bool,
    #[serde(default)]
    pub method_logonly: bool,
    #[serde(default)]
    pub ipv6_logonly: bool,
    /// ML anomaly: block in protect mode (otherwise detect only).
    #[serde(default)]
    pub anomaly_block: bool,
    /// Anomaly sensitivity: low|medium|high.
    #[serde(default = "default_sens")]
    pub anomaly_sens: String,
    /// Redirect HTTP to HTTPS (301) for this domain.
    #[serde(default)]
    pub force_https: bool,
    /// Skip backend certificate validation (for self-signed or IP-addressed origins).
    #[serde(default)]
    pub insecure_backend: bool,
    /// Allow proxying to a private or local origin (10.x/172.16.x/192.168.x/127.0.0.1)
    /// on the node's network or host. Defaults to true for compatibility: the node used to ignore this flag and
    /// private backends were permitted. false makes the node reject such backends for this site.
    /// Metadata and link-local addresses (169.254.*) are always blocked, regardless of this flag.
    #[serde(default = "default_true")]
    pub allow_private_backend: bool,
    /// Log retention for this site in ClickHouse, in days (0 defaults to 30).
    #[serde(default)]
    pub retention_days: u16,
    /// Trusted IPs/CIDRs: ML trains ONLY on these, giving a clean baseline of normal traffic.
    /// Empty means the model does not train and waits for trusted traffic.
    #[serde(default)]
    pub ml_trusted_ips: Vec<String>,
    /// Store full details (headers and body) for ALL requests, rather than only notable ones.
    #[serde(default)]
    pub log_full: bool,
    /// Custom block page: the response body (HTML, text or JSON). Empty uses the default.
    #[serde(default)]
    pub block_body: String,
    /// Content-Type of the custom page (defaults to text/html).
    #[serde(default)]
    pub block_content_type: String,
    /// Allow-listed IPs/CIDRs: passed through immediately, bypassing every check.
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    /// Deny-listed IPs/CIDRs: blocked immediately, before any check.
    #[serde(default)]
    pub ip_blacklist: Vec<String>,
    /// Bot detection mode: off|detect|block.
    #[serde(default)]
    pub bot_mode: String,
    /// Search crawler verification via FCrDNS (forward-confirmed reverse DNS).
    /// Catches User-Agent forgery: a claimed Googlebot or Bingbot is confirmed via rDNS.
    #[serde(default)]
    pub verbot_enabled: bool,
    /// Action when a crawler is claimed but NOT confirmed (a spoof):
    /// "detect" | "challenge" | "block". Works independently of bot_mode.
    #[serde(default)]
    pub verbot_spoof_action: String,
    /// Protection against ATO and credential stuffing on login endpoints.
    #[serde(default)]
    pub ato_enabled: bool,
    /// Login path prefixes (e.g. "/login", "/api/auth"). Empty disables the check.
    #[serde(default)]
    pub ato_login_paths: Vec<String>,
    /// Action when triggered: "detect" | "challenge" | "block".
    #[serde(default)]
    pub ato_action: String,
    /// Observation window in seconds (0 defaults to 300).
    #[serde(default)]
    pub ato_window: u64,
    /// Threshold: login attempts from one IP per window (0 disables it).
    #[serde(default)]
    pub ato_ip_attempts: u32,
    /// Threshold: DISTINCT logins from one IP per window, i.e. credential stuffing (0 disables it).
    #[serde(default)]
    pub ato_ip_users: u32,
    /// Threshold: DISTINCT IPs per login per window, i.e. distributed brute force (0 disables it).
    #[serde(default)]
    pub ato_user_ips: u32,
    /// Login field names in the body (form or JSON). Empty defaults to username, email, login, user.
    #[serde(default)]
    pub ato_user_fields: Vec<String>,
    /// DLP: inspect the RESPONSE body for leaks (secrets, PII, errors).
    #[serde(default)]
    pub dlp_enabled: bool,
    /// Action: "detect" | "redact" | "block".
    #[serde(default)]
    pub dlp_action: String,
    #[serde(default)]
    pub dlp_secrets: bool,
    #[serde(default)]
    pub dlp_pii: bool,
    #[serde(default)]
    pub dlp_errors: bool,
    /// User-supplied regexes (bytes) for the response body.
    #[serde(default)]
    pub dlp_patterns: Vec<String>,
    /// Cap on how many body bytes are scanned (0 defaults to 1 MiB).
    #[serde(default)]
    pub dlp_max_scan: usize,
    /// Apply centrally managed rules (virtual patching, delivered by the cloud).
    #[serde(default)]
    pub managed_rules_enabled: bool,
    /// Collective defence: apply the cross-tenant attacker IP feed (populated by opt-in tenants).
    #[serde(default)]
    pub collective_defense_enabled: bool,
    /// Action: "detect" (pre-warning) | "challenge" | "block" (pre-ban).
    #[serde(default)]
    pub collective_defense_action: String,
    /// Adaptive rate limiting: tighten limits when the site's rps exceeds a threshold.
    #[serde(default)]
    pub adaptive_rl_enabled: bool,
    /// Load threshold (site rps) above which limits tighten (0 disables it).
    #[serde(default)]
    pub adaptive_rl_threshold: u32,
    /// Limit multiplier under load, as a percentage (e.g. 50 means rps x 0.5). 0 or 100 means no reduction.
    #[serde(default)]
    pub adaptive_rl_factor: u32,
    /// Load measurement window in seconds (0 defaults to 10).
    #[serde(default)]
    pub adaptive_rl_window: u64,
    /// Under load, serve a challenge instead of a block: humans solve the PoW, bots do not.
    #[serde(default)]
    pub adaptive_rl_challenge: bool,
    /// Extra bot check: TLS fingerprint (JA3/JA4) against the claimed browser.
    /// Enable ONLY when the node terminates TLS directly, not behind a CDN.
    #[serde(default)]
    pub bot_tls_check: bool,
    /// Deny list of JA3 TLS fingerprints (md5 hashes): blocked immediately.
    #[serde(default)]
    pub ja3_blacklist: Vec<String>,
    /// Deny list of JA4 TLS fingerprints: blocked immediately.
    #[serde(default)]
    pub ja4_blacklist: Vec<String>,
    /// Injection detector (libinjection style, SQLi/XSS), contributing to the threat score.
    #[serde(default)]
    pub siginj_enabled: bool,
    /// Behavioural bot management: scoring client behaviour within a window.
    #[serde(default)]
    pub bot_behavior: bool,
    /// Behavioural analysis sensitivity: low | medium | high.
    #[serde(default)]
    pub bot_behavior_sens: String,
    /// Centrally managed feed of malicious JA3/JA4 TLS fingerprints from the cloud.
    #[serde(default)]
    pub fpfeed_enabled: bool,
    /// Targeted: log every request for this site, including legitimate ones and bodies.
    #[serde(default)]
    pub log_all_requests: bool,
    /// Automatic IP banning: N terminal blocks within a window results in a ban for a set duration.
    #[serde(default)]
    pub autoban_enabled: bool,
    #[serde(default)]
    pub autoban_threshold: u32, // how many blocks (0 or unset defaults to 10)
    #[serde(default)]
    pub autoban_window: u32,    // counting window in seconds (0 or unset defaults to 60)
    #[serde(default)]
    pub autoban_duration: u32,  // ban duration in seconds (0 or unset defaults to 3600)
    /// Behind a CDN: the header carrying the client JA3 (e.g. cf-client-ja3). Empty means not behind a CDN.
    #[serde(default)]
    pub cdn_ja3_header: String,
    /// Behind a CDN: the header carrying the client JA4. Empty means none.
    #[serde(default)]
    pub cdn_ja4_header: String,
    /// Threat Score: whether the aggregated threat score is enabled.
    #[serde(default)]
    pub score_enabled: bool,
    /// whether IP reputation checking (the cloud threat-intel list) is enabled for this site
    #[serde(default)]
    pub iprep_enabled: bool,
    /// Blocking threshold on the total score (0 disables it).
    #[serde(default)]
    pub score_threshold: u32,
    /// Signal weights (0 means default). Tune these per site.
    #[serde(default)]
    pub score_w_bot: u32,
    #[serde(default)]
    pub score_w_anomaly: u32,
    #[serde(default)]
    pub score_w_rule: u32,
    #[serde(default)]
    pub score_w_geo: u32,
    /// Weight of the ML signal, multiplied by the model's confidence (0..1). 0 means default.
    #[serde(default)]
    pub score_w_ml: u32,
    /// Grey-listed countries: not blocked, but they add to the threat score.
    #[serde(default)]
    pub score_grey_countries: Vec<String>,
    /// Threat Score threshold for a CHALLENGE (0 disables score-driven challenges).
    #[serde(default)]
    pub score_challenge: u32,
    /// Proof-of-work difficulty in leading zero bits. 0 defaults to 18.
    #[serde(default)]
    pub challenge_difficulty: u32,
    /// Secret for signing the challenge token (HMAC). Empty falls back to the node secret.
    #[serde(default)]
    pub challenge_secret: String,
    /// Maximum request body size in KB (0 means no limit). Exceeding it yields 413.
    #[serde(default)]
    pub max_body_kb: usize,
    /// Maximum size of a SINGLE uploaded file in KB (0 disables it). Checked per file after
    /// parsing multipart parts; exceeding it yields 413. For non-multipart it applies to the whole body.
    #[serde(default)]
    pub upload_max_kb: usize,
    /// OPTIONAL extra scope for upload checks. Uploads are detected by Content-Type and multipart
    /// (request shape), NOT by path. A non-empty list restricts checks to these prefixes;
    /// empty (the default) applies them to all uploads wherever they occur.
    #[serde(default)]
    pub upload_paths: Vec<String>,
    /// Hard-block webshell uploads (dangerous extension or type mismatch) in protect mode.
    /// false (the default) only contributes to the threat score.
    #[serde(default)]
    pub upload_block: bool,
    /// Maximum URI length in KB (0 means no limit). Exceeding it yields 414.
    #[serde(default)]
    pub max_uri_kb: usize,
    /// Enable supervised ML detection for this site.
    #[serde(default = "default_true")]
    pub ml_enabled: bool,
    /// Pass WebSocket upgrades through to the backend; the handshake still traverses the WAF.
    #[serde(default = "default_true")]
    pub websocket: bool,
    /// gzip response compression (text/json/js/css/...) when the client supports it.
    #[serde(default = "default_true")]
    pub compression: bool,
    /// Cache backend responses (explicitly cacheable ones only, and only AFTER the WAF checks).
    #[serde(default)]
    pub cache: bool,
    /// Upper bound on cache TTL in seconds (0 means unbounded, taken from Cache-Control).
    #[serde(default)]
    pub cache_ttl: u32,
    /// Attack probability threshold for blocking (0..1, default 0.8). 0 uses the default.
    #[serde(default)]
    pub ml_threshold: f64,
    /// ML contribution to the Threat Score (weight, default 50).
    #[serde(default)]
    pub ml_weight: u32,
    /// Lower bound of the ML grey zone for quarantine (0..1, default 0.4). Requests
    /// with a probability in [low, threshold) are logged for review rather than blocked.
    #[serde(default)]
    pub ml_review_low: f64,
    /// Minimum ML severity that has EFFECT (scoring/detection): 1=low, 2=medium, 3=high, 4=critical.
    /// The band is derived from the confidence value. Below the threshold it only quarantines for training, scoring nothing.
    /// 0 or 1 means the default (low, the current behaviour).
    #[serde(default)]
    pub ml_min_severity: u8,
    /// ML severity blocking mode: when true, ML blocks on its own from ml_min_severity upwards
    /// (in protect) and only detects below that; in this mode ML does not feed the overall threat score.
    /// false (the default) feeds the threat score, and blocking happens via the combined threshold.
    #[serde(default)]
    pub ml_severity_block: bool,
    /// Anomaly profile reset epoch, bumped from the dashboard. Internal bookkeeping:
    /// it must not be required in a hand-written config file, hence the default.
    #[serde(default)]
    pub ml_reset_epoch: i64,
    /// PEM certificate authority that client certificates are validated against.
    /// Required for mTLS without the cloud: `mtls_locations` alone only checks that
    /// a certificate was presented, and the presenting is what the CA verifies.
    #[serde(default)]
    pub mtls_ca_file: String,
    /// Path prefixes requiring mTLS (a client certificate). Empty disables mTLS.
    #[serde(default)]
    pub mtls_locations: Vec<String>,
    /// Serial numbers of revoked client certificates (hex).
    #[serde(default)]
    pub mtls_revoked: Vec<String>,
    /// Prebuilt set of normalised revoked serials for O(1) lookup.
    /// Populated when policy is loaded; not serialised.
    #[serde(skip)]
    pub mtls_revoked_set: std::collections::HashSet<String>,
}

fn default_true() -> bool { true }
fn default_sens() -> String {
    "medium".to_string()
}

fn default_geo() -> String {
    "off".to_string()
}

fn default_mode() -> String {
    "detect".to_string()
}

fn default_tail_kb() -> usize { 32 }
fn default_oversized() -> u8 { 1 } // the uninspected gap inside large bodies is visible in the threat score

fn default_http() -> String {
    "0.0.0.0:8088".to_string()
}

/// Index of sites by domain, for fast routing on the Host header.
pub struct Router {
    pub by_domain: HashMap<String, Arc<Site>>,
    /// wildcard sites: the suffix ".domain.com" (for *.domain.com) -> site.
    pub wildcards: Vec<(String, Arc<Site>)>,
}

impl Router {
    pub fn new(cfg: &Config) -> Self {
        Router::from_sites(cfg.sites.clone())
    }

    pub fn from_sites(sites: Vec<Site>) -> Self {
        let mut by_domain = HashMap::new();
        let mut wildcards: Vec<(String, Arc<Site>)> = Vec::new();
        for s in sites {
            let dom = s.domain.to_lowercase();
            if let Some(rest) = dom.strip_prefix("*.") {
                // *.domain.com becomes the suffix ".domain.com", matching any subdomain
                wildcards.push((format!(".{}", rest), Arc::new(s)));
            } else {
                by_domain.insert(dom, Arc::new(s));
            }
        }
        // the longer, more specific suffix wins: *.api.domain.com takes precedence over *.domain.com
        wildcards.sort_by_key(|w| std::cmp::Reverse(w.0.len()));
        Router { by_domain, wildcards }
    }

    /// Find a site by the Host header value, ignoring the port.
    /// Exact match first, then wildcard *.domain.com across subdomains.
    pub fn match_host(&self, host: &str) -> Option<Arc<Site>> {
        let h = host.split(':').next().unwrap_or(host).to_lowercase();
        if let Some(s) = self.by_domain.get(&h) { return Some(s.clone()); }
        for (suffix, site) in &self.wildcards {
            // foo.domain.com matches the suffix ".domain.com"; the apex domain.com does not
            if h.len() > suffix.len() && h.ends_with(suffix.as_str()) {
                return Some(site.clone());
            }
        }
        None
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
        let data = std::fs::read_to_string(path)?;
        let mut cfg: Config = serde_json::from_str(&data)?;

        // The API-security gates take a raw JSON blob rather than typed fields,
        // because they read the same flat key set the cloud policy uses
        // (api_jwt_*, api_json_*, api_schema_*). Those keys are therefore not
        // fields on Site, so parse the document a second time as untyped JSON and
        // hand each site's object to the gate constructors. serde preserves array
        // order, so index i here is the same site as index i above.
        let raw: serde_json::Value = serde_json::from_str(&data)?;
        let raw_sites = raw.get("sites").and_then(|v| v.as_array());

        for (i, site) in cfg.sites.iter_mut().enumerate() {
            if let Some(rs) = raw_sites.and_then(|a| a.get(i)) {
                site.api_sec = crate::apisec::ApiSecCfg::from_config(rs);
                site.openapi = crate::openapi::OpenApiGate::from_config(rs);
            }

            // build the set of revoked mTLS serials for O(1) lookup (normalised)
            if !site.mtls_revoked.is_empty() {
                site.mtls_revoked_set = site.mtls_revoked.iter()
                    .map(|s| s.trim_start_matches('0').to_ascii_lowercase())
                    .collect();
            }
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod default_tests {
    use super::*;

    /// The serde defaults below are security-relevant: if any of them silently
    /// becomes the type's zero value, a protection quietly turns itself off and
    /// nothing in the logs will say so. Deserialise a minimal config and assert
    /// the values, so a refactor that orphans a `default_*` fn fails loudly here.
    #[test]
    fn site_defaults_are_applied() {
        let s: Site =
            serde_json::from_str(r#"{"domain":"a.test","backends":["http://127.0.0.1:8000"]}"#)
                .unwrap();
        assert_eq!(s.mode, "detect", "mode must default to detect, not empty");
        assert_eq!(s.body_tail_kb, 32, "tail inspection must default to 32 KB");
        assert_eq!(s.body_oversized, 1, "oversized-body signal must default to scoring");
        assert_eq!(s.geo_mode, "off");
        assert_eq!(s.anomaly_sens, "medium");
    }

    /// The API-security gates are configured from a flat key set that is not
    /// made up of Site fields, so they are wired up by hand in Config::load.
    /// If that wiring is dropped, the gates silently do nothing and no error is
    /// reported anywhere — hence this test.
    #[test]
    fn api_gates_are_configured_from_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("threatail_api_cfg_{}.json", std::process::id()));
        std::fs::write(&path, r#"{
          "sites": [{
            "domain": "api.test",
            "backends": ["http://127.0.0.1:8000"],
            "api_jwt_enabled": true,
            "api_jwt_paths": ["/api/"],
            "api_jwt_require": true,
            "api_jwt_algs": ["rs256"],
            "api_jwt_logonly": false,
            "api_json_enabled": true,
            "api_json_max_depth": 5,
            "api_schema_enabled": true
          }]
        }"#).unwrap();

        let cfg = Config::load(path.to_str().unwrap()).unwrap();
        let s = &cfg.sites[0];
        assert!(s.api_sec.jwt_enabled, "JWT gate must be enabled from config.json");
        assert!(s.api_sec.jwt_require);
        assert_eq!(s.api_sec.jwt_paths, vec!["/api/".to_string()]);
        assert_eq!(s.api_sec.jwt_algs, vec!["rs256".to_string()]);
        assert!(s.api_sec.json_enabled, "JSON hygiene must be enabled from config.json");
        assert_eq!(s.api_sec.json_max_depth, 5);
        assert!(s.openapi.enabled, "OpenAPI gate must be enabled from config.json");

        let _ = std::fs::remove_file(&path);
    }

    /// The example config is what every new user copies first. If a required
    /// field is added to Site without a serde default, this catches it here
    /// rather than in someone's terminal on their first run.
    #[test]
    fn shipped_example_config_loads() {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.json");
        let cfg = Config::load(p).expect("config.example.json must load as-is");
        assert!(!cfg.sites.is_empty(), "example config should define at least one site");
    }

    #[test]
    fn config_defaults_are_applied() {
        let c: Config = serde_json::from_str(r#"{"sites":[]}"#).unwrap();
        assert_eq!(c.listen_http, "0.0.0.0:8088");
    }
}
