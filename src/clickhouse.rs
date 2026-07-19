// Logging of ALL traffic straight into ClickHouse (option A).
// The node accumulates records in a channel; a background task sends them in batches over the
// ClickHouse HTTP interface (INSERT ... FORMAT JSONEachRow). ClickHouse prefers infrequent large
// inserts, so batching is by size and by time.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ClickhouseCfg {
    /// http://host:8123 (empty disables ClickHouse logging).
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_db")]
    pub db: String,
}

fn default_db() -> String {
    "threatail".to_string()
}

impl ClickhouseCfg {
    pub fn enabled(&self) -> bool {
        !self.url.is_empty()
    }
}

/// A single access-log record; fields mirror the ClickHouse schema.
#[derive(Debug, Serialize, Clone)]
pub struct AccessLog {
    pub node: String,
    pub host: String,
    pub client_ip: String,
    pub country: String,
    pub method: String,
    pub uri: String,
    pub location: String,
    pub status: u16,
    pub action: String,
    pub sig: String,
    pub severity: u8,
    pub ua: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub latency_ms: u32,
    pub query_string: String,
    pub req_headers: String,
    pub req_body: String,
    pub incident_id: String,
    pub retention_days: u16,
    #[serde(default)]
    pub ml_proba: f32, // ML attack probability (0 when ML did not run)
    #[serde(default)]
    pub http_version: String, // request protocol version
}

pub type AccessTx = tokio::sync::mpsc::UnboundedSender<AccessLog>;

/// Start the background batch-insert task for ClickHouse. Returns the channel.
pub fn spawn(cfg: ClickhouseCfg) -> Option<AccessTx> {
    if !cfg.enabled() {
        return None;
    }
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<AccessLog>();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client");
    tokio::spawn(async move {
        sender(cfg, http, rx).await;
    });
    Some(tx)
}

async fn sender(
    cfg: ClickhouseCfg,
    http: reqwest::Client,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<AccessLog>,
) {
    // INSERT over HTTP: the body is JSONEachRow lines.
    let insert_url = format!(
        "{}/?query={}",
        cfg.url.trim_end_matches('/'),
        urlencode(&format!("INSERT INTO {}.access FORMAT JSONEachRow", cfg.db))
    );

    let mut batch: Vec<AccessLog> = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(rec) => {
                        batch.push(rec);
                        if batch.len() >= 500 {
                            flush(&http, &insert_url, &cfg, &mut batch).await;
                        }
                    }
                    None => { flush(&http, &insert_url, &cfg, &mut batch).await; break; }
                }
            }
            _ = tick.tick() => {
                if !batch.is_empty() {
                    flush(&http, &insert_url, &cfg, &mut batch).await;
                }
            }
        }
    }
}

async fn flush(http: &reqwest::Client, url: &str, cfg: &ClickhouseCfg, batch: &mut Vec<AccessLog>) {
    // body: one JSON line per record
    let mut body = String::with_capacity(batch.len() * 200);
    for rec in batch.iter() {
        if let Ok(line) = serde_json::to_string(rec) {
            body.push_str(&line);
            body.push('\n');
        }
    }
    let mut req = http.post(url).body(body);
    if !cfg.user.is_empty() {
        req = req.header("X-ClickHouse-User", &cfg.user);
        req = req.header("X-ClickHouse-Key", &cfg.password);
    }
    match req.send().await {
        Ok(r) if r.status().is_success() => batch.clear(),
        Ok(r) => {
            tracing::warn!("ClickHouse INSERT status {}", r.status());
            batch.clear(); // do not accumulate forever if the schema is wrong
        }
        Err(e) => {
            tracing::debug!("ClickHouse unavailable: {:?}", e);
            if batch.len() > 5000 {
                batch.clear(); // guards against memory growth during a long outage
            }
        }
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
