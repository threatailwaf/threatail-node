// Stage 4: unsupervised ML — a profile of normal traffic plus anomaly scoring.
// The profile is built per (site -> location) and holds request feature statistics:
// parameter count, value lengths, ratio of special characters, and known argument
// names. A request that deviates strongly from its location's profile receives a
// high anomaly score. The profile is persisted to disk as JSON.
//
// This is a heuristic statistical profile (mean and standard deviation per feature), not
// a neural network: fast and inline, but it measures unusualness rather than understanding an attack.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// training criteria (as in the C project)
const MIN_SAMPLES: u64 = 50_000;
const MIN_UNIQUE_IPS: usize = 200;
const MIN_LOCATIONS: usize = 8;
const MIN_WINDOW_SECS: i64 = 24 * 3600;
const IP_CAP: usize = 2000; // memory cap for the IP set
// Cap on locations per site: the locations key is the normalised request path
// (attacker-controlled, and non-numeric segments are not collapsed), so without a limit the map
// grows without bound and OOMs the whole node. A legitimate site has a finite endpoint set;
// a burst of unique paths means a scanner or flood. The value leaves headroom over real APIs.
const MAX_LOCATIONS: usize = 1024;
// Hard cap on argument names within a single LocProfile (anti-OOM): the soft cleanup of
// singletons (retain count>1) is defeated by a stream of names with count>=2. Past the cap, no new names are added.
const ARG_NAMES_HARD_CAP: usize = 1024;

/// Profile of one location: cumulative feature statistics.
#[derive(Default, Serialize, Deserialize, Clone)]
struct LocProfile {
    count: u64,
    // sums and sums of squares, for mean and standard deviation
    np_sum: f64,  np_sq: f64,  // parameter count
    len_sum: f64, len_sq: f64, // mean value length
    spc_sum: f64, spc_sq: f64, // ratio of special characters
    #[serde(default)] mx_sum: f64, #[serde(default)] mx_sq: f64,  // maximum value length
    #[serde(default)] dg_sum: f64, #[serde(default)] dg_sq: f64,  // ratio of digits
    #[serde(default)] en_sum: f64, #[serde(default)] en_sq: f64,  // entropy
    arg_names: HashMap<String, u64>, // known argument names and their frequencies
}

impl LocProfile {
    fn mean_std(sum: f64, sq: f64, n: f64) -> (f64, f64) {
        if n < 2.0 {
            return (sum / n.max(1.0), 0.0);
        }
        let mean = sum / n;
        let var = (sq / n - mean * mean).max(0.0);
        (mean, var.sqrt())
    }
    fn update(&mut self, f: &Features) {
        self.count += 1;
        // protects the profile from one-off outliers: extreme values are clamped so that
        // a single enormous request cannot poison the baseline.
        let cl = |x: f64, cap: f64| x.min(cap);
        let np = cl(f.nparams, 200.0);
        let ln = cl(f.avg_len, 100_000.0);
        let mx = cl(f.max_len, 1_000_000.0);
        self.np_sum += np; self.np_sq += np * np;
        self.len_sum += ln; self.len_sq += ln * ln;
        self.spc_sum += f.spc_ratio; self.spc_sq += f.spc_ratio * f.spc_ratio;
        self.mx_sum += mx; self.mx_sq += mx * mx;
        self.dg_sum += f.digit_ratio; self.dg_sq += f.digit_ratio * f.digit_ratio;
        self.en_sum += f.entropy; self.en_sq += f.entropy * f.entropy;
        for name in &f.arg_names {
            // Hard cap: past the limit no new names are added, only known ones are updated.
            // The soft cleanup below removes only singletons (count<=1); a stream of unique names
            // sent twice (count>=2) evades it and, without this cap, would grow without bound.
            if self.arg_names.len() >= ARG_NAMES_HARD_CAP && !self.arg_names.contains_key(name) {
                continue;
            }
            *self.arg_names.entry(name.clone()).or_insert(0) += 1;
        }
        // bound the name dictionary so it cannot grow forever
        if self.arg_names.len() > 500 {
            self.arg_names.retain(|_, &mut c| c > 1);
        }
    }
    /// score [0..1]: how far the request deviates from this location's profile.
    fn score(&self, f: &Features) -> f64 {
        if self.count < 30 {
            return 0.0; // too little data for this location, so we do not score
        }
        let n = self.count as f64;
        let mut z_total = 0.0;
        let mut z_max: f64 = 0.0;
        let mut feats = 0.0;

        for (sum, sq, x) in [
            (self.np_sum, self.np_sq, f.nparams),
            (self.len_sum, self.len_sq, f.avg_len),
            (self.spc_sum, self.spc_sq, f.spc_ratio),
            (self.mx_sum, self.mx_sq, f.max_len),
            (self.dg_sum, self.dg_sq, f.digit_ratio),
            (self.en_sum, self.en_sq, f.entropy),
        ] {
            let (mean, std) = Self::mean_std(sum, sq, n);
            if std > 1e-6 {
                let z = ((x - mean) / std).abs();
                z_total += z;
                if z > z_max { z_max = z; }
                feats += 1.0;
            }
        }

        // share of unfamiliar argument names
        let mut unknown = 0.0;
        for name in &f.arg_names {
            if !self.arg_names.contains_key(name) {
                unknown += 1.0;
            }
        }
        let unknown_ratio = if f.arg_names.is_empty() {
            0.0
        } else {
            unknown / f.arg_names.len() as f64
        };

        let z_avg = if feats > 0.0 { z_total / feats } else { 0.0 };
        // combine mean z and max z: an attack often spikes exactly ONE feature
        // (a long injection, a burst of special characters), which max-z catches while
        // avg-z washes it out. We take a weighted blend.
        let z_eff = 0.5 * z_avg + 0.5 * z_max;
        // sigmoid of z: z=3 -> ~0.63, z=5 -> ~0.81
        let z_score = 1.0 - (-z_eff / 3.0).exp();
        (z_score * 0.75 + unknown_ratio * 0.25).clamp(0.0, 1.0)
    }
}

/// Request features extracted for ML.
pub struct Features {
    pub nparams: f64,
    pub avg_len: f64,
    pub spc_ratio: f64,
    pub max_len: f64,     // length of the longest value
    pub digit_ratio: f64, // ratio of digits
    pub entropy: f64,     // Shannon entropy over the combined payload
    pub arg_names: Vec<String>,
}

/// Shannon entropy of a string, in bits per character.
fn entropy_of(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    let mut total = 0u32;
    for b in s.bytes() { freq[b as usize] += 1; total += 1; }
    let tf = total as f64;
    let mut e = 0.0;
    for &f in freq.iter() {
        if f > 0 {
            let p = f as f64 / tf;
            e -= p * p.log2();
        }
    }
    e
}

/// Extract features from the query string (args) and the body.
pub fn extract_features(args: &str, body: &str) -> Features {
    let mut names = Vec::new();
    let mut total_len = 0usize;
    let mut nval = 0usize;
    let mut spc = 0usize;
    let mut digits = 0usize;
    let mut chars = 0usize;
    let mut max_len = 0usize;

    let scan = |s: &str, names: &mut Vec<String>, total_len: &mut usize, nval: &mut usize, spc: &mut usize, digits: &mut usize, chars: &mut usize, max_len: &mut usize| {
        for pair in s.split('&') {
            if pair.is_empty() { continue; }
            let mut it = pair.splitn(2, '=');
            let key = it.next().unwrap_or("");
            let val = it.next().unwrap_or("");
            if !key.is_empty() { names.push(key.to_string()); }
            *total_len += val.len();
            if val.len() > *max_len { *max_len = val.len(); }
            *nval += 1;
            for b in val.bytes() {
                *chars += 1;
                if b.is_ascii_digit() { *digits += 1; }
                if !(b.is_ascii_alphanumeric() || b == b' ' || b == b'_' || b == b'-' || b == b'.') {
                    *spc += 1;
                }
            }
        }
    };
    scan(args, &mut names, &mut total_len, &mut nval, &mut spc, &mut digits, &mut chars, &mut max_len);
    if !body.is_empty() {
        let mut blen = 0usize;
        for b in body.bytes() {
            chars += 1;
            blen += 1;
            if b.is_ascii_digit() { digits += 1; }
            if !(b.is_ascii_alphanumeric() || b == b' ' || b == b'_' || b == b'-' || b == b'.' || b == b'\n') {
                spc += 1;
            }
        }
        total_len += body.len();
        if blen > max_len { max_len = blen; }
        nval += 1;
    }

    // entropy over the combined payload (args + body)
    let mut combined = String::with_capacity(args.len() + body.len() + 1);
    combined.push_str(args);
    combined.push(' ');
    combined.push_str(body);

    Features {
        nparams: names.len() as f64,
        avg_len: if nval > 0 { total_len as f64 / nval as f64 } else { 0.0 },
        spc_ratio: if chars > 0 { spc as f64 / chars as f64 } else { 0.0 },
        max_len: max_len as f64,
        digit_ratio: if chars > 0 { digits as f64 / chars as f64 } else { 0.0 },
        entropy: entropy_of(&combined),
        arg_names: names,
    }
}

/// Site profile.
#[derive(Default, Serialize, Deserialize, Clone)]
struct SiteProfile {
    locations: HashMap<String, LocProfile>,
    total: u64,
    #[serde(default)]
    unique_ips: HashSet<String>,
    first_ts: i64,
    last_ts: i64,
}

/// Training status, for the UI.
#[derive(Serialize, Clone)]
pub struct ModelStatus {
    pub samples: u64,
    pub target: u64,
    pub unique_ips: usize,
    pub locations: usize,
    pub window_hours: i64,
    pub progress: u8,
    pub ready: bool,
}

pub struct Anomaly {
    // DashMap gives per-site sharded locks instead of one global Mutex.
    // observe and score for different sites run in parallel, with no serialisation on a single lock.
    sites: dashmap::DashMap<String, SiteProfile>,
    path: String,
    // Applied reset epochs per site, persisted in a sidecar file, so that a node restart
    // does not re-apply the same reset epoch again.
    reset_epochs: dashmap::DashMap<String, i64>,
    reset_path: String,
}

impl Anomaly {
    /// Load the profile from disk, or create an empty one.
    pub fn load(path: &str) -> Anomaly {
        let map: HashMap<String, SiteProfile> = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let sites = dashmap::DashMap::new();
        for (k, v) in map { sites.insert(k, v); }
        let reset_path = format!("{}.reset", path);
        let remap: HashMap<String, i64> = std::fs::read_to_string(&reset_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let reset_epochs = dashmap::DashMap::new();
        for (k, v) in remap { reset_epochs.insert(k, v); }
        Anomaly { sites, path: path.to_string(), reset_epochs, reset_path }
    }

    /// Reset a site's profile when a newer reset epoch arrives from policy. The applied
    /// epoch is persisted so restarts and polling do not trigger repeated resets.
    pub fn maybe_reset(&self, site: &str, epoch: i64) {
        if epoch <= 0 { return; }
        let applied = self.reset_epochs.get(site).map(|r| *r).unwrap_or(0);
        if epoch > applied {
            self.sites.remove(site);
            self.reset_epochs.insert(site.to_string(), epoch);
            self.persist_reset_epochs();
            tracing::info!("ANOMALY-RESET {} epoch={}", site, epoch);
        }
    }

    fn persist_reset_epochs(&self) {
        let snap: HashMap<String, i64> = self.reset_epochs.iter()
            .map(|r| (r.key().clone(), *r.value())).collect();
        if let Ok(json) = serde_json::to_string(&snap) {
            let tmp = format!("{}.tmp", self.reset_path);
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, &self.reset_path);
            }
        }
    }

    /// Record a request into the profile (training runs always, except for pass exceptions).
    pub fn observe(&self, site: &str, location: &str, ip: &str, f: &Features, ts: i64) {
        // entry locks only this site's shard, so other sites are not blocked
        let mut sp = self.sites.entry(site.to_string()).or_default();
        if sp.first_ts == 0 { sp.first_ts = ts; }
        sp.last_ts = ts;
        sp.total += 1;
        if sp.unique_ips.len() < IP_CAP {
            sp.unique_ips.insert(ip.to_string());
        }
        // Bound the number of locations (anti-OOM). At the limit we update only ALREADY known
        // locations and add no new ones; otherwise a stream of unique paths from one IP
        // (/a0001, /a0002, ...) inflates the map permanently, since it has no eviction.
        let at_cap = sp.locations.len() >= MAX_LOCATIONS;
        if !at_cap || sp.locations.contains_key(location) {
            sp.locations.entry(location.to_string()).or_default().update(f);
        }
    }

    /// Anomaly score [0..1] for a request.
    pub fn score(&self, site: &str, location: &str, f: &Features) -> f64 {
        match self.sites.get(site) {
            Some(sp) => match sp.locations.get(location) {
                Some(lp) => lp.score(f),
                None => 0.0,
            },
            None => 0.0,
        }
    }

    /// Whether the site's model is trained, by all criteria.
    pub fn ready(&self, site: &str) -> bool {
        match self.sites.get(site) {
            Some(sp) => {
                sp.total >= MIN_SAMPLES
                    && sp.unique_ips.len() >= MIN_UNIQUE_IPS
                    && sp.locations.len() >= MIN_LOCATIONS
                    && (sp.last_ts - sp.first_ts) >= MIN_WINDOW_SECS
            }
            None => false,
        }
    }

    /// Training status for the UI.
    pub fn status(&self, site: &str) -> ModelStatus {
        let sp = self.sites.get(site).map(|r| r.clone()).unwrap_or_default();
        let vol = (sp.total as f64 / MIN_SAMPLES as f64).min(1.0);
        let ips = (sp.unique_ips.len() as f64 / MIN_UNIQUE_IPS as f64).min(1.0);
        let locs = (sp.locations.len() as f64 / MIN_LOCATIONS as f64).min(1.0);
        let win = (((sp.last_ts - sp.first_ts) as f64) / MIN_WINDOW_SECS as f64).min(1.0);
        let progress = ((vol + ips + locs + win) / 4.0 * 100.0) as u8;
        let ready = sp.total >= MIN_SAMPLES
            && sp.unique_ips.len() >= MIN_UNIQUE_IPS
            && sp.locations.len() >= MIN_LOCATIONS
            && (sp.last_ts - sp.first_ts) >= MIN_WINDOW_SECS;
        ModelStatus {
            samples: sp.total,
            target: MIN_SAMPLES,
            unique_ips: sp.unique_ips.len(),
            locations: sp.locations.len(),
            window_hours: (sp.last_ts - sp.first_ts) / 3600,
            progress,
            ready,
        }
    }

    /// Flush the profile to disk atomically via a temporary file.
    pub fn flush(&self) {
        // snapshot into a plain map for serialisation
        let snapshot: HashMap<String, SiteProfile> = self.sites.iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect();
        if let Ok(json) = serde_json::to_string(&snapshot) {
            let tmp = format!("{}.tmp", self.path);
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }
}

/// Scoring threshold by sensitivity level.
pub fn threshold(sens: &str) -> f64 {
    match sens {
        "low" => 0.85,
        "high" => 0.55,
        _ => 0.70, // medium
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations_capped_against_path_flood() {
        // Anomaly::load on a missing path yields an empty in-memory profile; persistence is separate.
        let a = Anomaly::load("/tmp/tt-anomaly-test-nonexistent");
        let f = extract_features("a=1", "");
        // a stream of unique paths from one IP (a scanner) must not grow the map without bound
        for i in 0..(MAX_LOCATIONS + 500) {
            a.observe("site", &format!("/scan{}", i), "1.2.3.4", &f, 1);
        }
        let locs = a.status("site").locations;
        assert!(locs <= MAX_LOCATIONS, "locations must be capped at {}, got {}", MAX_LOCATIONS, locs);
        // an already known location keeps training even after the cap is reached
        let before = a.status("site").samples;
        a.observe("site", "/scan0", "5.6.7.8", &f, 2);
        assert!(a.status("site").samples > before, "known location must keep updating");
    }
}
