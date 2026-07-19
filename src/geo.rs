// Country lookup by IP via the MaxMind GeoLite2-Country.mmdb database.
// The database is optional: if no path is set or the file cannot be opened, geo is disabled.

use std::net::IpAddr;
use std::sync::Arc;

pub struct Geo {
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
}

impl Geo {
    /// Open the database. None if missing or unreadable.
    pub fn open(path: &str) -> Option<Geo> {
        if path.is_empty() {
            return None;
        }
        match maxminddb::Reader::open_readfile(path) {
            Ok(r) => {
                tracing::info!("GeoIP database loaded: {}", path);
                Some(Geo { reader: Arc::new(r) })
            }
            Err(e) => {
                tracing::warn!("GeoIP: cannot open {}: {:?}", path, e);
                None
            }
        }
    }

    /// ISO country code for an IP ("" if not found).
    pub fn country(&self, ip: &str) -> String {
        let addr: IpAddr = match ip.parse() {
            Ok(a) => a,
            Err(_) => return String::new(),
        };
        // maxminddb 0.28: lookup(addr) -> Result<LookupResult, _> (not generic).
        // Read only country.iso_code via decode_path instead of decoding the whole record.
        // Ok(Some(code)) = found; Ok(None) = no data or field; Err = database error.
        match self.reader.lookup(addr) {
            Ok(res) => res
                .decode_path::<String>(&maxminddb::path!["country", "iso_code"])
                .ok()
                .flatten()
                .unwrap_or_default(),
            Err(_) => String::new(),
        }
    }
}

/// Geo policy decision.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GeoMode {
    Off,
    Allow, // allow only the listed countries
    Deny,  // block the listed countries
}

impl GeoMode {
    pub fn from_str(s: &str) -> GeoMode {
        match s {
            "allow" => GeoMode::Allow,
            "deny" => GeoMode::Deny,
            _ => GeoMode::Off,
        }
    }
}

/// true = block according to the geo policy.
pub fn geo_blocked(mode: GeoMode, countries: &[String], country: &str) -> bool {
    match mode {
        GeoMode::Off => false,
        GeoMode::Allow => {
            // empty country (undetermined) or not in the list -> block
            !countries.iter().any(|c| c.eq_ignore_ascii_case(country)) || country.is_empty()
        }
        GeoMode::Deny => countries.iter().any(|c| c.eq_ignore_ascii_case(country)),
    }
}
