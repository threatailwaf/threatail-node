// Centrally managed feed of malicious TLS fingerprints (JA3/JA4) from the cloud.
// The cloud aggregates the enabled sources and serves them to nodes (/api/node/fpfeed);
// applied per site via the fpfeed_enabled flag. Hot-swapped via ArcSwap.
// Fast matching against a HashSet of exact strings (JA3 md5 hex or JA4), all lower-cased.

use std::collections::HashSet;

#[derive(Default)]
pub struct FpFeed {
    set: HashSet<String>, // ja3 (md5 hex) and/or ja4, normalised to lower case
}

impl FpFeed {
    /// Parses a feed with one fingerprint per line. The first token is used
    /// (so CSV like `ja3_md5,date,reason` works); `#` and `;` lines are skipped.
    /// Accepts JA3 (32 hex chars) and JA4 (contains `_`, characters [a-z0-9_]).
    pub fn parse(text: &str) -> FpFeed {
        let mut set = HashSet::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let tok = line
                .split([',', ';', ' ', '\t'])
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if is_ja3(&tok) || is_ja4(&tok) {
                set.insert(tok);
            }
        }
        FpFeed { set }
    }

    /// Whether the fingerprint is in the feed (exact match, case-insensitive).
    pub fn contains(&self, fp: &str) -> bool {
        if fp.is_empty() {
            return false;
        }
        self.set.contains(&fp.to_ascii_lowercase())
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
    pub fn len(&self) -> usize {
        self.set.len()
    }
}

/// JA3 is an md5: exactly 32 hex characters.
fn is_ja3(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// JA4 contains `_` and consists of [a-z0-9_] once lower-cased. Length is not fixed.
fn is_ja4(s: &str) -> bool {
    s.contains('_') && !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ja3_csv_and_ja4() {
        let f = FpFeed::parse(
            "# ja3_md5,date,reason\n\
             e7d705a3286e19ea42f587b344ee6865,2021-01-01,malware\n\
             t13d1516h2_8daaf6152771_b186095e22b6\n\
             ; comment\n\
             not-a-fingerprint\n",
        );
        assert!(f.contains("E7D705A3286E19EA42F587B344EE6865")); // case-insensitive
        assert!(f.contains("t13d1516h2_8daaf6152771_b186095e22b6"));
        assert!(!f.contains("00000000000000000000000000000000"));
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn empty_and_garbage() {
        let f = FpFeed::parse("\n  \n#c\nxyz\n12345\n");
        assert!(f.is_empty());
        assert!(!f.contains("12345"));
    }
}
