// IP reputation: a set of known malicious IPs from a threat-intel feed.
// Fast matching: a HashSet of exact IPv4 addresses (O(1)) plus a list of CIDR ranges (usually few).
// Hot-swapped wholesale via ArcSwap, like the geo database.

use std::collections::HashSet;

#[derive(Default)]
pub struct IpRep {
    exact: HashSet<u32>,    // individual IPv4 host addresses
    cidrs: Vec<(u32, u32)>, // (network, mask) pairs for ranges
    count: usize,
}

impl IpRep {
    /// Parses a feed with one address per line. Accepts `ip`, `ip/prefix`,
    /// `ip,category` and `ip;...`; `#` and `;` start a comment. The first token of the line is used.
    pub fn parse(text: &str) -> IpRep {
        let mut exact = HashSet::new();
        let mut cidrs = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let tok = line
                .split([',', ';', ' ', '\t'])
                .next()
                .unwrap_or("")
                .trim();
            if tok.is_empty() {
                continue;
            }
            if let Some((net, bits)) = tok.split_once('/') {
                if let (Some(n), Ok(b)) = (parse_v4(net), bits.trim().parse::<u8>()) {
                    if b <= 32 {
                        let mask = if b == 0 { 0 } else { u32::MAX << (32 - b) };
                        cidrs.push((n & mask, mask));
                    }
                }
            } else if let Some(n) = parse_v4(tok) {
                exact.insert(n);
            }
        }
        let count = exact.len() + cidrs.len();
        IpRep { exact, cidrs, count }
    }

    /// Whether the IP is in the feed, either an exact match or inside a CIDR range.
    pub fn is_bad(&self, ip: &str) -> bool {
        let n = match parse_v4(ip) {
            Some(n) => n,
            None => return false,
        };
        if self.exact.contains(&n) {
            return true;
        }
        self.cidrs.iter().any(|(net, mask)| (n & mask) == *net)
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn len(&self) -> usize {
        self.count
    }
}

fn parse_v4(s: &str) -> Option<u32> {
    let mut parts = s.trim().split('.');
    let a = parts.next()?.trim().parse::<u8>().ok()?;
    let b = parts.next()?.trim().parse::<u8>().ok()?;
    let c = parts.next()?.trim().parse::<u8>().ok()?;
    let d = parts.next()?.trim().parse::<u8>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_cidr() {
        let rep = IpRep::parse("1.2.3.4\n10.0.0.0/8\n# comment\n8.8.8.8,scanner\n");
        assert!(rep.is_bad("1.2.3.4"));
        assert!(rep.is_bad("8.8.8.8"));
        assert!(rep.is_bad("10.5.6.7")); // within /8
        assert!(!rep.is_bad("11.0.0.1"));
        assert!(!rep.is_bad("1.2.3.5"));
        assert_eq!(rep.len(), 3);
    }

    #[test]
    fn empty_and_garbage() {
        let rep = IpRep::parse("\n  \n#only comment\nnot-an-ip\n999.1.1.1\n");
        assert!(rep.is_empty());
        assert!(!rep.is_bad("1.1.1.1"));
    }

    #[test]
    fn cidr_32_and_0() {
        let rep = IpRep::parse("5.5.5.5/32\n");
        assert!(rep.is_bad("5.5.5.5"));
        assert!(!rep.is_bad("5.5.5.6"));
    }
}
