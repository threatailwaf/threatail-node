// Effective client IP: X-Forwarded-For is honoured ONLY when the connection came
// from a trusted proxy (IPv4/CIDR from the list). Otherwise the peer address is used.
// This prevents XFF spoofing. The reverse proxy itself sees the real IP, but if there is
// a CDN or load balancer in front of it, list its subnets in trusted_proxies.

use std::net::IpAddr;

/// Parse an IP (v4 or v6) from a string, stripping the brackets of an IPv6 literal [..].
fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    let s = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(s);
    s.parse::<IpAddr>().ok()
}

/// Address octets (4 for v4, 16 for v6).
fn octets(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// Whether the first `prefix` bits of two same-family addresses match.
fn bits_match(net: &[u8], ip: &[u8], prefix: u32) -> bool {
    if net.len() != ip.len() { return false; }
    let max = (net.len() * 8) as u32;
    if prefix > max { return false; }
    let full = (prefix / 8) as usize;
    if net[..full] != ip[..full] { return false; }
    let rem = prefix % 8;
    if rem == 0 { return true; }
    let mask = 0xFFu8 << (8 - rem);
    (net[full] & mask) == (ip[full] & mask)
}

/// Check whether an ip falls inside an entry (a bare IP, or CIDR a.b.c.d/n, or v6/n). Families must match.
fn ip_in(entry: &str, ip: &IpAddr) -> bool {
    let entry = entry.trim();
    if let Some((net_s, pfx_s)) = entry.split_once('/') {
        let net = match parse_ip(net_s) { Some(v) => v, None => return false };
        let prefix: u32 = match pfx_s.trim().parse() { Ok(v) => v, Err(_) => return false };
        bits_match(&octets(&net), &octets(ip), prefix)
    } else {
        match parse_ip(entry) { Some(net) => &net == ip, None => false }
    }
}

fn is_trusted(trusted: &[String], ip: &IpAddr) -> bool {
    trusted.iter().any(|e| ip_in(e, ip))
}

/// Public helper: whether a string IP (v4/v6) is contained in a list of IPs/CIDRs.
pub fn ip_in_list(ip_str: &str, list: &[String]) -> bool {
    if list.is_empty() {
        return false;
    }
    match parse_ip(ip_str) {
        Some(ip) => is_trusted(list, &ip),
        None => false,
    }
}

/// Return the effective client IP as a string (v4/v6).
/// conn_ip is the peer address; xff is the X-Forwarded-For header value (or "").
/// XFF is honoured ONLY when the connection came from a trusted proxy.
pub fn effective_ip(conn_ip: &str, xff: &str, trusted: &[String]) -> String {
    if trusted.is_empty() {
        return conn_ip.to_string();
    }
    let conn = match parse_ip(conn_ip) {
        Some(v) => v,
        None => return conn_ip.to_string(),
    };
    if !is_trusted(trusted, &conn) {
        return conn_ip.to_string();
    }
    if xff.is_empty() {
        return conn_ip.to_string();
    }
    // walk right to left and take the first address that is not a trusted proxy
    for part in xff.rsplit(',') {
        let cand = part.trim();
        if let Some(v) = parse_ip(cand) {
            if !is_trusted(trusted, &v) {
                return cand.trim_start_matches('[').trim_end_matches(']').to_string();
            }
        }
    }
    conn_ip.to_string()
}

/// Extract the serial number of an X.509 certificate (DER) as a hex string.
/// Structure: Certificate ::= SEQUENCE { tbsCertificate SEQUENCE {
///   [0] version (optional), serialNumber INTEGER, ... } ... }
/// Returns the serial as lower-case hex without DER's leading zero padding.
pub fn cert_serial_hex(der: &[u8]) -> Option<String> {
    // helper: read a DER length, returning (length, number of bytes in the length header)
    fn read_len(b: &[u8]) -> Option<(usize, usize)> {
        if b.is_empty() { return None; }
        let first = b[0];
        if first & 0x80 == 0 {
            Some((first as usize, 1))
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || b.len() < 1 + n { return None; }
            let mut len = 0usize;
            for i in 0..n { len = (len << 8) | b[1 + i] as usize; }
            Some((len, 1 + n))
        }
    }
    // outer SEQUENCE
    if der.first() != Some(&0x30) { return None; }
    let (_outer_len, hdr) = read_len(&der[1..])?;
    let mut p = 1 + hdr;
    // tbsCertificate SEQUENCE
    if der.get(p) != Some(&0x30) { return None; }
    let (_tbs_len, tbs_hdr) = read_len(&der[p + 1..])?;
    p += 1 + tbs_hdr;
    // optional [0] version (context tag 0xA0)
    if der.get(p) == Some(&0xA0) {
        let (vlen, vhdr) = read_len(&der[p + 1..])?;
        p += 1 + vhdr + vlen;
    }
    // serialNumber INTEGER (0x02)
    if der.get(p) != Some(&0x02) { return None; }
    let (slen, shdr) = read_len(&der[p + 1..])?;
    let start = p + 1 + shdr;
    let end = start + slen;
    if end > der.len() { return None; }
    let bytes = &der[start..end];
    // drop the leading zero byte (DER sign padding)
    let bytes = if bytes.first() == Some(&0x00) && bytes.len() > 1 { &bytes[1..] } else { bytes };
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    // the control plane formats the serial as 16 hex chars (u64 BE), so normalise to match
    Some(hex.trim_start_matches('0').to_string()).map(|s| if s.is_empty() { "0".to_string() } else { s })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn s(v: &[&str]) -> Vec<String> { v.iter().map(|x| x.to_string()).collect() }

    #[test]
    fn effective_ip_no_trusted_ignores_xff() {
        assert_eq!(effective_ip("203.0.113.5", "1.2.3.4", &[]), "203.0.113.5");
    }
    #[test]
    fn effective_ip_untrusted_conn_ignores_xff() {
        // connection is not from a trusted proxy, so XFF is not trusted (anti-spoofing)
        assert_eq!(effective_ip("203.0.113.5", "9.9.9.9", &s(&["10.0.0.0/8"])), "203.0.113.5");
    }
    #[test]
    fn effective_ip_trusted_v4_picks_rightmost_untrusted() {
        assert_eq!(effective_ip("10.0.0.2", "9.9.9.9, 10.0.0.2", &s(&["10.0.0.0/8"])), "9.9.9.9");
        assert_eq!(effective_ip("10.0.0.2", "8.8.8.8, 10.0.0.9, 10.0.0.2", &s(&["10.0.0.0/8"])), "8.8.8.8");
    }
    #[test]
    fn effective_ip_single_ip_entry() {
        assert_eq!(effective_ip("203.0.113.1", "7.7.7.7", &s(&["203.0.113.1"])), "7.7.7.7");
    }
    #[test]
    fn effective_ip_v6() {
        assert_eq!(effective_ip("2001:db8::2", "2001:dead::1, 2001:db8::2", &s(&["2001:db8::/32"])), "2001:dead::1");
        // bracketed IPv6 inside XFF
        assert_eq!(effective_ip("2001:db8::2", "[2001:dead::1], 2001:db8::2", &s(&["2001:db8::/32"])), "2001:dead::1");
    }
    #[test]
    fn ip_in_list_v4_and_cidr() {
        assert!(ip_in_list("192.168.1.5", &s(&["192.168.1.0/24"])));
        assert!(!ip_in_list("192.168.2.5", &s(&["192.168.1.0/24"])));
        assert!(ip_in_list("10.1.2.3", &s(&["10.1.2.3"])));
        assert!(!ip_in_list("10.1.2.4", &s(&["10.1.2.3"])));
    }
    #[test]
    fn ip_in_list_v6_and_cidr() {
        assert!(ip_in_list("2001:db8::1234", &s(&["2001:db8::/32"])));
        assert!(!ip_in_list("2001:db9::1", &s(&["2001:db8::/32"])));
        // families are never mixed
        assert!(!ip_in_list("1.2.3.4", &s(&["2001:db8::/32"])));
        assert!(!ip_in_list("2001:db8::1", &s(&["10.0.0.0/8"])));
    }
    #[test]
    fn ip_in_list_empty_and_bad() {
        assert!(!ip_in_list("1.2.3.4", &[]));
        assert!(!ip_in_list("not-an-ip", &s(&["0.0.0.0/0"])));
        // a garbage prefix neither panics nor matches
        assert!(!ip_in_list("1.2.3.4", &s(&["1.2.3.4/999"])));
    }
}
