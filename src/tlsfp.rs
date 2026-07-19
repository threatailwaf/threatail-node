// TLS fingerprinting (JA3 / JA4) from a raw ClientHello.
//
// Performance: called ONCE per TLS connection on the peeked buffer,
// not per request. The parser is strictly length-checked: the ClientHello is attacker-
// controlled, so malformed data must never panic; any shortfall of bytes yields None.
//
// JA3 = md5(version,ciphers,extensions,curves,point_formats). JA4 is the FoxIO format (TLS/TCP).
// GREASE values (RFC 8701) are excluded from every list.

use sha2::{Digest, Sha256};

pub struct Fp {
    pub ja3: String, // md5 hex
    pub ja4: String,
    pub grease: bool, // whether GREASE values (RFC 8701) were present — real browsers send them
}

struct Hello {
    legacy_version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    groups: Vec<u16>,
    point_formats: Vec<u8>,
    sig_algs: Vec<u16>,
    alpns: Vec<String>,
    sni: bool,
    sup_versions: Vec<u16>,
    grease: bool,
}

#[inline]
fn is_grease(v: u16) -> bool {
    let b = (v & 0xff) as u8;
    ((v >> 8) as u8) == b && (b & 0x0f) == 0x0a
}

/// Bounds-checked cursor over the buffer; never panics.
struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self { Cur { b, i: 0 } }
    fn rem(&self) -> usize { self.b.len().saturating_sub(self.i) }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.i)?;
        self.i += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        if self.rem() < 2 { return None; }
        let v = ((self.b[self.i] as u16) << 8) | self.b[self.i + 1] as u16;
        self.i += 2;
        Some(v)
    }
    fn u24(&mut self) -> Option<usize> {
        if self.rem() < 3 { return None; }
        let v = ((self.b[self.i] as usize) << 16) | ((self.b[self.i + 1] as usize) << 8) | self.b[self.i + 2] as usize;
        self.i += 3;
        Some(v)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        if self.rem() < n { return None; }
        self.i += n;
        Some(())
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.rem() < n { return None; }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Some(s)
    }
}

fn parse_hello(raw: &[u8]) -> Option<Hello> {
    let mut c = Cur::new(raw);
    // TLS record header
    if c.u8()? != 0x16 { return None; } // handshake
    c.skip(2)?;                          // record version
    let rec_len = c.u16()? as usize;
    // handshake header (within a single record; a fragmented ClientHello is skipped)
    let hs = c.take(rec_len.min(c.rem()))?;
    let mut h = Cur::new(hs);
    if h.u8()? != 0x01 { return None; }  // ClientHello
    let body_len = h.u24()?;
    let body = h.take(body_len.min(h.rem()))?;
    let mut p = Cur::new(body);

    let legacy_version = p.u16()?;
    p.skip(32)?;                         // random
    let sid = p.u8()? as usize; p.skip(sid)?; // session id

    let cs_len = p.u16()? as usize;
    let cs = p.take(cs_len)?;
    let mut ciphers = Vec::new();
    let mut grease = false;
    let mut k = 0;
    while k + 1 < cs.len() {
        let v = ((cs[k] as u16) << 8) | cs[k + 1] as u16;
        if is_grease(v) { grease = true; } else { ciphers.push(v); }
        k += 2;
    }

    let comp = p.u8()? as usize; p.skip(comp)?; // compression methods

    let mut extensions = Vec::new();
    let mut groups = Vec::new();
    let mut point_formats = Vec::new();
    let mut sig_algs = Vec::new();
    let mut alpns = Vec::new();
    let mut sni = false;
    let mut sup_versions = Vec::new();

    // the extensions block may be absent, in which case we proceed without it
    if let Some(ext_total) = p.u16() {
        let ext_total = ext_total as usize;
        let ext_buf = p.take(ext_total.min(p.rem()))?;
        let mut e = Cur::new(ext_buf);
        while e.rem() >= 4 {
            let etype = e.u16()?;
            let elen = e.u16()? as usize;
            let edata = e.take(elen.min(e.rem()))?;
            if is_grease(etype) { grease = true; } else { extensions.push(etype); }
            match etype {
                0x0000 => sni = true, // server_name
                0x000a => {           // supported_groups
                    let mut d = Cur::new(edata);
                    if let Some(ll) = d.u16() {
                        let list = d.take((ll as usize).min(d.rem())).unwrap_or(&[]);
                        let mut j = 0;
                        while j + 1 < list.len() {
                            let v = ((list[j] as u16) << 8) | list[j + 1] as u16;
                            if !is_grease(v) { groups.push(v); }
                            j += 2;
                        }
                    }
                }
                0x000b => {           // ec_point_formats
                    let mut d = Cur::new(edata);
                    if let Some(ll) = d.u8() {
                        let list = d.take((ll as usize).min(d.rem())).unwrap_or(&[]);
                        point_formats.extend_from_slice(list);
                    }
                }
                0x000d => {           // signature_algorithms
                    let mut d = Cur::new(edata);
                    if let Some(ll) = d.u16() {
                        let list = d.take((ll as usize).min(d.rem())).unwrap_or(&[]);
                        let mut j = 0;
                        while j + 1 < list.len() {
                            sig_algs.push(((list[j] as u16) << 8) | list[j + 1] as u16);
                            j += 2;
                        }
                    }
                }
                0x0010 => {           // ALPN
                    let mut d = Cur::new(edata);
                    if let Some(_ll) = d.u16() {
                        while d.rem() >= 1 {
                            let pl = d.u8()? as usize;
                            match d.take(pl.min(d.rem())) {
                                Some(s) => alpns.push(String::from_utf8_lossy(s).into_owned()),
                                None => break,
                            }
                        }
                    }
                }
                0x002b => {           // supported_versions
                    let mut d = Cur::new(edata);
                    if let Some(ll) = d.u8() {
                        let list = d.take((ll as usize).min(d.rem())).unwrap_or(&[]);
                        let mut j = 0;
                        while j + 1 < list.len() {
                            let v = ((list[j] as u16) << 8) | list[j + 1] as u16;
                            if !is_grease(v) { sup_versions.push(v); }
                            j += 2;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Some(Hello { legacy_version, ciphers, extensions, groups, point_formats, sig_algs, alpns, sni, sup_versions, grease })
}

fn ja3(h: &Hello) -> String {
    let join = |v: &[u16]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-");
    let pf = h.point_formats.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-");
    let s = format!("{},{},{},{},{}", h.legacy_version, join(&h.ciphers), join(&h.extensions), join(&h.groups), pf);
    md5_hex(s.as_bytes())
}

fn sha256_12(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let out = hasher.finalize();
    let hex: String = out.iter().map(|b| format!("{:02x}", b)).collect();
    hex[..12].to_string()
}

fn alpn_code(alpns: &[String]) -> String {
    match alpns.iter().find(|a| !a.is_empty()) {
        Some(a) => {
            let b = a.as_bytes();
            format!("{}{}", b[0] as char, b[b.len() - 1] as char)
        }
        None => "00".to_string(),
    }
}

fn ja4(h: &Hello) -> String {
    let ver = match h.sup_versions.iter().copied().max().unwrap_or(0) {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => match h.legacy_version {
            0x0304 => "13", 0x0303 => "12", 0x0302 => "11", 0x0301 => "10",
            _ => "00",
        },
    };
    let sni = if h.sni { 'd' } else { 'i' };
    let cc = format!("{:02}", h.ciphers.len().min(99));
    let ec = format!("{:02}", h.extensions.len().min(99));
    let a = format!("t{}{}{}{}{}", ver, sni, cc, ec, alpn_code(&h.alpns));

    let mut cs: Vec<String> = h.ciphers.iter().map(|c| format!("{:04x}", c)).collect();
    cs.sort();
    let b = sha256_12(&cs.join(","));

    // extensions for the hash: SNI (0x0000) and ALPN (0x0010) excluded, sorted
    let mut exts: Vec<String> = h.extensions.iter().filter(|e| **e != 0x0000 && **e != 0x0010).map(|e| format!("{:04x}", e)).collect();
    exts.sort();
    let sig: Vec<String> = h.sig_algs.iter().map(|s| format!("{:04x}", s)).collect();
    let cinput = if sig.is_empty() { exts.join(",") } else { format!("{}_{}", exts.join(","), sig.join(",")) };
    let cc2 = sha256_12(&cinput);

    format!("{}_{}_{}", a, b, cc2)
}

/// Entry point: peeked ClientHello bytes -> (JA3, JA4). None if truncated or not a ClientHello.
pub fn fingerprint(raw: &[u8]) -> Option<Fp> {
    let h = parse_hello(raw)?;
    if h.ciphers.is_empty() { return None; }
    Some(Fp { ja3: ja3(&h), ja4: ja4(&h), grease: h.grease })
}

// ───────────────────────── MD5 (self-contained, for JA3) ─────────────────────────
// RFC 1321. Dependency-free to avoid pulling extra crates into the hot path.

fn md5_hex(input: &[u8]) -> String {
    let d = md5(input);
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

fn md5(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];
    let (mut a0, mut b0, mut c0, mut d0): (u32, u32, u32, u32) = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);

    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (j, w) in m.iter_mut().enumerate() {
            let o = j * 4;
            *w = u32::from_le_bytes([chunk[o], chunk[o + 1], chunk[o + 2], chunk[o + 3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = if i < 16 {
                ((b & c) | (!b & d), i)
            } else if i < 32 {
                ((d & b) | (!d & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | !d), (7 * i) % 16)
            };
            let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(md5_hex(b"The quick brown fox jumps over the lazy dog"), "9e107d9d372bb6826bd81d3542a419d6");
        assert_eq!(md5_hex(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"), "57edf4a22be3c955ac49da2e2107b67a");
    }

    #[test]
    fn grease() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xdada));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0xc02f));
    }

    #[test]
    fn garbage_no_panic() {
        assert!(fingerprint(&[]).is_none());
        assert!(fingerprint(&[0x16, 0x03, 0x01]).is_none());
        assert!(fingerprint(&[0x17; 50]).is_none()); // not a handshake
        let mut junk = vec![0x16, 0x03, 0x01, 0x00, 0xff];
        junk.extend_from_slice(&[0xaa; 20]);
        assert!(fingerprint(&junk).is_none()); // truncated ClientHello -> None, no panic
    }
}
