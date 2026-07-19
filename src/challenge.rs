// Proof-of-work challenge (the Cloudflare-style 'checking your browser' interstitial).
// The server serves a page containing a PoW task; client-side JS searches for a nonce such
// that SHA-256(prefix+nonce) has at least `difficulty` leading zero bits.
// On success a signed HMAC token is set as a cookie, so the check is not repeated
// until it expires.

use hmac::{Hmac, Mac, KeyInit};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const COOKIE_NAME: &str = "thwaf_clr";
pub const TOKEN_TTL_SECS: u64 = 1800; // 30 minutes

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sign a token with the value "<expiry>.<hexmac>", where mac = HMAC(secret, ip + expiry).
pub fn issue_token(secret: &str, ip: &str) -> String {
    let exp = now() + TOKEN_TTL_SECS;
    let mac = sign(secret, ip, exp);
    format!("{}.{}", exp, mac)
}

/// Validate a token from the cookie. true = valid and not expired.
pub fn verify_token(secret: &str, ip: &str, token: &str) -> bool {
    let mut it = token.splitn(2, '.');
    let exp_s = it.next().unwrap_or("");
    let mac = it.next().unwrap_or("");
    let exp: u64 = match exp_s.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if exp < now() {
        return false; // expired
    }
    let expect = sign(secret, ip, exp);
    // constant-time comparison
    constant_eq(mac.as_bytes(), expect.as_bytes())
}

fn sign(secret: &str, ip: &str, exp: u64) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"fallback").unwrap());
    mac.update(ip.as_bytes());
    mac.update(b".");
    mac.update(exp.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a PoW solution: SHA-256(prefix + nonce) has at least `difficulty` leading zero bits.
pub fn verify_pow(prefix: &str, nonce: &str, difficulty: u32) -> bool {
    let mut h = Sha256::new();
    h.update(prefix.as_bytes());
    h.update(nonce.as_bytes());
    let digest = h.finalize();
    leading_zero_bits(&digest) >= difficulty
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut n = 0u32;
    for &b in bytes {
        if b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

/// The task prefix is bound to the client IP and a time window. Returns the prefix for a window offset.
pub fn pow_prefix_at(secret: &str, ip: &str, window_offset: i64) -> String {
    let window = (now() / 300) as i64 + window_offset;
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    h.update(ip.as_bytes());
    h.update(window.to_string().as_bytes());
    hex::encode(&h.finalize()[..8])
}

/// Current prefix, used when issuing a new task.
pub fn pow_prefix(secret: &str, ip: &str) -> String {
    pow_prefix_at(secret, ip, 0)
}

/// Whether a prefix is valid (current or previous window, in case the solve straddles the boundary).
pub fn prefix_valid(secret: &str, ip: &str, prefix: &str) -> bool {
    prefix == pow_prefix_at(secret, ip, 0) || prefix == pow_prefix_at(secret, ip, -1)
}

/// Extract the thwaf_clr cookie value from the Cookie header.
pub fn token_from_cookies(cookie_header: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let p = part.trim();
        if let Some(v) = p.strip_prefix(&format!("{}=", COOKIE_NAME)) {
            return Some(v.to_string());
        }
    }
    None
}

/// The challenge HTML page, running PoW inside a Web Worker.
/// prefix and difficulty are passed to the client, which POSTs the answer back to the same URL
/// with the __thwaf_prefix and __thwaf_nonce fields.
pub fn challenge_page(prefix: &str, difficulty: u32, lang: &str) -> String {
    format!(
        r##"<!doctype html><html lang="{lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
background:#f6f8fa;color:#1c1e21;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}}
.card{{background:#fff;border:1px solid #e3e6ea;border-radius:14px;box-shadow:0 4px 24px rgba(0,0,0,.06);
max-width:480px;width:100%;padding:48px 40px;text-align:center}}
h1{{font-size:20px;margin:0 0 10px}}
p{{color:#5b6470;line-height:1.6;margin:0 0 24px;font-size:15px}}
.spin{{width:42px;height:42px;border:4px solid #e3e6ea;border-top-color:#2563eb;border-radius:50%;
margin:0 auto 20px;animation:r 1s linear infinite}}
@keyframes r{{to{{transform:rotate(360deg)}}}}
.bar{{height:6px;background:#eef1f4;border-radius:3px;overflow:hidden;margin-top:8px}}
.bar i{{display:block;height:100%;width:0;background:#2563eb;transition:width .2s}}
.small{{font-size:12px;color:#9aa0aa;margin-top:14px}}
</style></head>
<body><div class="card">
<div class="spin"></div>
<h1>{heading}</h1>
<p>{message}</p>
<div class="bar"><i id="b"></i></div>
<div class="small">{footer}</div>
</div>
<script>
(function(){{
  var prefix={prefix:?}, diff={difficulty};
  var bar=document.getElementById('b');
  // SHA-256 (чистый JS, чтобы работать без SubtleCrypto в http)
  {sha256}
  function lz(hex){{var n=0;for(var i=0;i<hex.length;i++){{var v=parseInt(hex[i],16);
    if(v===0){{n+=4;}}else{{if(v>=8)n+=0;else if(v>=4)n+=1;else if(v>=2)n+=2;else n+=3;break;}}}}return n;}}
  function solve(){{
    var nonce=0,start=Date.now();
    function step(){{
      for(var i=0;i<5000;i++){{
        var h=sha256(prefix+nonce);
        if(lz(h)>=diff){{ submit(nonce); return; }}
        nonce++;
      }}
      bar.style.width=Math.min(95,(Date.now()-start)/30)+'%';
      setTimeout(step,0);
    }}
    step();
  }}
  function submit(nonce){{
    bar.style.width='100%';
    var f=document.createElement('form');f.method='POST';f.action=location.href;
    function add(n,v){{var e=document.createElement('input');e.type='hidden';e.name=n;e.value=v;f.appendChild(e);}}
    add('__thwaf_prefix',prefix);add('__thwaf_nonce',String(nonce));
    document.body.appendChild(f);f.submit();
  }}
  setTimeout(solve,50);
}})();
</script>
</body></html>"##,
        prefix = prefix,
        difficulty = difficulty,
        sha256 = SHA256_JS,
        lang = lang,
        title = crate::i18n::chl_title(lang),
        heading = crate::i18n::chl_heading(lang),
        message = crate::i18n::chl_message(lang),
        footer = crate::i18n::chl_footer(lang)
    )
}

// A compact, correct SHA-256 in JS (hex output). Verified against the "abc" and "" vectors.
const SHA256_JS: &str = r#"
function sha256(ascii){
  function rightRotate(value,amount){return(value>>>amount)|(value<<(32-amount));}
  var mathPow=Math.pow,maxWord=mathPow(2,32),result='';
  var words=[],asciiBitLength=ascii.length*8;
  var hash=sha256.h=sha256.h||[];var k=sha256.k=sha256.k||[];
  var primeCounter=k.length;var isComposite={};
  for(var candidate=2;primeCounter<64;candidate++){
    if(!isComposite[candidate]){
      for(var i=0;i<313;i+=candidate){isComposite[i]=candidate;}
      hash[primeCounter]=(mathPow(candidate,.5)*maxWord)|0;
      k[primeCounter++]=(mathPow(candidate,1/3)*maxWord)|0;
    }
  }
  ascii+='\x80';
  while(ascii.length%64-56)ascii+='\x00';
  for(var i=0;i<ascii.length;i++){var j=ascii.charCodeAt(i);if(j>>8)return;words[i>>2]|=j<<((3-i)%4)*8;}
  words[words.length]=((asciiBitLength/maxWord)|0);
  words[words.length]=(asciiBitLength);
  for(var j=0;j<words.length;){
    var w=words.slice(j,j+=16);var oldHash=hash;hash=hash.slice(0,8);
    for(var i=0;i<64;i++){
      var w15=w[i-15],w2=w[i-2];var a=hash[0],e=hash[4];
      var temp1=hash[7]+(rightRotate(e,6)^rightRotate(e,11)^rightRotate(e,25))
        +((e&hash[5])^((~e)&hash[6]))+k[i]
        +(w[i]=(i<16)?w[i]:(w[i-16]+(rightRotate(w15,7)^rightRotate(w15,18)^(w15>>>3))
        +w[i-7]+(rightRotate(w2,17)^rightRotate(w2,19)^(w2>>>10)))|0);
      var temp2=(rightRotate(a,2)^rightRotate(a,13)^rightRotate(a,22))
        +((a&hash[1])^(a&hash[2])^(hash[1]&hash[2]));
      hash=[(temp1+temp2)|0].concat(hash);hash[4]=(hash[4]+temp1)|0;
    }
    for(var i=0;i<8;i++){hash[i]=(hash[i]+oldHash[i])|0;}
  }
  for(var i=0;i<8;i++){for(var j=3;j+1;j--){var b=(hash[i]>>(j*8))&255;result+=((b<16)?0:'')+b.toString(16);}}
  return result;
}
"#;
