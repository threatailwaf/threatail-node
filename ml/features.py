"""
Unified v2 (per-part) feature extractor for the supervised ML model (LightGBM).

STRICTLY mirrors node/src/features.rs. Any divergence breaks inference on the node:
FEATURE_VERSION and the feature order MUST match. Parity is verified by running
against node/src/golden.json (python features.py).

v2: the signal features (kw_*, special characters, entropy, angle brackets, quotes)
are computed SEPARATELY for path, query and body, which localises detections per part.
The global block holds lengths, ratios and aggregates.

No dependencies; pure Python from the standard library.
"""
from __future__ import annotations
import math

FEATURE_VERSION = 5  # v5: adds expand_base64, a port of verdict.rs that expands long base64 tokens
N_FEATURES = 36

KW_SQL = [
    "union", "select", "insert", "update", "delete", "drop", "from", "where",
    "or 1=1", "sleep(", "benchmark(", "'--", "' or ", "waitfor", "xp_",
    "information_schema",
]
KW_XSS = [
    "<script", "javascript:", "onerror", "onload", "onmouseover", "<svg",
    "<img", "document.cookie", "alert(", "eval(", "fromcharcode",
]
KW_PATH = [
    "../", "..\\", "%2e%2e", "/etc/passwd", "/proc/", "php://", "file://",
    "/windows/win.ini", "/.git", "/.env",
]
KW_CMD = [
    ";cat ", ";ls ", ";id", "|cat ", "`", "$(", "&&", "wget ", "curl ",
    "nc ", "/bin/sh", "/bin/bash", "${jndi:",
]

_PART = ["path", "query", "body"]
FEATURE_NAMES = [
    # global features (10)
    "len_path", "len_query", "len_body", "n_params", "n_segments",
    "kw_total", "entropy_total", "ratio_special_total", "ratio_digits_total", "ratio_upper_total",
]
for _p in _PART:  # 8 per part (24)
    FEATURE_NAMES += [
        f"kw_sql_{_p}", f"kw_xss_{_p}", f"kw_path_{_p}", f"kw_cmd_{_p}",
        f"ratio_special_{_p}", f"entropy_{_p}", f"n_angle_{_p}", f"n_quote_{_p}",
    ]
# v3: injection detector (siginj) verdicts over the whole payload, as 0/1
FEATURE_NAMES += ["det_sqli", "det_xss"]
assert len(FEATURE_NAMES) == N_FEATURES, (len(FEATURE_NAMES), N_FEATURES)


def _hex_val(c: int):
    if 0x30 <= c <= 0x39:
        return c - 0x30
    if 0x61 <= c <= 0x66:
        return c - 0x61 + 10
    if 0x41 <= c <= 0x46:
        return c - 0x41 + 10
    return None


def percent_decode(s: str) -> str:
    b = s.encode("utf-8", "replace")
    out = bytearray()
    i, n = 0, len(b)
    while i < n:
        if b[i] == 0x25 and i + 2 < n:        # '%' plus 2 characters
            h = _hex_val(b[i + 1]); l = _hex_val(b[i + 2])
            if h is not None and l is not None:
                out.append((h << 4) | l); i += 3; continue
        if b[i] == 0x2B:                       # '+'
            out.append(0x20)
        else:
            out.append(b[i])
        i += 1
    return out.decode("utf-8", "replace")


# ─── v4: payload normalisation before feature extraction (anti encoding-bypass) ───
# MIRRORS node/src/features.rs (recursive_percent_decode / html_decode / normalize).
# Any divergence breaks inference; parity is checked by golden.json plus cargo test.

def _recursive_percent_decode(s: str, max_passes: int = 3) -> str:
    """Percent-decode until stable (double or triple encoding), capped at max_passes."""
    for _ in range(max_passes):
        d = percent_decode(s)
        if d == s:
            break
        s = d
    return s


# minimal fixed table of named entities (ASCII keys; the same set as in Rust)
_HTML_ENT = {"lt": "<", "gt": ">", "amp": "&", "quot": "\"", "apos": "'"}


def _is_dec(s: str) -> bool:
    return len(s) > 0 and all("0" <= c <= "9" for c in s)


def _is_hex(s: str) -> bool:
    return len(s) > 0 and all(c in "0123456789abcdefABCDEF" for c in s)


def _html_decode(s: str) -> str:
    """Decode &lt;/&gt;/&amp;/&quot;/&apos; and numeric &#DDD; / &#xHH;. Everything else is left as is.
    The code point range follows char::from_u32 in Rust (<=0x10FFFF, no surrogates)."""
    if "&" not in s:
        return s
    out = []
    i, n = 0, len(s)
    while i < n:
        if s[i] == "&":
            end = min(n, i + 12)
            semi = -1
            j = i + 1
            while j < end:
                if s[j] == ";":
                    semi = j
                    break
                j += 1
            if semi != -1:
                ent = s[i + 1:semi]
                dec = None
                if ent[:1] == "#":
                    num = ent[1:]
                    cp = None
                    if num[:1] in ("x", "X"):
                        if _is_hex(num[1:]):
                            cp = int(num[1:], 16)
                    elif _is_dec(num):
                        cp = int(num)
                    if cp is not None and cp <= 0x10FFFF and not (0xD800 <= cp <= 0xDFFF):
                        dec = chr(cp)
                elif ent in _HTML_ENT:
                    dec = _HTML_ENT[ent]
                if dec is not None:
                    out.append(dec)
                    i = semi + 1
                    continue
        out.append(s[i])
        i += 1
    return "".join(out)


def normalize(s: str) -> str:
    """Unwrap encodings before feature extraction: percent (recursive) -> HTML -> percent -> base64."""
    s = _recursive_percent_decode(s)
    s = _html_decode(s)
    s = _recursive_percent_decode(s)
    s = _expand_base64(s)
    return s


# ─── v5: expanding long base64 tokens — an EXACT PORT of node/src/verdict.rs ───
# (b64_is / b64_val / b64_decode / expand_base64). The decode is APPENDED to the string (the original
# is not replaced), conservatively: core length 20..1024, at least 80% printable, budget of 8 tokens.
def _b64_is(c: int) -> bool:
    return (0x41 <= c <= 0x5A) or (0x61 <= c <= 0x7A) or (0x30 <= c <= 0x39) \
        or c in (0x2B, 0x2F, 0x2D, 0x5F)  # + / - _


def _b64_val(c: int):
    if 0x41 <= c <= 0x5A:
        return c - 0x41
    if 0x61 <= c <= 0x7A:
        return c - 0x61 + 26
    if 0x30 <= c <= 0x39:
        return c - 0x30 + 52
    if c in (0x2B, 0x2D):
        return 62
    if c in (0x2F, 0x5F):
        return 63
    return None


def _b64_decode(bs: bytes):
    out = bytearray()
    buf = 0
    bits = 0
    for c in bs:
        if c == 0x3D:  # '='
            break
        v = _b64_val(c)
        if v is None:
            return None
        buf = (buf << 6) | v
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
    return bytes(out)


def _expand_base64(s: str) -> str:
    b = s.encode("utf-8")
    n = len(b)
    extra = []
    i = 0
    budget = 8
    while i < n and budget > 0:
        if _b64_is(b[i]):
            start = i
            while i < n and _b64_is(b[i]):
                i += 1
            core = i - start
            end = i
            while end < n and b[end] == 0x3D:
                end += 1
            if 20 <= core <= 1024:
                dec = _b64_decode(b[start:end])
                if dec is not None and len(dec) > 0:
                    printable = sum(1 for c in dec if c in (9, 10, 13) or 32 <= c <= 126)
                    if printable * 100 // len(dec) >= 80:
                        extra.append("\n")
                        extra.append(dec.decode("utf-8", "replace"))
                        budget -= 1
            i = end
        else:
            i += 1
    if not extra:
        return s
    return s + "".join(extra)


def _count_substr(hay: str, needle: str) -> int:
    if not needle:
        return 0
    n, start = 0, 0
    while True:
        pos = hay.find(needle, start)
        if pos < 0:
            break
        n += 1
        start = pos + len(needle)
        if start >= len(hay):
            break
    return n


def _kw_hits(low: str, dict_) -> int:
    return sum(_count_substr(low, k) for k in dict_)


def _shannon_entropy(s: str) -> float:
    """Over UTF-8 BYTES (matching Rust's s.bytes()), base 2."""
    if not s:
        return 0.0
    data = s.encode("utf-8", "replace")
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    total = float(len(data))
    e = 0.0
    for f in freq:
        if f > 0:
            p = f / total
            e -= p * math.log2(p)
    return e


def _char_stats(s: str):
    """special, digits, alpha and upper counts per character (ASCII classes, as in Rust)."""
    special = digits = alpha = upper = 0
    for c in s:
        o = ord(c)
        if 0x30 <= o <= 0x39:
            digits += 1
        elif (0x41 <= o <= 0x5A) or (0x61 <= o <= 0x7A):
            alpha += 1
            if 0x41 <= o <= 0x5A:
                upper += 1
        elif c not in (" ", "_", "-", ".", "/"):
            special += 1
    return special, digits, alpha, upper


def _part_features(s: str):
    """8 signal features for a part plus the keyword sum (for kw_total). Returns (list[8], kw_sum)."""
    low = s.lower()
    kw_sql = _kw_hits(low, KW_SQL)
    kw_xss = _kw_hits(low, KW_XSS)
    kw_path = _kw_hits(low, KW_PATH)
    kw_cmd = _kw_hits(low, KW_CMD)
    sp, _dg, _al, _up = _char_stats(s)
    tc = float(max(len(s), 1))
    ratio_special = sp / tc
    entropy = _shannon_entropy(s)
    n_angle = float(s.count("<") + s.count(">"))
    n_quote = float(s.count("'") + s.count('"'))
    feats = [float(kw_sql), float(kw_xss), float(kw_path), float(kw_cmd),
             ratio_special, entropy, n_angle, n_quote]
    return feats, (kw_sql + kw_xss + kw_path + kw_cmd)


# ─── siginj (injection detector) — mirrors node/src/siginj.rs ───
# The verdict MUST match Rust, otherwise the det_* features diverge between training and serving.
_SIG_KW = {
    "union","select","from","insert","into","update","delete","drop","table","database",
    "or","and","like","sleep","benchmark","waitfor","pg_sleep","load_file","outfile",
    "information_schema","extractvalue","updatexml","exec","execute",
}
_SIG_OPCH = set("=<>!+-*/%|&^~")
_SIG_CMP = {"=","<",">","<>","!=",">=","<=","=="}


def _sig_tokenize(s, start_in=None):
    n = len(s); out = []; i = 0
    if start_in is not None:
        j = 0; found = False
        while j < n:
            if s[j] == '\\': j += 2; continue
            if s[j] == start_in: found = True; break
            j += 1
        if not found: return out
        out.append(("str", False)); i = j + 1
    while i < n:
        c = s[i]
        if c in (' ', '\t', '\n', '\r'): i += 1; continue
        if c in ("'", '"', '`'):
            i += 1
            while i < n and s[i] != c:
                if s[i] == '\\': i += 2; continue
                i += 1
            i += 1; out.append(("str", False)); continue
        if c.isdigit():
            j = i
            while j < n and (s[j].isalnum() or s[j] == '.'): j += 1
            i = j; out.append(("num", False)); continue
        if (c == '-' and i + 1 < n and s[i + 1] == '-') or c == '#':
            while i < n and s[i] != '\n': i += 1
            out.append(("comment", False)); continue
        if c == '/' and i + 1 < n and s[i + 1] == '*':
            i += 2
            while i + 1 < n and not (s[i] == '*' and s[i + 1] == '/'): i += 1
            i += 2; out.append(("comment", False)); continue
        if c in _SIG_OPCH:
            st = i; j = i
            while j < n and s[j] in _SIG_OPCH: j += 1
            out.append(("op", s[st:j] in _SIG_CMP)); i = j; continue
        if c == '(': out.append(("lp", False)); i += 1; continue
        if c == ')': out.append(("rp", False)); i += 1; continue
        if c == ',': out.append(("comma", False)); i += 1; continue
        if c == ';': out.append(("semi", False)); i += 1; continue
        if c == '.': out.append(("dot", False)); i += 1; continue
        if c.isalpha() or c == '_':
            st = i; j = i
            while j < n and (s[j].isalnum() or s[j] == '_'): j += 1
            w = s[st:j]; i = j
            out.append(("kw", w) if w in _SIG_KW else ("word", False)); continue
        out.append(("other", False)); i += 1
    return out


def _sig_is_lit(t): return t[0] in ("str", "num", "word")
def _sig_is_cmp(t): return (t[0] == "op" and t[1]) or (t[0] == "kw" and t[1] == "like")
def _sig_has_kw(t, k): return any(x[0] == "kw" and x[1] == k for x in t)


def _sig_adj(t, a, b, gap=2):
    for i, x in enumerate(t):
        if x[0] == "kw" and x[1] == a:
            for y in t[i + 1:i + 1 + gap]:
                if y[0] == "kw" and y[1] == b: return True
    return False


def _sig_detect_ctx(t, broke):
    if _sig_adj(t, "union", "select"): return True
    for k in ("sleep", "benchmark", "waitfor", "pg_sleep", "load_file", "outfile",
              "information_schema", "extractvalue", "updatexml"):
        if _sig_has_kw(t, k): return True
    for i, x in enumerate(t):
        if x[0] == "semi":
            for y in t[i + 1:i + 3]:
                if y[0] == "kw" and y[1] in ("select", "insert", "update", "delete", "drop", "exec", "execute"):
                    return True
    if _sig_adj(t, "drop", "table") or _sig_adj(t, "drop", "database"): return True
    if _sig_adj(t, "insert", "into"): return True
    if _sig_adj(t, "delete", "from"): return True
    if len(t) >= 3:
        for i in range(len(t) - 2):
            if _sig_is_lit(t[i]) and _sig_is_cmp(t[i + 1]) and _sig_is_lit(t[i + 2]):
                near = i > 0 and t[i - 1][0] == "kw" and t[i - 1][1] in ("or", "and")
                if broke or near: return True
    if broke and any(x[0] == "comment" for x in t): return True
    if _sig_has_kw(t, "select") and _sig_has_kw(t, "from"):
        has_cmp = any(x[0] == "op" and x[1] for x in t)
        if has_cmp or any(x[0] == "comment" for x in t) or any(x[0] == "semi" for x in t) or _sig_has_kw(t, "union"):
            return True
    return False


def is_sqli(s: str) -> bool:
    if not s: return False
    low = s.lower()
    for start, broke in ((None, False), ("'", True), ('"', True)):
        if _sig_detect_ctx(_sig_tokenize(low, start), broke): return True
    return False


_XSS_TAGS = {"script", "iframe", "object", "embed", "svg", "base", "applet",
             "frameset", "isindex", "meta", "math"}
_XSS_EVENTS = {
    "onload", "onerror", "onclick", "onmouseover", "onmouseenter", "onmouseout",
    "onfocus", "onblur", "onsubmit", "onchange", "onkeydown", "onkeyup", "onkeypress",
    "ontoggle", "onanimationstart", "onanimationend", "onpointerover", "onwheel",
    "onbegin", "onfinish", "onstart", "onmousemove", "onresize", "onscroll", "onplay",
    "onpageshow", "onhashchange", "onauxclick", "oncontextmenu",
}


def is_xss(s: str) -> bool:
    if not s: return False
    low = s.lower()
    if "javascript:" in low or "vbscript:" in low: return True
    if "fromcharcode" in low: return True
    if "data:" in low and "text/html" in low: return True
    n = len(low); i = 0
    while i < n:
        if low[i] == '<':
            j = i + 1
            while j < n and low[j] in ' /\t': j += 1
            st = j
            while j < n and (low[j].isalpha() or (j > st and low[j].isdigit())): j += 1
            if j > st and low[st:j] in _XSS_TAGS: return True
        i += 1
    i = 0
    while i + 2 < n:
        if low[i:i + 2] == "on" and (i == 0 or not low[i - 1].isalnum()):
            j = i + 2
            while j < n and low[j].isalpha(): j += 1
            ne = j
            while j < n and low[j] in ' \t': j += 1
            if ne > i + 2 and j < n and low[j] == '=' and low[i:ne] in _XSS_EVENTS: return True
        i += 1
    return False


def extract(path: str, query: str, body: str):
    dpath = normalize(path)
    dquery = normalize(query)
    dbody = normalize(body)
    payload = f"{dpath} {dquery} {dbody}"

    def count_params(s):
        return sum(1 for p in s.split("&") if p)

    n_params = float(count_params(dquery) + count_params(dbody))
    n_segments = float(sum(1 for x in dpath.split("/") if x))

    sp, dg, al, up = _char_stats(payload)
    tc = float(max(len(payload), 1))
    ratio_special_total = sp / tc
    ratio_digits_total = dg / tc
    ratio_upper_total = (up / al) if al > 0 else 0.0
    entropy_total = _shannon_entropy(payload)

    pf_path, kwp = _part_features(dpath)
    pf_query, kwq = _part_features(dquery)
    pf_body, kwb = _part_features(dbody)
    kw_total = float(kwp + kwq + kwb)

    glob = [
        float(len(dpath)), float(len(dquery)), float(len(dbody)), n_params, n_segments,
        kw_total, entropy_total, ratio_special_total, ratio_digits_total, ratio_upper_total,
    ]
    # v3: injection detector verdicts over the whole payload (0/1)
    det = [1.0 if is_sqli(payload) else 0.0, 1.0 if is_xss(payload) else 0.0]
    return glob + pf_path + pf_query + pf_body + det


# v4: new decoding cases for golden (double percent, HTML entities, mixed)
_NEW_CASES = [
    {"path": "/p", "query": "q=%2553ELECT", "body": ""},                       # double-url → SELECT
    {"path": "/a%252e%252e%252fetc%252fpasswd", "query": "", "body": ""},       # double-url traversal
    {"path": "/", "query": "q=&lt;script&gt;alert(1)&lt;/script&gt;", "body": ""},
    {"path": "/", "query": "q=&#60;script&#62;", "body": ""},                   # numeric entity
    {"path": "/", "query": "q=&#x3c;svg/onload=alert(1)&#x3e;", "body": ""},    # hex entity
    {"path": "/", "query": "x=%26lt%3Bscript%26gt%3B", "body": ""},            # percent→entity→<script>
    {"path": "/", "query": "q=YWxlcnQoZG9jdW1lbnQuY29va2llKQ==", "body": ""},   # base64(alert(document.cookie))
    {"path": "/", "query": "d=JyBVTklPTiBTRUxFQ1QgcGFzc3dvcmQgRlJPTSB1c2VycyB3aGVyZSBpZD0xLS0=", "body": ""},  # base64(SQLi)
    {"path": "/", "query": "", "body": "p=PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg=="},  # base64(<img onerror>) in the body
]


def _regen_golden(path):
    import json
    try:
        cases = json.load(open(path, encoding="utf-8"))
        inputs = [{"path": c["path"], "query": c["query"], "body": c["body"]} for c in cases]
    except (OSError, ValueError):
        inputs = []
    seen = {(i["path"], i["query"], i["body"]) for i in inputs}
    for c in _NEW_CASES:
        k = (c["path"], c["query"], c["body"])
        if k not in seen:
            inputs.append(dict(c)); seen.add(k)
    out = [{**c, "features": extract(c["path"], c["query"], c["body"])} for c in inputs]
    json.dump(out, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"golden.json regenerated: {len(out)} cases -> {path}")


if __name__ == "__main__":
    import json, os, sys
    here = os.path.dirname(os.path.abspath(__file__))
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    default_golden = os.path.join(here, "..", "src", "golden.json")
    golden = args[0] if args else default_golden

    if "--gen" in sys.argv:
        _regen_golden(golden)
        sys.exit(0)

    cases = json.load(open(golden, encoding="utf-8"))
    ok = True
    for i, c in enumerate(cases):
        got = extract(c["path"], c["query"], c["body"])
        if len(c["features"]) != N_FEATURES:
            ok = False; print(f"FAIL case {i}: golden has {len(c['features'])} features, expected {N_FEATURES}")
            continue
        for j, (g, e) in enumerate(zip(got, c["features"])):
            if abs(g - e) > 1e-9:
                ok = False; print(f"FAIL case {i} feature {j} ({FEATURE_NAMES[j]}): {g} != {e}")
    print("features.py matches golden.json" if ok else "MISMATCH")
    sys.exit(0 if ok else 1)
