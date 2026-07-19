// Pure-Rust injection detector (SQLi / XSS) following the libinjection approach:
// tokenise, then fingerprint the structure rather than matching raw regexes. High precision,
// low false positives: it reacts to SQL/HTML STRUCTURE, not to individual scary-looking words.
//
// No external dependencies and no C. Operates on the decoded string (any_norm).
// SQLi is parsed in three contexts: as-is, and as if already inside a ' or " string,
// which catches quote-breaking payloads (' or '1'='1, admin'--, and so on).

#[derive(Clone, Copy, PartialEq)]
enum Kw {
    Union, Select, From, Insert, Into, Update, Delete, Drop, Table, Database,
    Or, And, Like, Sleep, Benchmark, Waitfor, PgSleep, LoadFile, Outfile,
    InfoSchema, Extractvalue, Updatexml, Exec, Execute,
}

fn kw_of(w: &str) -> Option<Kw> {
    Some(match w {
        "union" => Kw::Union, "select" => Kw::Select, "from" => Kw::From,
        "insert" => Kw::Insert, "into" => Kw::Into, "update" => Kw::Update,
        "delete" => Kw::Delete, "drop" => Kw::Drop, "table" => Kw::Table,
        "database" => Kw::Database, "or" => Kw::Or, "and" => Kw::And, "like" => Kw::Like,
        "sleep" => Kw::Sleep, "benchmark" => Kw::Benchmark, "waitfor" => Kw::Waitfor,
        "pg_sleep" => Kw::PgSleep, "load_file" => Kw::LoadFile, "outfile" => Kw::Outfile,
        "information_schema" => Kw::InfoSchema, "extractvalue" => Kw::Extractvalue,
        "updatexml" => Kw::Updatexml, "exec" => Kw::Exec, "execute" => Kw::Execute,
        _ => return None,
    })
}

#[derive(Clone, Copy, PartialEq)]
enum Tok { Str, Num, Op(bool /*is_cmp*/), Comma, LParen, RParen, Semi, Dot, Comment, Word, Other, K(Kw) }

const OPCH: &[u8] = b"=<>!+-*/%|&^~";

fn tokenize(s: &str, start_in: Option<u8>) -> Vec<Tok> {
    let b = s.as_bytes();
    let n = b.len();
    let mut out: Vec<Tok> = Vec::new();
    let mut i = 0usize;

    // 'already inside a string' context: everything up to the first such quote is a string literal
    if let Some(q) = start_in {
        let mut j = 0usize;
        let mut found = false;
        while j < n {
            if b[j] == b'\\' { j += 2; continue; }
            if b[j] == q { found = true; break; }
            j += 1;
        }
        if !found { return out; } // no quote, so the whole input is one string
        out.push(Tok::Str);
        i = j + 1;
    }

    while i < n {
        let c = b[i];
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' { i += 1; continue; }
        // string literal
        if c == b'\'' || c == b'"' || c == b'`' {
            i += 1;
            while i < n && b[i] != c {
                if b[i] == b'\\' { i += 2; continue; }
                i += 1;
            }
            i += 1; out.push(Tok::Str); continue;
        }
        // number
        if c.is_ascii_digit() {
            let mut j = i;
            while j < n && (b[j].is_ascii_alphanumeric() || b[j] == b'.') { j += 1; }
            i = j; out.push(Tok::Num); continue;
        }
        // comments -- ... , # ... , /* ... */
        if (c == b'-' && i + 1 < n && b[i + 1] == b'-') || c == b'#' {
            while i < n && b[i] != b'\n' { i += 1; }
            out.push(Tok::Comment); continue;
        }
        if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < n && !(b[i] == b'*' && b[i + 1] == b'/') { i += 1; }
            i += 2; out.push(Tok::Comment); continue;
        }
        // operators
        if OPCH.contains(&c) {
            let st = i;
            let mut j = i;
            while j < n && OPCH.contains(&b[j]) { j += 1; }
            let op = &s[st..j];
            let is_cmp = matches!(op, "=" | "<" | ">" | "<>" | "!=" | ">=" | "<=" | "==");
            out.push(Tok::Op(is_cmp));
            i = j; continue;
        }
        match c {
            b'(' => { out.push(Tok::LParen); i += 1; continue; }
            b')' => { out.push(Tok::RParen); i += 1; continue; }
            b',' => { out.push(Tok::Comma); i += 1; continue; }
            b';' => { out.push(Tok::Semi); i += 1; continue; }
            b'.' => { out.push(Tok::Dot); i += 1; continue; }
            _ => {}
        }
        // word / keyword
        if c.is_ascii_alphabetic() || c == b'_' {
            let st = i;
            let mut j = i;
            while j < n && (b[j].is_ascii_alphanumeric() || b[j] == b'_') { j += 1; }
            let w = &s[st..j];
            i = j;
            match kw_of(w) { Some(k) => out.push(Tok::K(k)), None => out.push(Tok::Word) }
            continue;
        }
        out.push(Tok::Other); i += 1;
    }
    out
}

#[inline]
fn is_lit(t: Tok) -> bool { matches!(t, Tok::Str | Tok::Num | Tok::Word) }
#[inline]
fn is_cmp(t: Tok) -> bool { matches!(t, Tok::Op(true)) || t == Tok::K(Kw::Like) }
#[inline]
fn has_kw(t: &[Tok], k: Kw) -> bool { t.contains(&Tok::K(k)) }

// two keywords adjacent (within `gap` tokens)
fn adj(t: &[Tok], a: Kw, b: Kw, gap: usize) -> bool {
    for i in 0..t.len() {
        if t[i] == Tok::K(a) {
            let end = (i + 1 + gap).min(t.len());
            for x in &t[i + 1..end] {
                if *x == Tok::K(b) { return true; }
            }
        }
    }
    false
}

fn detect_ctx(t: &[Tok], broke: bool) -> Option<&'static str> {
    if adj(t, Kw::Union, Kw::Select, 2) { return Some("union_select"); }
    // dangerous functions and markers
    for &(k, name) in &[
        (Kw::Sleep, "sleep"), (Kw::Benchmark, "benchmark"), (Kw::Waitfor, "waitfor"),
        (Kw::PgSleep, "pg_sleep"), (Kw::LoadFile, "load_file"), (Kw::Outfile, "outfile"),
        (Kw::InfoSchema, "information_schema"), (Kw::Extractvalue, "extractvalue"),
        (Kw::Updatexml, "updatexml"),
    ] {
        if has_kw(t, k) { return Some(name); }
    }
    // stacked query: ; <select|insert|update|delete|drop|exec>
    for i in 0..t.len() {
        if t[i] == Tok::Semi {
            let end = (i + 3).min(t.len());
            for x in &t[i + 1..end] {
                if matches!(*x, Tok::K(Kw::Select) | Tok::K(Kw::Insert) | Tok::K(Kw::Update)
                    | Tok::K(Kw::Delete) | Tok::K(Kw::Drop) | Tok::K(Kw::Exec) | Tok::K(Kw::Execute)) {
                    return Some("stacked");
                }
            }
        }
    }
    if adj(t, Kw::Drop, Kw::Table, 2) || adj(t, Kw::Drop, Kw::Database, 2) { return Some("drop"); }
    if adj(t, Kw::Insert, Kw::Into, 2) { return Some("insert"); }
    if adj(t, Kw::Delete, Kw::From, 2) { return Some("delete"); }
    // tautology: lit cmp lit (in the normal context, only next to or/and)
    if t.len() >= 3 {
        for i in 0..t.len() - 2 {
            if is_lit(t[i]) && is_cmp(t[i + 1]) && is_lit(t[i + 2]) {
                let near = i > 0 && (t[i - 1] == Tok::K(Kw::Or) || t[i - 1] == Tok::K(Kw::And));
                if broke || near { return Some("tautology"); }
            }
        }
    }
    // in the break-out context: the string is closed and a comment follows immediately (admin'--)
    if broke && t.contains(&Tok::Comment) { return Some("comment_inject"); }
    // select ... from plus an explicit SQL tail (operator/comment/semicolon/union), otherwise it is prose
    if has_kw(t, Kw::Select) && has_kw(t, Kw::From) {
        let has_cmp = t.iter().any(|x| matches!(*x, Tok::Op(true)));
        if has_cmp || t.contains(&Tok::Comment)
            || t.contains(&Tok::Semi) || has_kw(t, Kw::Union) {
            return Some("select_from");
        }
    }
    None
}

/// Whether this looks like SQL injection. Returns a fingerprint label for logging, or None.
pub fn is_sqli(input: &str) -> Option<&'static str> {
    if input.is_empty() { return None; }
    let low = input.to_ascii_lowercase();
    for &(start, broke) in &[(None, false), (Some(b'\''), true), (Some(b'"'), true)] {
        let t = tokenize(&low, start);
        if let Some(r) = detect_ctx(&t, broke) { return Some(r); }
    }
    None
}

// ---- XSS ----

const XSS_TAGS: &[&str] = &[
    "script", "iframe", "object", "embed", "svg", "base", "applet",
    "frameset", "isindex", "meta", "math",
];
const XSS_EVENTS: &[&str] = &[
    "onload", "onerror", "onclick", "onmouseover", "onmouseenter", "onmouseout",
    "onfocus", "onblur", "onsubmit", "onchange", "onkeydown", "onkeyup", "onkeypress",
    "ontoggle", "onanimationstart", "onanimationend", "onanimationiteration",
    "onpointerover", "onpointerdown", "onpointerup", "onpointermove", "onpointerenter",
    "onpointerleave", "onpointerout", "onpointercancel", "ongotpointercapture",
    "onlostpointercapture", "onwheel", "onbegin", "onfinish", "onstart", "onmousemove",
    "onmousedown", "onmouseup", "onmouseleave", "onmousewheel", "ondblclick", "onauxclick",
    "oncontextmenu", "onresize", "onscroll", "onscrollend", "onplay", "onplaying", "onpause",
    "onpageshow", "onpagehide", "onhashchange", "onpopstate", "onstorage", "onbeforeunload",
    "onunload", "onmessage", "onmessageerror", "onopen", "onclose", "ononline", "onoffline",
    "ontouchstart", "ontouchend", "ontouchmove", "ontouchcancel", "oninput", "oninvalid",
    "onreset", "onsearch", "onselect", "onselectstart", "onselectionchange", "oncut", "oncopy",
    "onpaste", "ondrag", "ondragstart", "ondragend", "ondragenter", "ondragleave", "ondragover",
    "ondrop", "oncanplay", "oncanplaythrough", "ontimeupdate", "ondurationchange", "onvolumechange",
    "onwaiting", "onseeked", "onseeking", "onended", "onloadstart", "onloadeddata",
    "onloadedmetadata", "onprogress", "onstalled", "onsuspend", "onratechange", "onemptied",
    "onfocusin", "onfocusout", "ontransitionend", "ontransitionstart", "oncuechange",
    "onreadystatechange", "onvisibilitychange", "onshow", "onbeforeprint", "onafterprint",
    "onwebkitanimationstart", "onwebkitanimationend", "onwebkittransitionend",
];

/// Whether this looks like XSS. A bare tag is flagged only for always-dangerous tags; ordinary ones
/// (img/a/div/...) only count when they carry an on*= handler or a javascript: scheme.
pub fn is_xss(input: &str) -> Option<&'static str> {
    if input.is_empty() { return None; }
    let low = input.to_ascii_lowercase();
    if low.contains("javascript:") || low.contains("vbscript:") { return Some("scheme"); }
    if low.contains("fromcharcode") { return Some("js_sink"); }
    if low.contains("data:") && low.contains("text/html") { return Some("data_html"); }

    let b = low.as_bytes();
    let n = b.len();

    // <tag — dangerous tag
    let mut i = 0usize;
    while i < n {
        if b[i] == b'<' {
            let mut j = i + 1;
            while j < n && (b[j] == b' ' || b[j] == b'/' || b[j] == b'\t') { j += 1; }
            let st = j;
            while j < n && (b[j].is_ascii_alphabetic() || (j > st && b[j].is_ascii_digit())) { j += 1; }
            if j > st {
                let tag = &low[st..j];
                if XSS_TAGS.contains(&tag) { return Some("tag"); }
            }
        }
        i += 1;
    }

    // event handler: onXxx [ws] =
    let mut i = 0usize;
    while i + 2 < n {
        if b[i] == b'o' && b[i + 1] == b'n' && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            let mut j = i + 2;
            while j < n && b[j].is_ascii_alphabetic() { j += 1; }
            let name_end = j;
            while j < n && (b[j] == b' ' || b[j] == b'\t') { j += 1; }
            if name_end > i + 2 && j < n && b[j] == b'=' {
                let ev = &low[i..name_end];
                if XSS_EVENTS.contains(&ev) { return Some("event"); }
            }
        }
        i += 1;
    }

    // JS context: a break-out (quote, paren, `>`, `;`) plus a sink function call. Deliberately narrow —
    // it requires BOTH the break-out AND the sink, so the word `alert` in ordinary text is ignored. Catches
    // `'-alert(1)//`, `")prompt(1)`, `>eval(...)` and similar payloads that carry no tag or on*=.
    let lb = low.as_bytes();
    for sink in ["alert(", "confirm(", "prompt(", "eval(", "atob("] {
        let sb = sink.as_bytes();
        if let Some(p) = lb.windows(sb.len()).position(|w| w == sb) {
            let s0 = p.saturating_sub(4);
            if lb[s0..p]
                .iter()
                .any(|&c| matches!(c, b'\'' | b'"' | b'>' | b';' | b')' | b'`'))
            {
                return Some("jsctx");
            }
        }
    }
    None
}

/// XXE / external entities: an ENTITY declaration, or a DOCTYPE with SYSTEM/PUBLIC.
/// High precision: legitimate requests do not contain `<!ENTITY` or `<!DOCTYPE ... SYSTEM`.
pub fn is_xxe(input: &str) -> Option<&'static str> {
    let low = input.to_ascii_lowercase();
    if low.contains("<!entity") {
        return Some("entity");
    }
    if low.contains("<!doctype") && (low.contains("system") || low.contains("public")) {
        return Some("doctype");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xxe_detects() {
        assert!(is_xxe(r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#).is_some());
        assert!(is_xxe("<!doctype x system \"http://evil\">").is_some());
        assert!(is_xxe("<soap>hello world</soap>").is_none());
    }

    #[test]
    fn xss_jsctx_detects() {
        assert!(is_xss("'-alert(1)//").is_some());
        assert!(is_xss("\")prompt(1)").is_some());
        // no break-out before the call, so we do not flag it (fewer false positives)
        assert!(is_xss("myalert(x)").is_none());
    }

    #[test]
    fn sqli_detects_attacks() {
        for a in &[
            "' or '1'='1", "1' OR 1=1--", "admin'--",
            "1 UNION SELECT username,password FROM users",
            "'; DROP TABLE users; --", "1 AND SLEEP(5)",
            "1' AND extractvalue(1,version())--", "'; exec xp_cmdshell('dir')--",
            "1 OR 1=1", "') OR ('1'='1", "1; INSERT INTO logs VALUES(1)",
        ] {
            assert!(is_sqli(a).is_some(), "should be detected as SQLi: {}", a);
        }
    }

    #[test]
    fn sqli_no_false_positives() {
        for b in &[
            "where are you from? select any option",
            "I can't select from the list right now",
            "Order from our menu and select a dish",
            "use the update button to set preferences",
            "drop me a line at the table", "1 + 1 = 2",
            "delete the file from the folder", "group by category and order by name",
            "the cat or the dog", "insert your card and select language",
            "price = 5 for the item", "please update and set the value",
        ] {
            assert!(is_sqli(b).is_none(), "false positive SQLi: {}", b);
        }
    }

    #[test]
    fn xss_detects_attacks() {
        for a in &[
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>", "javascript:alert(document.cookie)",
            "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>", "<object data=x>",
            "<META http-equiv=refresh content=0>", "<div onmouseover=alert(1)>",
        ] {
            assert!(is_xss(a).is_some(), "should be detected as XSS: {}", a);
        }
    }

    #[test]
    fn xss_no_false_positives() {
        for b in &[
            "<img src=cat.jpg alt=cat>", "<a href=/page>link</a>",
            "<p>hello <b>world</b></p>", "<table><tr><td>data</td></tr></table>",
            "<div class=box>content</div>", "2 < 3 and 5 > 1",
            "onset of winter", "function add(a,b){return a+b}",
            "<ul><li>one</li></ul>", "the price is < 100", "<h1>Title</h1>",
            // traps: the substring \"on\" not followed by '=', and words merely starting with on*
            "contact information section", "reason=other", "the online store is open",
            "once upon a time", "onboarding=complete",
        ] {
            assert!(is_xss(b).is_none(), "false positive XSS: {}", b);
        }
    }

    #[test]
    fn xss_more_event_handlers_detected() {
        // these handlers used to be missing from the list, which allowed a bypass. Now they are caught.
        for a in &[
            "<img onpointerdown=alert(1)>", "<div ondblclick=alert(1)>",
            "<a onmousedown=steal()>", "<b oncopy=x>", "<x oninput=y>",
            "<p ontouchstart=z>", "<i ondrop=w>", "<u onwheel=q>",
            "<span onfocusin=alert(1)>", "<label onselect=x>",
        ] {
            assert!(is_xss(a).is_some(), "should be detected as XSS: {}", a);
        }
    }

    #[test]
    fn fingerprint_labels_are_stable() {
        // pin the labels for unambiguous cases (regression guard)
        assert_eq!(is_sqli("1 union select a,b from users"), Some("union_select"));
        assert_eq!(is_xss("javascript:alert(1)"), Some("scheme"));
        assert_eq!(is_xss("<script>alert(1)</script>"), Some("tag"));
        assert_eq!(is_xss("<img src=x onerror=alert(1)>"), Some("event"));
        assert_eq!(is_xxe(r#"<!ENTITY xxe SYSTEM "file:///etc/passwd">"#), Some("entity"));
    }
}
