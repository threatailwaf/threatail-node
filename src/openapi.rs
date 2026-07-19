// openapi.rs — API protection, phase 2 (positive security model driven by OpenAPI).
//
// LAYERS 2a + 2b (this file):
//   2a — positive routing: a request to a path or method absent from the schema is detected or blocked.
//        Covers hidden endpoints, surplus methods and scanners (OWASP API8, partially API1).
//   2b — query and path parameter validation: required flags, type (integer/number/boolean/string)
//        and enum. Values outside the schema are detected or blocked.
//
// LAYER 2c (next iteration): BODY validation against JSON Schema
//   (types, required, additionalProperties:false, covering mass assignment / BOPA). The check()
//   signature already takes the body, so 2c slots in without an interface change.
//
// Environment constraint: the spec is accepted as JSON (OpenAPI 3.x). Convert YAML beforehand.
// No external crates beyond serde_json. The model is compiled ONCE (in site_from_policy),
// not per request.

use crate::apisec::{ApiHit, Sev};
use serde_json::Value;
use std::collections::HashMap;

// ─────────────────────────── path segment ───────────────────────────

#[derive(Clone, Debug)]
enum Seg {
    Lit(String),   // literal segment, e.g. "users"
    Param(String), // the {id} parameter
}

#[derive(Clone, Debug, Default)]
struct ParamSpec {
    name: String,
    required: bool,
    ty: String,           // "integer"|"number"|"boolean"|"string"|"array"|"" (any)
    enum_vals: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct Operation {
    query: Vec<ParamSpec>,
    path: Vec<ParamSpec>,
    // Layer 2c: the body schema and whether it is required (currently stored only).
    body_schema: Option<Value>,
    body_required: bool,
}

#[derive(Clone, Debug)]
struct Route {
    segs: Vec<Seg>,
    lit_count: usize,                   // number of literal segments (specificity)
    ops: HashMap<String, Operation>,    // METHOD(upper) -> Operation
}

#[derive(Clone, Debug, Default)]
pub struct OpenApiModel {
    routes: Vec<Route>,
    root: Value, // the spec root, used to resolve nested $ref during body validation
}

// ─────────────────────────── gate (configuration + model) ───────────────────────────

#[derive(Clone, Debug, Default)]
pub struct OpenApiGate {
    pub enabled: bool,
    pub logonly: bool,
    pub validate_params: bool, // 2b
    pub validate_body: bool,   // 2c (currently a no-op)
    pub model: Option<OpenApiModel>,
}

impl OpenApiGate {
    /// Build from the site's JSON configuration blob. Keys:
    ///   api_schema_enabled (bool), api_schema_logonly (bool, default true),
    ///   api_schema_params (bool, default true), api_schema_body (bool, default false),
    ///   api_schema_spec (an OpenAPI object or a JSON string).
    pub fn from_config(c: &Value) -> Self {
        let b = |k: &str, d: bool| c.get(k).and_then(|v| v.as_bool()).unwrap_or(d);
        let enabled = b("api_schema_enabled", false);
        let logonly = b("api_schema_logonly", true);
        let validate_params = b("api_schema_params", true);
        let validate_body = b("api_schema_body", false);

        let mut model = None;
        if enabled {
            // the spec may be an object or a JSON string
            let spec_val: Option<Value> = match c.get("api_schema_spec") {
                Some(Value::String(s)) if !s.trim().is_empty() => serde_json::from_str(s).ok(),
                Some(v) if v.is_object() => Some(v.clone()),
                _ => None,
            };
            match spec_val {
                Some(v) => match compile(&v) {
                    Ok(m) => model = Some(m),
                    // fail open: the gate stays inactive, but the reason is logged
                    Err(e) => tracing::warn!("openapi: schema compile failed, gate inactive: {}", e),
                },
                None => tracing::warn!("openapi: schema enabled but api_schema_spec missing/invalid JSON, gate inactive"),
            }
        }
        OpenApiGate { enabled, logonly, validate_params, validate_body, model }
    }

    #[inline]
    pub fn active(&self) -> bool {
        self.enabled && self.model.is_some()
    }

    /// Check a request against the schema. Returns the first violation, or None.
    pub fn check(
        &self,
        method: &str,
        path: &str,
        query: &str,
        content_type: &str,
        body: &[u8],
    ) -> Option<ApiHit> {
        let model = self.model.as_ref()?;
        let hit = |reason: String| Some(mk_hit(self.logonly, reason));

        // 2a — path matching. The path is normalised (percent-decode plus resolving . and ..)
        // so the WAF sees what the backend sees, guarding against path confusion.
        let norm = normalize_path(path);
        let want = split_path(&norm);
        let mut best: Option<&Route> = None;
        for r in &model.routes {
            if seg_match(&r.segs, &want)
                && best.is_none_or(|b| r.lit_count > b.lit_count) {
                    best = Some(r);
                }
        }
        let route = match best {
            Some(r) => r,
            None => return hit(format!("path not in schema: {}", path)),
        };
        let op = match route.ops.get(&method.to_ascii_uppercase()) {
            Some(o) => o,
            None => return hit(format!("method {} not allowed for {}", method, path)),
        };

        // 2b — parameters
        if self.validate_params {
            // query -> multi-values
            let qmap = parse_query(query);
            for p in &op.query {
                let vals = qmap.get(&p.name);
                match vals {
                    None => {
                        if p.required {
                            return hit(format!("missing required query param: {}", p.name));
                        }
                    }
                    Some(list) => {
                        for v in list {
                            if let Some(reason) = check_value(p, v) {
                                return hit(reason);
                            }
                        }
                    }
                }
            }
            // path parameters: match the template against the actual segments
            if !op.path.is_empty() {
                let pv = path_param_values(&route.segs, &want);
                for p in &op.path {
                    if let Some(v) = pv.get(&p.name) {
                        if let Some(reason) = check_value(p, v) {
                            return hit(reason);
                        }
                    }
                }
            }
        }

        // 2c — body validation against JSON Schema
        if self.validate_body {
            // Content-Type is not trusted: if the body looks like JSON, validate it anyway
            let is_json = content_type.to_ascii_lowercase().contains("json")
                || crate::apisec::looks_json(body);
            if body.is_empty() {
                if op.body_required {
                    return hit("missing required request body".to_string());
                }
            } else if is_json {
                match serde_json::from_slice::<Value>(body) {
                    Ok(v) => {
                        if let Some(schema) = &op.body_schema {
                            if let Some(reason) = validate_json(&model.root, schema, &v, 0) {
                                return hit(reason);
                            }
                        }
                    }
                    Err(_) => return hit("request body is not valid JSON".to_string()),
                }
            }
        }

        None
    }
}

// ApiHit is constructed through apisec (its fields are private there) via the public wrapper constructor.
fn mk_hit(logonly: bool, reason: String) -> ApiHit {
    crate::apisec::ApiHit {
        sig: "api_schema",
        sev: if logonly { Sev::Detect } else { Sev::Block },
        reason,
    }
}

// ─────────────────────────── schema compilation ───────────────────────────

const METHODS: [&str; 7] = ["GET", "PUT", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/// Compile an OpenAPI 3.x document (JSON) into the routing model.
pub fn compile(spec: &Value) -> Result<OpenApiModel, String> {
    let paths = spec
        .get("paths")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "openapi: no `paths` object".to_string())?;

    let mut routes: Vec<Route> = Vec::new();
    for (tmpl, item) in paths.iter() {
        let item = deref(spec, item);
        let segs = compile_segments(tmpl);
        let lit_count = segs.iter().filter(|s| matches!(s, Seg::Lit(_))).count();

        // path-level parameters, shared by all methods
        let path_level = collect_params(spec, item.get("parameters"));

        let mut ops: HashMap<String, Operation> = HashMap::new();
        if let Some(obj) = item.as_object() {
            for (k, opv) in obj.iter() {
                let ku = k.to_ascii_uppercase();
                if !METHODS.contains(&ku.as_str()) {
                    continue;
                }
                let opv = deref(spec, opv);
                let mut params = path_level.clone();
                params.extend(collect_params(spec, opv.get("parameters")));

                let (query, path): (Vec<_>, Vec<_>) =
                    params.into_iter().partition(|(loc, _)| loc == "query");
                let query: Vec<ParamSpec> = query.into_iter().map(|(_, p)| p).collect();
                let path: Vec<ParamSpec> = path.into_iter().map(|(_, p)| p).collect();

                // body (for 2c): take the schema from requestBody.content[json].schema
                let (body_schema, body_required) = extract_body(spec, opv.get("requestBody"));

                ops.insert(ku, Operation { query, path, body_schema, body_required });
            }
        }
        routes.push(Route { segs, lit_count, ops });
    }
    if routes.is_empty() {
        return Err("openapi: paths compiled to zero routes".to_string());
    }
    Ok(OpenApiModel { routes, root: spec.clone() })
}

fn compile_segments(tmpl: &str) -> Vec<Seg> {
    tmpl.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s.starts_with('{') && s.ends_with('}') && s.len() >= 2 {
                Seg::Param(s[1..s.len() - 1].to_string())
            } else {
                Seg::Lit(s.to_string())
            }
        })
        .collect()
}

/// Resolve a `$ref` (local `#/...` only). Returns a clone of the target node,
/// or the original when it is not a ref or cannot be found. Depth is bounded to avoid cycles.
fn deref(spec: &Value, node: &Value) -> Value {
    let mut cur = node.clone();
    for _ in 0..16 {
        let rf = match cur.get("$ref").and_then(|v| v.as_str()) {
            Some(r) if r.starts_with("#/") => r.to_string(),
            _ => return cur,
        };
        let mut p = spec;
        let mut ok = true;
        for part in rf[2..].split('/') {
            let part = part.replace("~1", "/").replace("~0", "~"); // JSON Pointer unescape
            match p.get(&part) {
                Some(v) => p = v,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            return cur;
        }
        cur = p.clone();
    }
    cur
}

/// Collect parameters from the `parameters` array. Returns (location, ParamSpec).
fn collect_params(spec: &Value, params: Option<&Value>) -> Vec<(String, ParamSpec)> {
    let mut out = Vec::new();
    let arr = match params.and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return out,
    };
    for p in arr {
        let p = deref(spec, p);
        let name = match p.get("name").and_then(|v| v.as_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let loc = p.get("in").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if loc != "query" && loc != "path" {
            continue; // header and cookie parameters are not validated here
        }
        let required = p.get("required").and_then(|v| v.as_bool()).unwrap_or(loc == "path");
        let sch = deref(spec, p.get("schema").unwrap_or(&Value::Null));
        let ty = sch.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let enum_vals = sch
            .get("enum")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().map(val_to_string).collect())
            .unwrap_or_default();
        out.push((loc, ParamSpec { name, required, ty, enum_vals }));
    }
    out
}

fn extract_body(spec: &Value, rb: Option<&Value>) -> (Option<Value>, bool) {
    let rb = match rb {
        Some(v) => deref(spec, v),
        None => return (None, false),
    };
    let required = rb.get("required").and_then(|v| v.as_bool()).unwrap_or(false);
    let schema = rb
        .get("content")
        .and_then(|c| c.as_object())
        .and_then(|c| {
            c.iter()
                .find(|(k, _)| k.contains("json"))
                .map(|(_, mt)| mt)
        })
        .and_then(|mt| mt.get("schema"))
        .map(|s| deref(spec, s));
    (schema, required)
}

// ─────────────────────────── matching and validation ───────────────────────────

/// Normalise a path the way most servers do: percent-decode,
/// then drop empty segments and ".", and collapse ".." by popping the previous segment.
/// Applied BEFORE matching so that encoded or obfuscated paths
/// (`/api/%61dmin`, `/a/..%2fb`) cannot diverge from what the backend resolves.
fn normalize_path(path: &str) -> String {
    let decoded = pct_decode(path);
    let mut out: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut p = String::from("/");
    p.push_str(&out.join("/"));
    p
}

fn split_path(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

fn seg_match(segs: &[Seg], want: &[&str]) -> bool {
    if segs.len() != want.len() {
        return false;
    }
    for (s, w) in segs.iter().zip(want.iter()) {
        match s {
            Seg::Lit(l) => {
                if l != w {
                    return false;
                }
            }
            Seg::Param(_) => {
                if w.is_empty() {
                    return false;
                }
            }
        }
    }
    true
}

fn path_param_values(segs: &[Seg], want: &[&str]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for (s, w) in segs.iter().zip(want.iter()) {
        if let Seg::Param(name) = s {
            m.insert(name.clone(), pct_decode(w));
        }
    }
    m
}

/// Validate a single parameter value against the spec. Some(reason) on violation.
fn check_value(p: &ParamSpec, raw: &str) -> Option<String> {
    let v = raw;
    match p.ty.as_str() {
        "integer" => {
            // as in body validation: an integer is a number with a zero fractional part
            let ok = matches!(v.parse::<f64>(), Ok(f) if f.fract() == 0.0);
            if !ok {
                return Some(format!("param {} not integer: {}", p.name, trunc(v)));
            }
        }
        "number" => {
            if v.parse::<f64>().is_err() {
                return Some(format!("param {} not number: {}", p.name, trunc(v)));
            }
        }
        "boolean"
            if v != "true" && v != "false" => {
                return Some(format!("param {} not boolean: {}", p.name, trunc(v)));
            }
        _ => {}
    }
    if !p.enum_vals.is_empty() && !p.enum_vals.iter().any(|e| e == v) {
        return Some(format!("param {} not in enum: {}", p.name, trunc(v)));
    }
    None
}

fn parse_query(q: &str) -> HashMap<String, Vec<String>> {
    let mut m: HashMap<String, Vec<String>> = HashMap::new();
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let k = pct_decode(it.next().unwrap_or(""));
        let v = pct_decode(it.next().unwrap_or(""));
        if k.is_empty() {
            continue;
        }
        m.entry(k).or_default().push(v);
    }
    m
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let h = hex(b[i + 1]);
                let l = hex(b[i + 2]);
                match (h, l) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn val_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn trunc(s: &str) -> String {
    let t: String = s.chars().take(40).collect();
    if t.len() < s.len() {
        format!("{}…", t)
    } else {
        t
    }
}

// ─────────────────────────── JSON Schema validator (2c) ───────────────────────────

/// Validate a value against a (sub)schema. Some(reason) on violation, None when valid.
/// Nested $ref are resolved through root. `depth` bounds recursion against cycles and DoS.
fn validate_json(root: &Value, schema: &Value, val: &Value, depth: usize) -> Option<String> {
    if depth > 64 {
        return None; // deeper levels are not validated (fail open; the apisec gate handles JSON bombs)
    }
    let schema = deref(root, schema);

    // Combinators are ANDed with the base constraints.
    if let Some(all) = schema.get("allOf").and_then(|v| v.as_array()) {
        for s in all {
            if let Some(r) = validate_json(root, s, val, depth + 1) {
                return Some(r);
            }
        }
    }
    if let Some(any) = schema.get("anyOf").and_then(|v| v.as_array()) {
        if !any.iter().any(|s| validate_json(root, s, val, depth + 1).is_none()) {
            return Some("value matches none of anyOf".to_string());
        }
    }
    if let Some(one) = schema.get("oneOf").and_then(|v| v.as_array()) {
        let n = one.iter().filter(|s| validate_json(root, s, val, depth + 1).is_none()).count();
        if n != 1 {
            return Some(format!("value matches {} of oneOf (need exactly 1)", n));
        }
    }
    if let Some(not) = schema.get("not") {
        if validate_json(root, not, val, depth + 1).is_none() {
            return Some("value matches `not` schema".to_string());
        }
    }

    // null / nullable
    if val.is_null() {
        let nullable = schema.get("nullable").and_then(|v| v.as_bool()).unwrap_or(false);
        if nullable || type_allows_null(&schema) {
            return None;
        }
        if schema.get("type").is_some() {
            return Some("null not allowed".to_string());
        }
        return None;
    }

    // type
    if let Some(reason) = check_type(&schema, val) {
        return Some(reason);
    }

    // enum (any type)
    if let Some(en) = schema.get("enum").and_then(|v| v.as_array()) {
        if !en.iter().any(|e| e == val) {
            return Some("value not in enum".to_string());
        }
    }

    match val {
        Value::Object(map) => {
            if let Some(req) = schema.get("required").and_then(|v| v.as_array()) {
                for r in req {
                    if let Some(name) = r.as_str() {
                        if !map.contains_key(name) {
                            return Some(format!("missing required field: {}", name));
                        }
                    }
                }
            }
            let props = schema.get("properties").and_then(|v| v.as_object());
            let addl = schema.get("additionalProperties");
            let addl_false = matches!(addl, Some(Value::Bool(false)));
            let addl_schema = match addl {
                Some(Value::Object(_)) => addl,
                _ => None,
            };
            for (k, v) in map.iter() {
                if let Some(ps) = props.and_then(|p| p.get(k)) {
                    if let Some(r) = validate_json(root, ps, v, depth + 1) {
                        return Some(r);
                    }
                } else if addl_false {
                    return Some(format!("unexpected field: {}", trunc(k)));
                } else if let Some(asch) = addl_schema {
                    if let Some(r) = validate_json(root, asch, v, depth + 1) {
                        return Some(r);
                    }
                }
            }
        }
        Value::Array(arr) => {
            if let Some(mx) = schema.get("maxItems").and_then(|v| v.as_u64()) {
                if arr.len() as u64 > mx {
                    return Some(format!("array longer than maxItems {}", mx));
                }
            }
            if let Some(mn) = schema.get("minItems").and_then(|v| v.as_u64()) {
                if (arr.len() as u64) < mn {
                    return Some(format!("array shorter than minItems {}", mn));
                }
            }
            if let Some(items) = schema.get("items") {
                for it in arr {
                    if let Some(r) = validate_json(root, items, it, depth + 1) {
                        return Some(r);
                    }
                }
            }
        }
        Value::String(s) => {
            let len = s.chars().count() as u64;
            if let Some(mx) = schema.get("maxLength").and_then(|v| v.as_u64()) {
                if len > mx {
                    return Some(format!("string longer than maxLength {}", mx));
                }
            }
            if let Some(mn) = schema.get("minLength").and_then(|v| v.as_u64()) {
                if len < mn {
                    return Some(format!("string shorter than minLength {}", mn));
                }
            }
        }
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if let Some(mx) = schema.get("maximum").and_then(|v| v.as_f64()) {
                    if f > mx {
                        return Some(format!("number > maximum {}", mx));
                    }
                }
                if let Some(mn) = schema.get("minimum").and_then(|v| v.as_f64()) {
                    if f < mn {
                        return Some(format!("number < minimum {}", mn));
                    }
                }
            }
        }
        _ => {}
    }
    None
}

fn check_type(schema: &Value, val: &Value) -> Option<String> {
    let types: Vec<String> = match schema.get("type") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect(),
        _ => return None, // no type given, so anything is accepted
    };
    if types.iter().any(|ty| json_is_type(ty, val)) {
        None
    } else {
        Some(format!("expected type {}, got {}", types.join("|"), json_kind(val)))
    }
}

fn json_is_type(ty: &str, v: &Value) -> bool {
    match ty {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "number" => v.is_number(),
        "integer" => v.is_i64() || v.is_u64() || v.as_f64().is_some_and(|f| f.fract() == 0.0),
        "null" => v.is_null(),
        _ => true,
    }
}

fn type_allows_null(schema: &Value) -> bool {
    match schema.get("type") {
        Some(Value::String(s)) => s == "null",
        Some(Value::Array(a)) => a.iter().any(|x| x.as_str() == Some("null")),
        _ => false,
    }
}

fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ─────────────────────────── tests ───────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;

    fn spec() -> Value {
        serde_json::json!({
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {"name":"limit","in":"query","required":true,"schema":{"type":"integer"}},
                            {"name":"sort","in":"query","schema":{"type":"string","enum":["asc","desc"]}}
                        ]
                    },
                    "post": {}
                },
                "/users/{id}": {
                    "parameters": [{"name":"id","in":"path","required":true,"schema":{"type":"integer"}}],
                    "get": {}
                }
            }
        })
    }

    fn gate() -> OpenApiGate {
        let mut g = OpenApiGate::default();
        g.enabled = true;
        g.logonly = false;
        g.validate_params = true;
        g.model = Some(compile(&spec()).unwrap());
        g
    }

    #[test]
    fn unknown_path_blocks() {
        let g = gate();
        let h = g.check("GET", "/admin", "", "", b"").unwrap();
        assert_eq!(h.sev, Sev::Block);
        assert!(h.reason.contains("not in schema"));
    }

    #[test]
    fn method_not_allowed() {
        let g = gate();
        let h = g.check("DELETE", "/users", "limit=1", "", b"").unwrap();
        assert!(h.reason.contains("not allowed"));
    }

    #[test]
    fn known_path_method_ok() {
        let g = gate();
        assert!(g.check("GET", "/users", "limit=10", "", b"").is_none());
        assert!(g.check("POST", "/users", "", "", b"").is_none());
    }

    #[test]
    fn required_query_missing() {
        let g = gate();
        let h = g.check("GET", "/users", "", "", b"").unwrap();
        assert!(h.reason.contains("missing required query param"));
    }

    #[test]
    fn query_type_and_enum() {
        let g = gate();
        assert!(g.check("GET", "/users", "limit=abc", "", b"").unwrap().reason.contains("not integer"));
        assert!(g.check("GET", "/users", "limit=1&sort=sideways", "", b"").unwrap().reason.contains("enum"));
        assert!(g.check("GET", "/users", "limit=1&sort=asc", "", b"").is_none());
    }

    #[test]
    fn path_param_type() {
        let g = gate();
        assert!(g.check("GET", "/users/42", "", "", b"").is_none());
        assert!(g.check("GET", "/users/abc", "", "", b"").unwrap().reason.contains("not integer"));
    }

    #[test]
    fn specificity_prefers_literal() {
        // /users/{id} must match /users/42 rather than being left unmatched
        let g = gate();
        assert!(g.check("GET", "/users/42", "", "", b"").is_none());
    }

    #[test]
    fn ref_deref_in_params() {
        let sp = serde_json::json!({
            "openapi":"3.0.0",
            "paths": {"/x": {"get": {"parameters":[{"$ref":"#/components/parameters/L"}]}}},
            "components": {"parameters": {"L": {"name":"n","in":"query","required":true,"schema":{"type":"integer"}}}}
        });
        let mut g = OpenApiGate::default();
        g.enabled = true; g.logonly = false; g.validate_params = true;
        g.model = Some(compile(&sp).unwrap());
        assert!(g.check("GET", "/x", "", "", b"").unwrap().reason.contains("missing required"));
        assert!(g.check("GET", "/x", "n=5", "", b"").is_none());
    }

    fn body_spec() -> Value {
        serde_json::json!({
            "openapi":"3.0.0",
            "paths": {"/u": {"post": {
                "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref":"#/components/schemas/User"}}}}
            }}},
            "components": {"schemas": {"User": {
                "type":"object","additionalProperties":false,
                "required":["name","age"],
                "properties":{
                    "name":{"type":"string","maxLength":10},
                    "age":{"type":"integer","minimum":0},
                    "role":{"type":"string","enum":["user","admin"]}
                }
            }}}
        })
    }
    fn body_gate() -> OpenApiGate {
        let mut g = OpenApiGate::default();
        g.enabled = true; g.logonly = false; g.validate_params = true; g.validate_body = true;
        g.model = Some(compile(&body_spec()).unwrap());
        g
    }

    #[test]
    fn body_ok() {
        let g = body_gate();
        assert!(g.check("POST", "/u", "", "application/json", br#"{"name":"a","age":5}"#).is_none());
    }
    #[test]
    fn body_additional_prop_rejected() {
        let g = body_gate();
        let h = g.check("POST", "/u", "", "application/json", br#"{"name":"a","age":5,"is_admin":true}"#).unwrap();
        assert!(h.reason.contains("unexpected field"));
    }
    #[test]
    fn body_missing_required() {
        let g = body_gate();
        let h = g.check("POST", "/u", "", "application/json", br#"{"name":"a"}"#).unwrap();
        assert!(h.reason.contains("missing required field"));
    }
    #[test]
    fn body_type_enum_len() {
        let g = body_gate();
        assert!(g.check("POST", "/u", "", "application/json", br#"{"name":"a","age":"x"}"#).unwrap().reason.contains("expected type"));
        assert!(g.check("POST", "/u", "", "application/json", br#"{"name":"a","age":5,"role":"root"}"#).unwrap().reason.contains("enum"));
        assert!(g.check("POST", "/u", "", "application/json", br#"{"name":"abcdefghijk","age":5}"#).unwrap().reason.contains("maxLength"));
    }
    #[test]
    fn body_required_missing() {
        let g = body_gate();
        let h = g.check("POST", "/u", "", "application/json", b"").unwrap();
        assert!(h.reason.contains("missing required request body"));
    }
    #[test]
    fn body_invalid_json() {
        let g = body_gate();
        let h = g.check("POST", "/u", "", "application/json", br#"{bad"#).unwrap();
        assert!(h.reason.contains("not valid JSON"));
    }

    #[test]
    fn path_normalization() {
        let g = gate();
        assert!(g.check("GET", "/users/%35", "", "", b"").is_none()); // %35 = '5'
        assert!(g.check("GET", "//users//5", "", "", b"").is_none());  // double slashes
        assert!(g.check("GET", "/users%2f5", "", "", b"").is_none());  // %2f = '/'
        assert!(g.check("GET", "/x/../users", "limit=1", "", b"").is_none()); // .. is collapsed
    }

    #[test]
    fn integer_accepts_zero_fraction() {
        let g = gate();
        assert!(g.check("GET", "/users", "limit=5.0", "", b"").is_none());
        assert!(g.check("GET", "/users", "limit=5.5", "", b"").unwrap().reason.contains("not integer"));
    }

    #[test]
    fn body_validated_despite_wrong_ct() {
        let g = body_gate();
        // a JSON body with a non-JSON Content-Type is still validated, closing the bypass
        let h = g.check("POST", "/u", "", "text/plain", br#"{"name":"a","age":5,"is_admin":true}"#).unwrap();
        assert!(h.reason.contains("unexpected field"));
        // a valid body with an empty content type passes
        assert!(g.check("POST", "/u", "", "", br#"{"name":"a","age":5}"#).is_none());
    }
}
