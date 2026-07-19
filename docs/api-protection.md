# API protection

Two layers, both configured from `config.json` per site.

- **Phase 1** (`src/apisec.rs`) — structural JWT validation and JSON body hygiene: an algorithm allow-list, `exp`/`nbf` checks with configurable leeway, optional signature verification (HS via a site secret, RS/ES via JWKS), plus limits on JSON nesting depth, key count, array length and string length.
- **Phase 2** (`src/openapi.rs`) — a positive security model built from an OpenAPI 3.x document: requests to paths or methods absent from the schema are detected or blocked, and query and path parameters are validated against their declared types and enums.

The key names are identical to the ones the cloud control plane sends, so a site's configuration is portable between standalone and cloud operation.

## JWT gate

```json
{
  "domain": "api.example.com",
  "backends": ["http://127.0.0.1:8000"],

  "api_jwt_enabled": true,
  "api_jwt_paths": ["/api/"],
  "api_jwt_require": true,
  "api_jwt_algs": ["rs256", "es256"],
  "api_jwt_leeway": 60,
  "api_jwt_logonly": true
}
```

| Key | Meaning |
|---|---|
| `api_jwt_enabled` | Turn the gate on |
| `api_jwt_paths` | Path prefixes it applies to; empty means presence is not enforced |
| `api_jwt_require` | Reject requests to those paths with no token at all |
| `api_jwt_algs` | Allow-list of algorithms, lower case |
| `api_jwt_leeway` | Clock skew tolerated on `exp` and `nbf`, in seconds |
| `api_jwt_logonly` | Detect without blocking |

The algorithm allow-list is the part worth setting deliberately. A token header declares its own `alg`, and accepting whatever it claims is how `alg: none` and the HS/RS confusion attack work — a token signed with the public key as an HMAC secret. Listing only the algorithms your issuer actually uses closes both.

Leave `api_jwt_logonly` at `true` until you have watched the logs. Any client still sending an old token shape shows up there rather than in your support queue.

## Signature verification

Structure and claims are checked without it. Verification additionally proves the token was issued by you.

```json
"api_jwt_verify_sig": true,
"api_jwt_jwks_url": "https://issuer.example.com/.well-known/jwks.json"
```

For HS algorithms, supply the shared secret instead:

```json
"api_jwt_verify_sig": true,
"api_jwt_secret": "your-hmac-secret"
```

JWKS keys are fetched by a background task every 10 minutes, with the first fetch at startup. The URL must be reachable from the node over HTTPS.

Keep `api_jwt_secret` out of a config file you commit. `.gitignore` already excludes `/config.json` for this reason.

## JSON hygiene

```json
"api_json_enabled": true,
"api_json_max_depth": 20,
"api_json_max_keys": 1000,
"api_json_max_array": 1000,
"api_json_max_str": 16384,
"api_json_require_valid": true,
"api_json_logonly": true
```

These bound the shape of a JSON body, not its contents. The target is resource exhaustion in the parser behind you: deeply nested structures, objects with enormous key counts, arrays sized to blow up memory once deserialised. `0` disables an individual limit.

`api_json_require_valid` treats a malformed body under a JSON content type as a violation. That is usually right for an API, and wrong for an endpoint that accepts arbitrary text under a mislabelled content type.

## OpenAPI positive model

```json
"api_schema_enabled": true,
"api_schema_logonly": true,
"api_schema_params": true,
"api_schema_body": false,
"api_schema_spec": "/etc/threatail/openapi.json"
```

`api_schema_spec` takes either a path to an OpenAPI 3.x document or the document inline as a string. Anything the schema does not describe is treated as an anomaly — which is the point, and also why `api_schema_logonly` should stay `true` at first.

A positive model is stricter than everything else in this node: it rejects what is not explicitly allowed rather than what is known to be bad. That is the stronger position, and it fails loudly when the schema drifts from the implementation. If your spec is generated at build time and kept current, this is the single most effective gate here. If it is written by hand and updated occasionally, it will block your own new endpoints the day they ship.

Set `api_schema_body` only once parameters have been running cleanly.

## Rollout order

1. Everything `logonly`, site in `detect`.
2. Read the logs for a few days. Every hit is a request that *would* have been rejected.
3. Turn off `logonly` one gate at a time, starting with JSON hygiene, then JWT, then the schema.

The schema gate is deliberately last: it is the one most likely to disagree with reality.
