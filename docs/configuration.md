# Configuration

The node reads a JSON file at `/etc/threatail/config.json`, or from a path given as the first argument:

```bash
threatail-node /path/to/config.json
```

Start from [`config.example.json`](../config.example.json). Every field is optional except `sites[].domain` and `sites[].backends`.

## Top level

| Field | Default | Meaning |
|---|---|---|
| `listen_http` | `0.0.0.0:80` | HTTP listener |
| `listen_https` | — | HTTPS listener; empty disables HTTPS |
| `http2_enabled` | `false` | ALPN h2 on the HTTPS listener |
| `metrics_listen` | — | Prometheus endpoint; **bind internally** |
| `metrics_token` | — | Bearer token for metrics |
| `geoip_db` | — | Path to GeoLite2-Country.mmdb |
| `ml_model_path` | — | Supervised model; empty disables it |
| `certs` | — | TLS certificates read from disk; see [certificates.md](certificates.md) |
| `iprep_file` | — | Malicious IP list, one address or CIDR per line |
| `managed_rules_file` | — | Managed rules as a JSON array |
| `fpfeed_file` | — | Malicious TLS fingerprints, one JA3 or JA4 per line |
| `sites` | — | List of sites |

### Threat data from files

`iprep_file`, `managed_rules_file` and `fpfeed_file` are what the per-site switches
`iprep_enabled`, `managed_rules_enabled` and `fpfeed_enabled` act on. Turning a switch
on without a file behind it does nothing at all — the set is simply empty — so check the
startup log, which reports the entry count for each source it loaded.

These files are read once at startup. Refreshing them means restarting the node, or
attaching the cloud, which polls them continuously instead.

## Per site

### Routing

| Field | Meaning |
|---|---|
| `domain` | Matched against `Host`. `*.example.com` matches subdomains |
| `backends` | One or more `http://host:port`, round-robin |
| `mode` | `learn`, `detect` or `protect` |
| `force_https` | Redirect HTTP to HTTPS with 301 |
| `insecure_backend` | Skip backend certificate validation |

More specific wildcards win: `*.api.example.com` beats `*.example.com`.

### Access control

| Field | Meaning |
|---|---|
| `ip_whitelist` | Passed through immediately, skipping every check |
| `ip_blacklist` | Blocked immediately |
| `trusted_proxies` | CIDRs whose `X-Forwarded-For` is trusted |
| `allowed_methods` | Uppercase list; anything else gets 405 |
| `geo_mode` | `off`, `allow` or `deny` |
| `geo_countries` | ISO country codes for the geo policy |

`trusted_proxies` matters whenever anything sits in front of the node. Without it `X-Forwarded-For` is ignored, which is deliberate: a client could otherwise forge any source IP and bypass every per-IP control.

`ip_whitelist` skips *everything*. It is not "trust a bit more", it is "do not inspect". Use it for health checks and monitoring, not for staff subnets you would still like protected.

### Limits

| Field | Default | Meaning |
|---|---|---|
| `body_limit` | 65536 | Bytes of body inspected |
| `body_tail_kb` | 32 | KB of the body's end also scanned |
| `body_oversized` | 1 | Uninspected gap: 0 off, 1 score, 2 block |
| `max_body_kb` | — | Reject larger bodies with 413 |
| `max_uri_kb` | — | Reject longer URIs with 414 |
| `upstream_timeout` | 30 | Backend response timeout, seconds |
| `body_read_timeout` | 30 | Request body read timeout, seconds |

Raising `body_limit` costs CPU on every request. Prefer leaving it and relying on tail inspection.

### Detection

| Field | Meaning |
|---|---|
| `custom_rules` | See [custom-rules.md](custom-rules.md) |
| `mtls_locations` | Path prefixes requiring a client certificate |
| `mtls_ca_file` | CA that client certificates are validated against |
| `api_jwt_*`, `api_json_*`, `api_schema_*` | See [api-protection.md](api-protection.md) |
| `exceptions` | Overrides that let a request through |
| `rate_rules` | Per-path rate limits |
| `bot_mode` | `off`, `detect` or `block` |
| `verbot_enabled` | Verify crawlers via reverse DNS |
| `behavior_enabled` | Behavioural bot analysis |
| `anomaly_sens` | `low`, `medium` or `high` |
| `anomaly_block` | Block on anomaly in protect mode |
| `ato_enabled` | Credential-stuffing protection |
| `ato_login_paths` | Prefixes such as `/login` |

### Rate rules

```json
{
  "location": "/api/",
  "operator": "prefix",
  "rps": 20,
  "burst": 40,
  "key": "ip",
  "action": "block"
}
```

`operator` is `prefix`, `equals` or `regex`. `key` is `ip` (default), `token`, `header:Name` or `cookie:name`. `action` is `block` (429) or `challenge` (proof of work).

Bucket capacity is `rps + burst`, so the example above tolerates a burst of 40 then settles at 20 rps. Rule selection is longest-match, so a rule on `/api/v2/auth` overrides one on `/`.

Limits are per process. Behind a load balancer with several nodes, the effective limit multiplies by the node count.

### Responses

| Field | Meaning |
|---|---|
| `block_status` | Status for blocks; default 403 |
| `ratelimit_status` | Status for rate limits; default 429 |
| `block_body` | Custom block page body |
| `block_content_type` | Defaults to `text/html` |
| `sec_headers` | Add nosniff, X-Frame-Options, Referrer-Policy, HSTS |
| `dlp_enabled` | Scan responses for leaked secrets and PII |

### Rolling out safely

| Field | Effect |
|---|---|
| `traversal_logonly` | Traversal gate detects but does not block |
| `method_logonly` | Method gate detects but does not block |
| `ipv6_logonly` | IPv6 gate detects but does not block |

These let a site run in `protect` while one gate is still being trialled.

## A worked order of operations

A sensible rollout:

1. `mode: learn` for a few days so the anomaly profile reflects real traffic.
2. `mode: detect`, then read the logs. Everything logged here *would* have been blocked.
3. Add `exceptions` for the false positives you find.
4. `mode: protect`.

Skipping step 2 is how people end up blocking their own checkout flow.
