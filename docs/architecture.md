# Architecture

The node is a reverse proxy. It accepts a connection, decides whether the request should reach your backend, forwards it if so, and optionally inspects the response on the way back.

```
client → [TLS] → routing → checks → backend → response checks → client
```

Everything happens in-process. There is no external service in the request path and no traffic leaves your server.

## Request pipeline

Checks run roughly cheapest-first, so most malicious traffic is dropped before expensive work happens.

1. **Connection.** On TLS, the ClientHello is fingerprinted once per connection (JA3/JA4) — not per request.
2. **Routing.** The `Host` header selects a site. No match means no site config, so nothing is served.
3. **Early blocks.** IP deny list, active bans, geo policy. These are lookups, not scans.
4. **Allow list.** Allow-listed IPs skip everything below.
5. **Hard gates.** HTTP method, URI length, body size, path traversal. A failure here is terminal and returns immediately.
6. **Body reading.** Read up to `body_limit`, then decode: gzip, deflate, brotli, UTF-16, UTF-7, base64 tokens, percent-encoding.
7. **Detection.** Signatures, injection detector, custom rules, bots, behaviour, rate limits, API gates, ML.
8. **Decision.** Individual verdicts and the threat score decide: pass, challenge, or block.
9. **Proxying.** Forward to a backend, round-robin across several.
10. **Response.** Optional DLP scan, security headers, compression, caching.

## Modes

| Mode | Blocks | Logs | Learns |
|---|---|---|---|
| `learn` | no | no | yes |
| `detect` | no | yes | yes |
| `protect` | yes | yes | yes |

Rules with `action: block` only actually block in `protect`. In `detect` they are logged as detections. This is what makes it safe to write rules against production traffic before enforcing them.

Individual gates can be softened independently with `traversal_logonly`, `method_logonly` and `ipv6_logonly`, so you can enforce most of a site while trialling one gate.

## Why decoding comes before matching

A signature engine that matches raw bytes is trivially bypassed. `union select` becomes `union/**/select`, or gets gzipped, or base64'd, or encoded as UTF-7 — and a naive matcher sees nothing.

The node normalises first and matches second. Body decompression is bounded so a decompression bomb cannot exhaust memory, and bodies whose declared `Content-Type` disagrees with their actual contents are inspected anyway.

Large bodies are inspected as a prefix plus a configurable tail (`body_tail_kb`), which catches payloads pushed past the limit by leading padding. The uninspected middle is not silently ignored: `body_oversized` makes that gap visible in the threat score.

## Detection layers

Layers are independent; each contributes a verdict, a score, or both.

- **Signatures** — substring and structural matching for SQLi, XSS, traversal, command injection, LDAP injection, XXE.
- **Injection detector** — tokenises input and fingerprints its *structure*, in the spirit of libinjection. Reacts to the shape of SQL or HTML rather than to individual scary words, which keeps false positives low.
- **Custom rules** — your own conditions, flat or as an AND/OR/NOT tree.
- **Rate limiting** — token buckets keyed by IP, token, header or cookie.
- **Bots** — user-agent heuristics, missing browser headers, TLS fingerprint mismatch, and crawler verification via forward-confirmed reverse DNS.
- **Behaviour** — how a client browses over a window: path diversity, absence of static asset fetches, user-agent rotation.
- **Anomaly (unsupervised)** — a statistical profile of normal traffic per endpoint. Works out of the box; see [anomaly.md](anomaly.md).
- **Supervised ML** — gradient-boosted trees over extracted features. The engine is here, the model is not; see [supervised-model.md](supervised-model.md).
- **Threat score** — weights the above into one number; see [threat-score.md](threat-score.md).

## State

The node keeps state in memory and persists the anomaly profile to `/var/lib/threatail`. Every in-memory map is bounded, because their keys are attacker-controlled: request paths, IP addresses, user-agent strings. A scanner sending thousands of unique paths must not be able to grow a map until the process dies, so caps and idle eviction exist throughout.

Nothing is shared between processes. Two nodes behind a load balancer keep separate rate-limit counters and separate profiles. Coordinating them is what the cloud control plane does.
