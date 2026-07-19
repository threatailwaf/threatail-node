# Metrics and dashboards

Set `metrics_listen` to expose Prometheus metrics at `/metrics` and a JSON snapshot at `/stats`.

```json
"metrics_listen": "127.0.0.1:9100",
"metrics_token": ""
```

**Bind this to an internal interface.** The endpoint reveals traffic volumes, block rates and per-site names. If it must be reachable across a network, set `metrics_token` and pass it as `Authorization: Bearer <token>`.

## Scrape config

```yaml
scrape_configs:
  - job_name: threatail
    static_configs:
      - targets: ['127.0.0.1:9100']
    # if metrics_token is set:
    # authorization:
    #   credentials: your-token
```

## Key series

| Metric | Type | Meaning |
|---|---|---|
| `threatail_requests_total` | counter | All requests |
| `threatail_blocked_total` | counter | Blocked, by `source` |
| `threatail_attacks_total` | counter | By attack `type` |
| `threatail_threat_level_total` | counter | By threat `level` |
| `threatail_latency_bucket` | histogram | WAF latency, ms |
| `threatail_upstream_latency_bucket` | histogram | Backend latency, ms |
| `threatail_upstream_errors_total` | counter | 502/504/timeouts |
| `threatail_challenge_total` | counter | Challenge outcomes |
| `threatail_ml_inferences_total` | counter | Model runs |
| `threatail_rps` | gauge | Live requests per second |
| `threatail_memory_bytes` | gauge | Process RSS |

Request, block and latency series also carry a `host` label, so dashboards can break down per site.

## Useful queries

Block rate:

```promql
sum(rate(threatail_blocked_total[5m])) / sum(rate(threatail_requests_total[5m]))
```

WAF latency, p95 — the number that answers "is the WAF slowing us down":

```promql
histogram_quantile(0.95, sum(rate(threatail_latency_bucket[5m])) by (le))
```

WAF overhead versus backend time:

```promql
histogram_quantile(0.95, sum(rate(threatail_latency_bucket[5m])) by (le))
  -
histogram_quantile(0.95, sum(rate(threatail_upstream_latency_bucket[5m])) by (le))
```

Attacks by type:

```promql
topk(10, sum by (type) (rate(threatail_attacks_total[15m])))
```

## Alerts worth having

**Block rate spike.** A sudden jump means either an attack or a rule you just deployed is eating real traffic. Both are worth waking up for, and you cannot tell which from the metric alone — check whether the increase is concentrated in one `sig`.

```promql
sum(rate(threatail_blocked_total[5m])) / sum(rate(threatail_requests_total[5m])) > 0.25
```

**Backend errors.** Distinguishes "the WAF is blocking" from "the origin is down".

```promql
sum(rate(threatail_upstream_errors_total[5m])) > 1
```

**Memory growth.** The node bounds its internal maps, but sustained growth toward the limit is worth seeing before the OOM killer does.

```promql
threatail_memory_bytes > 1.5e9
```

**Block rate falling to zero.** Less obvious and more insidious: if a site normally blocks a steady trickle and that stops, detection may have been disabled by a config change rather than the internet becoming peaceful.

## Dashboard

There is no packaged dashboard in this repository yet. A useful one has four rows: traffic and block rate; latency percentiles for WAF and backend side by side; attacks by type and by site; and process memory. The queries above cover all of it.
