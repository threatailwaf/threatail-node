# Threatail Node

A web application firewall that runs as a reverse proxy in front of your site. Written in Rust, ships as a single static binary, and keeps all traffic on your own infrastructure.

```
client ──▶ threatail-node ──▶ your backend
             (inspect,
              block, log)
```

**Status:** beta. Run in `detect` mode first — see [Modes](#modes).

---

## What it does

- **Signature detection** — SQL injection, XSS, path traversal, command injection, scanners.
- **Evasion-resistant inspection** — decodes request bodies before matching: gzip, deflate, brotli, UTF-16, UTF-7, and comment-based SQL obfuscation (`union/**/select`). Inspects bodies whose `Content-Type` claims to be binary but isn't.
- **Rate limiting** — per path prefix, keyed by IP, token, header, or cookie. Exceeding the limit blocks or serves a proof-of-work challenge.
- **Bot handling** — crawler verification via forward-confirmed reverse DNS, so a forged `Googlebot` user-agent is caught.
- **Credential-stuffing protection** — watches login attempt velocity per IP and per username.
- **Anomaly detection** — builds a per-site profile of normal traffic and scores deviations.
- **Access control** — IP allow/deny lists, geo policy, HTTP method allow-list, TLS fingerprinting.
- **Threat score** — weighted signals combined into one number, with a configurable blocking threshold.
- **Response inspection (DLP)** — scans backend responses for leaked secrets and stack traces.
- **API protection** — JWT validation with an algorithm allow-list, JSON body limits, and OpenAPI positive-model validation. See [`docs/api-protection.md`](docs/api-protection.md).

Every request is inspected in-process. Nothing is sent to a third party.

## Requirements

- Linux, x86-64
- Ports 80 and 443 available
- A backend to proxy to

No runtime dependencies — the release binary is statically linked against musl.

## Install

### Docker

```bash
git clone https://github.com/threatailwaf/threatail-node
cd threatail-node
docker build -t threatail-node .

docker run -d --name threatail \
  -p 80:80 -p 443:443 \
  -v /etc/threatail:/etc/threatail:ro \
  -v threatail-data:/var/lib/threatail \
  threatail-node
```

There is also a `docker-compose.yml` that runs the node in front of a demo backend. Full notes: [`docs/deployment-docker.md`](docs/deployment-docker.md).

### Kubernetes

Plain manifests, no templating engine:

```bash
$EDITOR deploy/k8s/02-configmap.yaml     # your domain and backends
$EDITOR deploy/k8s/03-deployment.yaml    # your image
kubectl apply -f deploy/k8s/
```

Creates a namespace, ConfigMap, 2-replica Deployment (non-root, read-only root filesystem) and Services for traffic and metrics. Read [`docs/deployment-kubernetes.md`](docs/deployment-kubernetes.md) before production — the sections on client IPs and per-pod state matter.

### Build from source

```bash
cargo build --release
sudo install -m755 target/release/threatail-node /usr/local/bin/
```

Requires Rust 1.87 or newer. The crate itself is edition 2021; the newer toolchain is needed because some dependencies use edition 2024.

## Quick start

```bash
sudo mkdir -p /etc/threatail /var/lib/threatail
sudo cp config.example.json /etc/threatail/config.json
sudo nano /etc/threatail/config.json     # set your domain and backend
sudo threatail-node                      # reads /etc/threatail/config.json
```

Point a different config with `threatail-node /path/to/config.json`.

Verify it is inspecting:

```bash
curl -i "http://localhost/?id=1'+UNION+SELECT+password+FROM+users--"
```

In `detect` mode this returns your backend's response and writes a log line. In `protect` mode it returns 403.

## Configuration

A minimal config:

```json
{
  "listen_http": "0.0.0.0:80",
  "listen_https": "0.0.0.0:443",
  "sites": [
    {
      "domain": "example.com",
      "backends": ["http://127.0.0.1:8080"],
      "mode": "detect"
    }
  ]
}
```

See [`config.example.json`](config.example.json) for a commented, realistic setup, and [`docs/`](docs/) for reference on each subsystem.

Multiple backends are load-balanced round-robin. Multiple sites are matched by `Host`.

### Modes

| Mode      | Blocks | Logs | Learns |
|-----------|--------|------|--------|
| `learn`   | no     | no   | yes    |
| `detect`  | no     | yes  | yes    |
| `protect` | yes    | yes  | yes    |

Start in `learn` for a few days so the anomaly profile reflects your real traffic, move to `detect` to see what *would* be blocked, then to `protect`.

Individual hard gates can stay non-blocking while the rest of the site is in `protect` — see `traversal_logonly`, `method_logonly`, `ipv6_logonly`.

### TLS

Provide certificates per site, or terminate TLS upstream and run the node on HTTP behind it. See [`docs/certificates.md`](docs/certificates.md).

### Metrics

Set `metrics_listen` to expose Prometheus metrics at `/metrics`. **Bind it to an internal interface** (`127.0.0.1:9100`), or set `metrics_token` if it must be reachable. Queries and alerts are in [`docs/prometheus-grafana.md`](docs/prometheus-grafana.md).

## Machine learning

The node has two ML layers, and they behave differently out of the box:

**Anomaly detection (unsupervised) — works standalone.** The node learns a traffic profile per site and scores deviations. Nothing to install. Give it a few days of `learn` mode, and optionally set `ml_trusted_ips` so it trains only on traffic you trust.

**Supervised model — no model ships with this repo.** The inference engine is here, but the bundled model file is an empty placeholder. Training needs labeled attack data and a pipeline that this repo does not include. Without a model, supervised scoring is simply inactive; signatures, rules, rate limiting, and anomaly detection all work normally.

You can supply your own model via `ml_model_path` — the format is documented in [`docs/supervised-model.md`](docs/supervised-model.md) — or get a maintained one from Threatail Cloud (below).

## Standalone or managed

The node is fully functional on its own. Everything above works from the config file, with no account and no network calls to us.

Optionally, it can attach to **Threatail Cloud**, a hosted control plane, by setting two environment variables:

```bash
THREATAIL_CLOUD_URL=https://lk.threatail.com
THREATAIL_ENROLLMENT_TOKEN=<token from the dashboard>
```

When attached, the node pulls its policy from the cloud instead of the local file, and reports incidents and per-minute aggregates. Full request traffic still never leaves your server.

| | Standalone | With Cloud |
|---|---|---|
| Detection, rules, rate limiting, bots, anomaly | ✅ | ✅ |
| Configuration | JSON file per node | Web dashboard, all nodes |
| Managed rules / virtual patching for new CVEs | — | ✅ |
| Trained supervised ML model + retraining | bring your own | ✅ |
| Multi-node, multi-tenant, team access | — | ✅ |
| Dashboards, alerting, log retention | your own Prometheus/Grafana | ✅ |
| Certificate automation (ACME) | manual | ✅ |

If you never set `THREATAIL_CLOUD_URL`, the node logs `cloud mode disabled` at startup and never contacts us.

## Security

This is software that sits in the path of your production traffic. A few things we do about that:

- Rust, no `unsafe` in the request path.
- Dependencies are audited (`cargo audit`) on every release.
- Request body decompression is bounded to prevent decompression bombs.
- Proxying to link-local metadata addresses (`169.254.*`) is always blocked.

Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md). Don't open a public issue.

## Testing your deployment

The node is tested against [GoTestWAF](https://github.com/wallarm/gotestwaf). Run it yourself:

```bash
docker run --rm --network host wallarm/gotestwaf \
  --url http://localhost --noEmailReport
```

## Contributing

Issues and pull requests are welcome. Please:

- Run `cargo test` and `cargo clippy` before opening a PR.
- Add a test for any detection change — see the test modules in `src/verdict.rs`.
- Detection rules should come with a bypass test, not only a positive one.

## License

[Apache-2.0](LICENSE).
