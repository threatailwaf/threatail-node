# Deploying with Docker

The node is a single static binary, so the image is small and has no runtime dependencies.

## Build the image

```bash
git clone https://github.com/threatailwaf/threatail-node
cd threatail-node
docker build -t threatail-node .
```

The build is multi-stage: a `rust:1.85-alpine` stage compiles a statically linked musl binary, and the final image is Alpine plus `ca-certificates`. Expect a few minutes for a cold build; dependency layers are cached afterwards.

## Run

```bash
mkdir -p /etc/threatail
cp config.example.json /etc/threatail/config.json
# edit the domain and backends

docker run -d --name threatail \
  -p 80:80 -p 443:443 \
  -v /etc/threatail:/etc/threatail:ro \
  -v threatail-data:/var/lib/threatail \
  threatail-node
```

`/etc/threatail/config.json` is read at startup. To use a different path, pass it as an argument:

```bash
docker run -d ... threatail-node /etc/threatail/other.json
```

### Why the two volumes

| Mount | Purpose |
|---|---|
| `/etc/threatail` (read-only) | your config file |
| `/var/lib/threatail` | the anomaly profile and other learned state |

The second one matters more than it looks. The node builds a statistical profile of normal traffic per site, and that profile lives in `/var/lib/threatail`. Without a persistent volume, every container restart throws away what the node learned and anomaly detection starts from zero.

## Docker Compose

`docker-compose.yml` in the repository root runs the node in front of a demo backend:

```bash
cp config.example.json config.json
# point "backends" at http://backend:80
docker compose up -d
```

Replace the `backend` service with your application, or delete it and point `backends` at an address reachable from the container.

Note that `127.0.0.1` inside the container is the container itself, not the host. To reach a service on the Docker host, use `host.docker.internal` (Docker Desktop) or the host's LAN address, and add `--add-host=host.docker.internal:host-gateway` on Linux.

## Networking and client IPs

The node makes decisions per client IP: rate limits, bans, behavioural analysis. If it sees the wrong IP, those features degrade quietly rather than failing loudly, so it is worth getting right.

Published ports via `-p` preserve the real client IP, so the default setup is fine.

If something else terminates connections in front of the node — a cloud load balancer, another reverse proxy, a CDN — the node sees that intermediary's address on every request. In that case list the intermediary's subnets in `trusted_proxies` for the site, which tells the node to read `X-Forwarded-For` instead:

```json
"trusted_proxies": ["10.0.0.0/8"]
```

Without this the node ignores `X-Forwarded-For` on purpose, since an untrusted client could otherwise forge any source IP and evade every per-IP control.

## TLS

Two options:

1. **Terminate TLS at the node.** Configure certificates per site and expose 443.
2. **Terminate ahead of it.** Run the node on HTTP only and let your load balancer or ingress handle certificates. Set `trusted_proxies` as above.

## Metrics

Set `metrics_listen` to `0.0.0.0:9100` inside the container and publish it only where Prometheus can reach it:

```bash
-p 127.0.0.1:9100:9100
```

Do not publish the metrics port to the internet. If it must be reachable across a network, set `metrics_token` as well.

## Running unprivileged

The image runs as a non-root user and the container filesystem can be read-only:

```bash
docker run -d --read-only \
  --tmpfs /tmp \
  -v threatail-data:/var/lib/threatail \
  ...
```

`/var/lib/threatail` must stay writable, since that is where the profile is persisted.

## Logs

The node logs to stdout, so `docker logs threatail` works normally. Log level is controlled by `RUST_LOG`:

```bash
-e RUST_LOG=info     # default
-e RUST_LOG=debug    # verbose, useful when tuning rules
```

## Checking it works

```bash
curl -i "http://localhost/?id=1'+UNION+SELECT+password+FROM+users--"
```

In `detect` mode you get your backend's response plus a log line. In `protect` mode you get 403. If neither happens, the request is probably not reaching the node — check that the `Host` header matches a configured `domain`.
