# Deploying on Kubernetes

Manifests live in [`deploy/k8s/`](../deploy/k8s/). They are plain YAML with no templating engine, so you can read them, edit them and apply them directly.

## Quick start

```bash
# 1. Build and push the image
docker build -t ghcr.io/threatailwaf/threatail-node:latest .
docker push ghcr.io/threatailwaf/threatail-node:latest

# 2. Edit the config and the image reference
$EDITOR deploy/k8s/02-configmap.yaml     # your domain and backends
$EDITOR deploy/k8s/03-deployment.yaml    # image: ghcr.io/OWNER/...

# 3. Apply
kubectl apply -f deploy/k8s/
kubectl -n threatail rollout status deployment/threatail-node
```

## What gets created

| File | Object |
|---|---|
| `01-namespace.yaml` | `threatail` namespace |
| `02-configmap.yaml` | the node config, same format as `config.example.json` |
| `03-deployment.yaml` | 2 replicas, non-root, read-only root filesystem |
| `04-service.yaml` | `LoadBalancer` for traffic, `ClusterIP` for metrics |

The node listens on 8080/8443 inside the pod rather than 80/443, so it never needs privileged ports or extra capabilities. The Service maps 80 and 443 onto them.

## Pointing at your application

In the ConfigMap, `backends` takes any address the pod can reach, which for an in-cluster Service is:

```
http://<service>.<namespace>.svc.cluster.local:<port>
```

For example, an app exposed as Service `my-app` in `default`:

```json
"backends": ["http://my-app.default.svc.cluster.local:80"]
```

Several entries are load-balanced round-robin by the node itself.

## Configuration changes

The node reads its config once at startup. After editing the ConfigMap, restart the pods:

```bash
kubectl -n threatail rollout restart deployment/threatail-node
```

## Client IP addresses

This is the part most likely to bite you, and it fails quietly: rate limits, auto-bans and behavioural detection all key on the client IP, so a wrong IP means those features silently degrade instead of erroring.

The manifests set `externalTrafficPolicy: Local` on the LoadBalancer Service, which preserves the real source IP and avoids an extra hop. Keep it unless you have a reason not to.

If anything terminates connections in front of the node — an ingress controller, a cloud L7 load balancer, a CDN — the node sees *its* address on every request. Then you must list that component's pod or node CIDR in `trusted_proxies` for the site:

```json
"trusted_proxies": ["10.0.0.0/8"]
```

Only then does the node trust `X-Forwarded-For`. It ignores that header from untrusted sources deliberately: otherwise any client could forge a source IP and walk straight past every per-IP control.

## Where the node sits

Two sensible topologies:

**In front of the ingress (recommended).** The `LoadBalancer` Service receives external traffic and the node forwards to your app. Traffic is inspected before it reaches anything else, which is the point of a WAF.

**Behind an existing ingress.** Change the Service to `ClusterIP`, route your ingress to it, and set `trusted_proxies` to the ingress controller's CIDR. Simpler to retrofit, but the ingress is exposed to raw traffic first.

## Replicas and shared state

Replicas are independent. Each pod keeps its own anomaly profile, its own rate-limit counters and its own local bans; nothing is shared between them.

The practical consequences:

- **Rate limits are per pod.** A limit of 20 rps across 3 replicas allows up to 60 rps in the worst case, depending on how the load balancer spreads connections. Divide your intended limit by the replica count, or accept the looser bound.
- **Anomaly profiles train separately.** Each pod needs its own learning period, so give the deployment longer in `learn` mode than a single node would need.
- **Scaling up dilutes training.** A new pod starts with no profile at all.

Shared state across nodes — one profile, cluster-wide rate limits, coordinated bans — is what the cloud control plane provides. Standalone replicas do not coordinate.

## Persisting the anomaly profile

The manifests use `emptyDir` for `/var/lib/threatail`, so each pod relearns from scratch on restart. That is fine for evaluation and bad for production.

For a stable profile, switch to a StatefulSet with a `volumeClaimTemplate` so every replica keeps its own persistent volume across restarts. A shared `ReadWriteMany` PVC is *not* a substitute: the pods would overwrite each other's profile files.

## Metrics

The `threatail-metrics` Service exposes port 9100 inside the cluster. With the Prometheus Operator:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: threatail-node
  namespace: threatail
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: threatail-node
  endpoints:
    - port: metrics
      interval: 30s
```

Metrics carry a `host` label, so you can break dashboards down per site.

## TLS

Either terminate TLS at the node (configure certificates per site and use the 443 port), or terminate it at your ingress and run the node on HTTP with `trusted_proxies` set. Certificates from cert-manager can be mounted as a Secret and referenced from the site config.

## Resource sizing

The requests in the manifest (200m CPU, 256Mi memory) are a starting point, not a measurement. Real usage depends on request rate, body inspection limits and how many sites the node serves.

Memory is the one to watch: the anomaly profile and the various tracking maps grow with the number of distinct paths and client IPs. The node bounds these internally, but a scanner hitting thousands of unique paths will push memory toward the ceiling. Watch `container_memory_working_set_bytes` for the first week and set limits from what you observe.

## Troubleshooting

```bash
kubectl -n threatail logs -l app.kubernetes.io/name=threatail-node --tail=50
```

At startup the node logs the config it loaded and how many sites it found. `config loaded: ... (0 sites)` means the ConfigMap parsed but contains nothing useful.

If requests return 404 or reach the wrong place, the `Host` header probably does not match any configured `domain` — that is how the node routes.
