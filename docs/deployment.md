# Deployment

The node is a **terminating reverse proxy**: it accepts the connection, terminates TLS,
inspects the request and forwards it to your server. Where you place it decides how
everything else behaves — above all whether the node sees the **real client IP**. Geo
policy, rate limiting, auto-ban and the behavioural profile all key on it.

Four shapes cover almost every case.

---

## 1 · In front of your server

The simplest, and the one to prefer. DNS points at the node; the node forwards to your
backend, which no longer needs to be reachable from the internet.

```
internet ──▶ threatail-node ──▶ your backend
                (TLS, WAF)        (private)
```

**Requirements:** inbound 80 and 443, outbound HTTPS to the cloud, a public IP.

**Close the backend to everything except the node.** Otherwise an attacker who finds its
address bypasses the WAF entirely by going straight there — the most common way a
correctly configured WAF ends up doing nothing.

---

## 2 · Behind a CDN or load balancer

The CDN terminates the visitor's connection, so the node sees the CDN's address on every
request.

```
internet ──▶ CDN ──▶ threatail-node ──▶ your backend
```

**Add the CDN ranges to Trusted proxies.** For Cloudflare this is one click. Without it
every visitor shares a single identity: rate limits throttle everyone at once, geo reads
the CDN's country, and auto-ban blocks the CDN itself. Nothing reports an error — the
protection simply stops distinguishing people. Check this whenever behaviour looks
"global" rather than per-client.

TLS fingerprinting is affected too: the handshake belongs to the CDN, not the visitor.
Either have the CDN forward the client fingerprint in a header and name that header in the
site settings, or leave the check off.

---

## 3 · In front of a Kubernetes or k3s cluster

The node stays **outside** the cluster — on its own VM or in a DMZ — and treats the
cluster as an ordinary upstream. Nothing about Kubernetes needs to change.

```
internet ──▶ threatail-node ──▶ cluster entry ──▶ pods
                                (LoadBalancer,
                                 NodePort or
                                 your ingress)
```

Point the node's backend at any stable entry point. From the node's side it is an address
and a port; scaling pods up and down changes nothing.

**Running the node inside the cluster** is possible but brings caveats the shapes above do
not have. With the default `externalTrafficPolicy: Cluster`, kube-proxy rewrites the
source address and the node sees the cluster node instead of the visitor. And several
replicas split the in-memory state — see shape 4. If you go that way, set
`externalTrafficPolicy: Local` and start with a single replica.

---

## 4 · Several nodes

Run more than one node for redundancy or to be closer to your users. A site is assigned to
one node or to all of them; DNS round-robin or a load balancer spreads the traffic.

**What is shared:** configuration, rules, the trained model and auto-ban decisions. They
come from the cloud and are identical everywhere.

**What is not:** rate-limit counters and the learned traffic profile live in each node's
memory. With N nodes, a limit of 100 requests per second allows up to N×100 in the worst
case, and the profile learns proportionally slower.

For strict limits, either serve the site from a single node or divide the limit by the
node count.

---

## What the node needs, in any shape

| | |
|---|---|
| Inbound | 80 and 443 from the internet |
| Outbound | HTTPS to the Threatail cloud — configuration, model, events |
| Inbound from us | none, ever. The node initiates every connection |
| Disk | a persistent path for enrollment and state (a Docker volume, if containerised) |
| Backend | reachable from the node, and ideally from nowhere else |

If the cloud is unreachable, the node keeps serving traffic with its last known
configuration. A cloud outage does not take your site down.

---

## Certificates

The node can obtain and renew certificates from Let's Encrypt automatically. Plain domains
use HTTP-01, which requires the domain to already resolve to the node and port 80 to be
reachable — a firewall on 80 is the usual reason issuance fails, even for sites that only
serve HTTPS. Wildcards use DNS-01 instead.

You can also upload your own certificate, including an origin certificate issued by your
CDN. Behind a CDN in strict mode this is often the simpler choice: no ACME on the origin
and nothing to renew.
