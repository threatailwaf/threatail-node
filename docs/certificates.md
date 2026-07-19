# TLS certificates

Two supported topologies. Pick based on where you want TLS to terminate.

## Terminate at the node

Set `listen_https` and list your certificates at the top level of the config:

```json
"listen_https": "0.0.0.0:443",
"certs": [
  {
    "domains": ["example.com", "www.example.com"],
    "cert_file": "/etc/threatail/certs/example.com.crt",
    "key_file":  "/etc/threatail/certs/example.com.key"
  }
]
```

`cert_file` is the PEM chain with the leaf first, then any intermediates. Omitting the intermediates is the usual cause of "works in my browser, fails from curl": browsers often fill the gap from cache, other clients do not.

`domains` are matched against SNI, exactly and case-insensitively. List each name that appears in the certificate's SAN. A wildcard certificate for `*.example.com` still needs the names you intend to serve listed here.

The node selects a certificate by SNI on each handshake, and the store is swapped atomically, so certificates can be replaced without a restart.

**With `certs` empty and `listen_https` set, the listener binds but has no certificate to present, and every handshake fails.** The node logs the certificate count at startup — check for `certificates: N domains from config`.

Wildcard certificates work: a certificate stored for `*.example.com` serves any subdomain. If both an exact and a wildcard entry match, the exact one wins.

## Terminate ahead of the node

Run the node on HTTP only and let a load balancer, ingress controller or CDN handle certificates. This is often simpler in Kubernetes, where cert-manager already exists.

One thing you must do in this topology: set `trusted_proxies` to the CIDR of whatever sits in front.

```json
"trusted_proxies": ["10.0.0.0/8"]
```

Without it the node ignores `X-Forwarded-For` and attributes every request to the proxy's address. Rate limits, bans and behavioural detection then key on a single IP and stop working in a way that produces no error — the counters simply never look right.

## ACME

Automated certificate issuance and renewal is part of Threatail Cloud, not the standalone node. Standalone, use whichever ACME client you already run — certbot, lego, cert-manager — and point the site config at the resulting files, or terminate TLS at a component that handles it for you.

If you serve HTTP-01 challenges through the node, keep `/.well-known/acme-challenge/` reachable. An overly broad blocking rule or an `allowed_methods` list that omits `GET` will break renewal, and the failure surfaces sixty days later when the certificate expires rather than at the moment you make the mistake.

## HSTS and related headers

`sec_headers: true` adds `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and, over HTTPS, `Strict-Transport-Security` — but only when the backend has not already set them.

HSTS deserves a moment's thought before you enable it. Once a browser has seen the header it will refuse plain HTTP for that domain for the max-age duration, and you cannot retract that decision from the server side. Make sure every subdomain you serve can do HTTPS before turning it on.

## Mutual TLS

Client-certificate authentication needs two things per site: the paths it applies to, and the CA that client certificates are checked against.

```json
{
  "domain": "api.example.com",
  "mtls_locations": ["/api/"],
  "mtls_ca_file": "/etc/threatail/certs/client-ca.pem",
  "mtls_revoked": ["3a7f2b1c"]
}
```

Both are required. `mtls_locations` on its own only establishes that some certificate was presented, and presentation is not authentication — the CA is what makes it mean anything. The node logs `mTLS: N domains from config` at startup, and refuses to enable mTLS for a domain that has no certificate of its own.

`mtls_revoked` holds serial numbers in hex. They are normalised and checked on every request, so revoking one takes effect at the next config reload rather than at the next CRL fetch.

## Backend certificates

If the node proxies to an origin over HTTPS with a self-signed certificate or an IP address, set `insecure_backend: true` for that site.

Scope it narrowly. It disables validation for that site's backend connections entirely, so use it for a trusted internal origin rather than as a quick fix for a certificate error you have not investigated.
