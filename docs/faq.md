# FAQ

Questions people ask before installing anything in front of production.

---

### What happens if the node crashes or the server dies?

The node is inline, so if it stops, traffic to that node stops. This is true of every
inline WAF, ours included, and it is the honest trade-off for inspecting requests before
they reach your application.

What you can do about it: run more than one node and spread traffic with DNS or a load
balancer, or keep a DNS record you can flip back to the origin. The node itself is a
single static binary with no runtime dependencies and no database, which removes most of
the usual reasons a proxy falls over.

### What happens if your cloud goes down?

Nothing on your side. The node keeps serving traffic with its last known configuration,
rules and model. It fetches updates over an outbound connection; when there is nothing to
fetch, it carries on with what it has.

Events queue locally and are delivered when the connection returns.

### Does my traffic go through your servers?

No. Every request is decided inside the node, on your server. The cloud holds
configuration, the trained model and the dashboard.

What is sent to us are **decisions and their evidence**: blocks, challenges, detections
and the requests queued for your review. An event carries the URL, the headers and a
truncated fragment of the body — without them a detection cannot be judged, and a queue
item cannot be labelled.

Ordinary passing traffic is not recorded at all unless you switch full logging on.

If a request contains something that must never leave your infrastructure, response
inspection can mask it, and you can exclude paths from logging entirely.

### How much latency does it add?

Inspection is in-process, with no network call in the path. Cheap checks run first and
most requests never reach the expensive ones: a request with no query and no body on a
static path skips content analysis entirely, and the signature engine confirms field by
field only after a cheap pass has already fired.

Measure it on your own traffic rather than trusting a number from a vendor page — your
payload sizes and endpoint mix decide the answer, and `detect` mode lets you measure
without risk.

### Will it break my API clients?

That is what `detect` mode is for. API clients are the usual source of surprises: they
send bodies no browser sends, skip headers every browser sends, and cannot solve a
challenge.

Run in `detect`, look at what would have been blocked, and add exceptions before you
switch. The dashboard shows exactly which detector fired on which path.

### Do I have to label anything for it to work?

No. Signatures, rules, rate limiting, bot handling and anomaly detection all work from the
first day with no labels at all.

Labelling trains the model for your site specifically. It is what turns a system that
knows attacks in general into one that knows what is normal in **your** application, and
that is where the large reductions in false positives come from. Half an hour a week is
enough.

### Can I run it without the cloud?

The node needs the cloud for configuration, the model and the dashboard. There is no
offline mode today.

### What does it run on?

Linux x86-64, ports 80 and 443, outbound HTTPS. A single static binary or a container.
No database, no runtime, no agent inside your application.

### Does it work behind Cloudflare?

Yes. Add the Cloudflare ranges to trusted proxies so the node sees the real visitor
address rather than Cloudflare's — see [Deployment](deployment.md). Note that TLS
fingerprinting sees the CDN's handshake, not the visitor's.

### Does it handle certificates?

It can obtain and renew them from Let's Encrypt automatically, or you can upload your own,
including a CDN origin certificate.

### How is it priced?

Plans and limits are shown in the dashboard. Start an account and look — no card is
required to create one.

### Where is the rest of the documentation?

Inside the dashboard, under **Documentation**, next to the settings it describes. It
covers rules, rate limiting, bots, the model and quarantine, API protection, account
takeover, response inspection, reading an event, and troubleshooting.

Keeping it there rather than here means it is one click from the switch it explains, and
it cannot drift out of date relative to the version you are actually running.
