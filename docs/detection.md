# What it detects

Detection happens inside the node, in one pass, in the order below. Nothing is sent
anywhere to be decided.

---

## Modes

| Mode | Blocks | Logs | Learns |
|---|---|---|---|
| `learn` | no | no | yes |
| `detect` | no | yes | yes |
| `protect` | yes | yes | yes |

Start in `learn` for a few days so the traffic profile reflects reality, move to `detect`
to see what *would* be blocked, and only then to `protect`. The dashboard has a
**Ready for protect?** check that replays the last week and tells you how many requests
would have been acted on — run it before you flip the switch, not after.

Switching back to `detect` costs nothing: detection, review queue and learning all keep
running.

---

## Decoding

Matching a raw request catches only careless attackers. Payloads are unwrapped first:

- gzip, deflate, brotli
- UTF-16, UTF-7
- percent-encoding and backslash escapes, applied repeatedly until stable
- HTML entities
- long base64 tokens, expanded and inspected
- comment-based SQL obfuscation — `union/**/select` normalises to `union select`

Bodies whose declared `Content-Type` claims to be binary but is not are inspected anyway.

**All request headers are inspected**, not a shortlist of three. An attack can be carried
in a header nobody thought to check, and that is exactly where it gets carried.

---

## Detectors

**Signatures** — SQL injection, XSS, path traversal, command injection, SSRF, XXE, SSTI,
LDAP injection, scanner fingerprints. Matches are confirmed **field by field**: a phrase
split across two harmless parameters is not counted, which is where a large share of false
positives comes from in simpler engines.

**Your rules** — match on any part of the request: path, query, a single parameter, body,
method, a named header, country, ASN, TLS fingerprint. Conditions combine with AND, OR and
NOT. Actions: block, challenge, allow, or log-only.

**Managed rules** — virtual patches for known CVEs, delivered from the cloud. They protect
an application you cannot update today without touching its code.

**Rate limiting** — per path prefix, keyed by IP, token, header or cookie. Over the limit
means a block or a proof-of-work challenge. Optional adaptive tightening squeezes every
limit while the whole site is under load.

**Bot handling** — search crawlers are verified by forward-confirmed reverse DNS, a check
only the real owner of the network can pass. Verified crawlers skip bot blocking, so
tightening bot protection does not cost you search indexing. The same check exposes the
opposite case: a user-agent claiming to be a crawler whose address does not confirm.

**Account takeover** — watches login endpoints for three shapes: many distinct logins from
one address (credential stuffing), one login from many addresses (distributed brute
force), and plain volume.

**Anomaly detection** — builds a profile of normal traffic per path and scores deviations.
It needs no labels and starts working on its own.

**Machine learning** — borderline requests are queued for you to label attack or normal.
Those labels train a model **for your site**, not a generic one. The dashboard shows a
readiness level that says plainly what the model can be trusted with, and what is missing
before it can be trusted with more.

**API protection** — JWT validation with signature verification, JSON body hygiene, and
OpenAPI positive-model validation where only what your schema describes is allowed.

**Response inspection** — scans what your backend sends back for leaked secrets, stack
traces and card numbers. Matches can be logged, masked or blocked.

---

## How the decision is made

Every detector contributes weighted points to one **threat score**. A single configurable
threshold decides.

This matters more than it sounds. A single suspicious signal — an unusual country, a
missing header — should not block a customer. Several together should. A score with one
threshold expresses that directly, and gives you one number to tune instead of a dozen
switches to guess at.

Signature detections and the model feed the score rather than blocking on their own, so
precision is not paid for with your customers' access.

---

## False positives

They will happen. What matters is how quickly you can tell what happened and fix it
without turning protection off.

Every event carries the evidence: the URL, the headers, the inspected part of the body,
the network the request came from, and the TLS fingerprint. Automatic flags answer
"is this a real visitor?" faster than reading raw headers — whether the address belongs to
a data centre, whether several clients sit behind it, whether an intermediary is present,
whether the declared language matches the geography.

One click marks an event as a false positive: it adds an allow exception for that path and
teaches the model the request was normal.

That is also the broadest fix. If only one detector is wrong — a legitimate `/search`
query tripping SQLi — suppress **that signal on that path** and leave every other
protection in place.

The threshold at which the model acts is calibrated against a target false-positive rate
measured on your own traffic, and reported with a confidence interval rather than a single
number, because a rate estimated from a sample is a range.
