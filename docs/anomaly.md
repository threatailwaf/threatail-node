# Anomaly detection

This layer is unsupervised: it learns what your traffic normally looks like and scores deviations. It needs no model file and no training data — just time.

## How it works

The node keeps a statistical profile per site and per endpoint. For each endpoint it tracks the distribution of:

- number of parameters
- mean and maximum value length
- ratio of special characters
- ratio of digits
- Shannon entropy of the payload
- which argument names it has seen before

A request is scored by how far it sits from that endpoint's profile, in standard deviations. The score combines the mean deviation across features with the largest single deviation, because an attack often spikes exactly one feature — a long injection string, a burst of punctuation — while the average stays unremarkable.

The result is a number from 0 to 1, fed into the [threat score](threat-score.md) or used directly when `anomaly_block` is on.

## Training

```json
"anomaly_sens": "medium",
"anomaly_block": false,
"ml_trusted_ips": []
```

An endpoint is not scored until it has enough observations, so new endpoints are ignored rather than flagged. Run in `learn` or `detect` for a few days first: profiles built from a couple of hours of traffic will produce noise once enforced.

`ml_trusted_ips` restricts training to addresses you trust. It is the right setting if you can identify clean traffic — your own QA, an office range, a synthetic monitor — because it means an attacker cannot teach the profile that their behaviour is normal. Left empty, the node learns from everything it sees, which is fine on a site that is not yet under sustained attack and risky on one that is.

Profiles persist to `/var/lib/threatail`. Without that path on a persistent volume, every restart discards training.

## Sensitivity

| Setting | Threshold | Use when |
|---|---|---|
| `low` | permissive | traffic is varied; you want the score, not blocks |
| `medium` | balanced | default |
| `high` | strict | a small, predictable API surface |

`high` on a site with diverse, human-driven traffic will produce false positives. It suits a machine-to-machine API where requests genuinely all look alike.

## What it catches, and what it does not

It catches things no signature covers: a novel payload shape, a parameter suddenly carrying 4 KB where it always carried 12 bytes, an endpoint receiving arguments it has never seen.

It does not understand attacks. It measures unusualness. A legitimate feature launch that changes request shape looks exactly like an anomaly, which is why `anomaly_block` defaults to false — the signal is most useful as a contribution to the threat score, where it has to agree with something else before anything gets blocked.

If you deploy a change that alters request structure, expect a bump in anomaly scores until the profile catches up. You can reset a profile from the config when a change makes the old baseline meaningless.

## Memory

The profile is keyed by normalised request path, and paths are attacker-controlled. A scanner walking thousands of unique URLs would grow that map without bound, so the node caps the number of tracked endpoints per site and the number of argument names per endpoint. Past the cap it keeps updating known endpoints and stops adding new ones — the profile degrades rather than the process dying.
