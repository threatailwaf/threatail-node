# Threat score

Most single signals are weak on their own. A datacentre IP is not an attack. A missing `Accept-Language` header is not an attack. An unusual path is not an attack. All three together, from an IP with a poor reputation, usually is.

The threat score adds up weighted signals and blocks when the total crosses a threshold.

```json
"score_enabled": true,
"score_threshold": 100,
"score_challenge_threshold": 70
```

Below `score_challenge_threshold` the request passes. Between the two it gets a proof-of-work challenge. Above `score_threshold` it is blocked (in `protect`).

## Contributing signals

- Signature and injection detector hits
- Bot heuristics and TLS fingerprint mismatch
- Behavioural analysis
- IP reputation
- Grey-listed countries (`score_grey_countries`)
- Anomaly score
- Supervised ML probability, scaled by confidence
- The uninspected body gap (`body_oversized: 1`)

Each has a weight, and weights default to sensible values. Set them per site when a signal is more or less meaningful for your traffic.

## Tuning

Start with `score_enabled: true` in `detect` and leave the thresholds alone. The logs record the score for each request, which tells you what your real traffic looks like before you enforce anything.

Then read the distribution. If legitimate traffic clusters below 40 and known-bad sits above 90, a threshold of 100 is too lax and 70 is about right. If they overlap heavily, the answer is not a different threshold — it is that one signal is misweighted for your application, and you should find which.

Lower the threshold and false positives rise faster than catches. This is worth taking seriously: a WAF that blocks 1% of real customers is worse than no WAF, because the failure is invisible to you and total for them.

The challenge threshold is the useful middle ground. A borderline request gets a proof-of-work page rather than a 403: humans wait a second, headless bots do not solve it. When in doubt, challenge rather than block.

## Why not just use ML

The score is deliberately legible. When a request is blocked you can see which signals fired and what each contributed, and you can change a weight and predict the effect.

That property matters more than raw accuracy when someone asks why their customer got a 403. A model that is 2% better but cannot be interrogated is a worse operational tool.
