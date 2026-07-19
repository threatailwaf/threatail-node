# Feature vector

`FEATURE_VERSION = 5`, `N_FEATURES = 36`. Position equals index.

The source of truth is `features.py`, which mirrors `node/src/features.rs`. Parity between the two is enforced by `golden.json` — run `python3 features.py` to check it.

Attack signals are computed **separately per request part**, which localises a detection to the path, query or body rather than reporting one blended number.

## Global block (0-9)

Part lengths, parameter and segment counts, keyword total, and entropy and character ratios over the whole payload.

| # | Name |
|---|---|
| 0 | len_path |
| 1 | len_query |
| 2 | len_body |
| 3 | n_params |
| 4 | n_segments |
| 5 | kw_total |
| 6 | entropy_total |
| 7 | ratio_special_total |
| 8 | ratio_digits_total |
| 9 | ratio_upper_total |

## Per-part block

Eight signal features for each part: path (10-17), query (18-25), body (26-33).

| Offset | Name |
|---|---|
| +0 | kw_sql |
| +1 | kw_xss |
| +2 | kw_path |
| +3 | kw_cmd |
| +4 | ratio_special |
| +5 | entropy |
| +6 | n_angle (`<`, `>`) |
| +7 | n_quote (`'`, `"`) |

So `kw_sql_path` is 10, `kw_sql_query` is 18, `kw_sql_body` is 26.

## Detector verdicts (34-35)

| # | Name |
|---|---|
| 34 | det_sqli — siginj SQLi verdict over the whole payload, 0 or 1 |
| 35 | det_xss — siginj XSS verdict over the whole payload, 0 or 1 |

## Changing the feature set

Adding, removing or reordering a feature means bumping `FEATURE_VERSION` in **both** `features.rs` and `features.py`, regenerating `golden.json`, and retraining. The node rejects a model whose `feature_version` does not match its own, which is deliberate: silently scoring a request against a mismatched vector produces confident nonsense.
