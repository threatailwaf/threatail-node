# Supervised model

The node ships the inference engine for a gradient-boosted tree model, but **no trained model is included in this repository**. The bundled `src/default_model.json` is an empty placeholder.

With no model, supervised scoring is simply inactive. Signatures, custom rules, rate limiting, bot detection, behavioural analysis and [anomaly detection](anomaly.md) all work normally — they do not depend on it.

## Why there is no model here

Training needs a large labelled corpus of attack and benign traffic, and a pipeline to produce and validate it. Neither is in this repository. Shipping a model trained on someone else's traffic would give you confident-looking scores that do not reflect your application, which is worse than no model at all.

Two ways to get one:

- **Train your own.** The feature extractor is in `src/features.rs` with a Python counterpart under `ml/`. Parity between them is enforced by a test against `ml/golden.json` — if you change one, that test tells you when the other has drifted.
- **Threatail Cloud.** Provides a maintained model plus retraining on quarantined samples.

## Model format

JSON, exported from LightGBM:

```json
{
  "feature_version": 2,
  "n_features": 34,
  "objective": "binary",
  "trees": [ ... ]
}
```

`feature_version` must match the node's `FEATURE_VERSION`; a mismatch is rejected at load rather than silently scoring nonsense. Point at it with `ml_model_path`, or per site with `ml_enabled`.

The model is loaded behind an atomic swap, so it can be replaced without restarting.

## Configuration

```json
"ml_enabled": true,
"ml_threshold": 0.8,
"ml_low_threshold": 0.4,
"ml_weight": 50
```

Requests scoring between `ml_low_threshold` and `ml_threshold` fall in the grey zone: they are logged for review rather than blocked. That queue is what you label to improve the next model.

By default ML feeds the [threat score](threat-score.md) rather than blocking on its own, so a single confident-but-wrong inference cannot take out a customer by itself.

## Explainability

Inference reports per-feature contributions via the Saabas method, so a detection comes with the features that pushed the score up rather than a bare probability. When the model fires on something no signature recognises, the node reports a best-guess family from those features, or `structural` when the evidence does not clearly point anywhere.

Treat `structural` as honest rather than unhelpful: the model reacted to the shape of the request, not to a pattern it can name.
