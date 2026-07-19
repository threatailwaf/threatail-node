# Model format (model.json)

Loaded by `node/src/mlmodel.rs`. Inference is `predict = sigmoid(sum of leaf values across all trees)`.

```jsonc
{
  "feature_version": 5,       // must equal the node's features::FEATURE_VERSION
  "n_features": 36,           // must equal features::N_FEATURES
  "objective": "binary",
  "trees": [                  // array of trees; each is a FLAT node array, index 0 is the root
    [
      {"leaf": false, "feature": 19, "threshold": 0.5, "left": 1, "right": 2, "default_left": true},
      {"leaf": true,  "value": -0.8},
      {"leaf": true,  "value":  1.2}
    ]
  ]
}
```

## Traversal

At each node: if `leaf`, add `value`; otherwise take `left` when `feats[feature] <= threshold` and `right` otherwise. On NaN, follow `default_left`. The `left` and `right` indices are local to their own tree.

An empty `trees` array is treated as "no model" and inference stays inactive. That is what ships in `src/default_model.json`.

## Export

`train.py::export_node_model` produces this format, flattening LightGBM's nested `dump_model()` output into the flat array.

## Two parameters you must not change

Training uses `boost_from_average=False` and `sigmoid=1.0`. With those, LightGBM's raw margin equals the sum of leaf values, so the node's inference matches LightGBM exactly.

Change either one and the node will still load the model and still produce numbers — they will just be quietly wrong, which is worse than a load failure. There is no runtime check for this, so it is on you.
