"""
Trains the supervised detector (LightGBM) and exports it to the node's JSON format
(node/src/mlmodel.rs). Supports the expert model and fine-tuning on top of it.

IMPORTANT about the node format: predict = sigmoid(sum of all tree leaves), with NO separate
init score. We therefore train with boost_from_average=False and sigmoid=1.0, which makes
LightGBM's raw margin exactly equal the leaf sum, so the node's inference matches one to one.

Scenarios:
  # 1) build the EXPERT model from the curated seed corpus (production-ready on day one)
  python3 train.py --seed-only --lgb-out expert.txt --out expert.model.json

  # 2) FINE-TUNE it on a larger corpus (synthetic, public or customer data)
  python3 synth.py --n 60000 --out synth.jsonl
  python3 train.py --data synth.jsonl --init-model expert.txt \
                   --lgb-out prod.txt --out model.json

  # 3) train from scratch on your own data
  python3 train.py --data synth.jsonl --data labeled_client.jsonl --out model.json

Input format (jsonl): {"path":..., "query":..., "body":..., "label":0|1}
The --out target is model.json for the node (THREATAIL_ML_MODEL_PATH).
"""
from __future__ import annotations
import argparse
import json
import sys

import features as F


# ---------------- data ----------------
def load_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def to_xy(rows):
    X, y = [], []
    for r in rows:
        X.append(F.extract(r.get("path", ""), r.get("query", ""), r.get("body", "")))
        y.append(int(r["label"]))
    return X, y


# ---------------- exporting LightGBM to the node format ----------------
def flatten_tree(struct: dict) -> list:
    """LightGBM's nested tree (dump_model) to the node's flat Vec<Node>, index 0 being the root."""
    nodes = []

    def rec(d: dict) -> int:
        idx = len(nodes)
        nodes.append(None)  # placeholder, filled in after recursing into the children
        if "split_feature" not in d:  # leaf
            nodes[idx] = {"leaf": True, "value": float(d.get("leaf_value", 0.0))}
        else:
            left = rec(d["left_child"])
            right = rec(d["right_child"])
            nodes[idx] = {
                "leaf": False,
                "feature": int(d["split_feature"]),
                "threshold": float(d["threshold"]),
                "left": left,
                "right": right,
                "default_left": bool(d.get("default_left", True)),
            }
        return idx

    rec(struct)
    return nodes


def export_node_model(booster, out_path: str):
    dump = booster.dump_model()
    trees = []
    for ti in dump.get("tree_info", []):
        trees.append(flatten_tree(ti["tree_structure"]))
    model = {
        "feature_version": F.FEATURE_VERSION,
        "n_features": F.N_FEATURES,
        "objective": "binary",
        "trees": trees,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(model, f)
    return len(trees)


# ---------------- training ----------------
def train(rows, init_model=None, rounds=300, lr=0.05, leaves=31, seed=42, class_weight=True):
    import lightgbm as lgb  # imported here so --help works without the dependency installed
    import numpy as np
    import os

    # warm start is optional: with no file we train from scratch rather than failing
    if init_model and not os.path.exists(init_model):
        print(f"⚠ init-model '{init_model}' not found; training from scratch (warm start skipped). "
              f"To enable it, create it first with --seed-only --lgb-out {init_model}")
        init_model = None

    X, y = to_xy(rows)
    X = np.asarray(X, dtype=np.float32)
    y = np.asarray(y, dtype=np.int32)
    ds = lgb.Dataset(X, label=y, feature_name=F.FEATURE_NAMES, free_raw_data=False)
    params = {
        "objective": "binary",
        "boosting_type": "gbdt",
        # CRITICAL for matching the node: no init score and the standard sigmoid
        "boost_from_average": False,
        "sigmoid": 1.0,
        "learning_rate": lr,
        "num_leaves": leaves,
        "min_data_in_leaf": 20,
        "feature_fraction": 0.9,
        "bagging_fraction": 0.8,
        "bagging_freq": 1,
        "max_depth": -1,
        "verbose": -1,
        "seed": seed,
    }
    # Class weighting: real traffic is around 99% normal, and bulk labelling by IP yields
    # mostly negatives, so without correction the model collapses into 'everything is normal'.
    # scale_pos_weight = n_neg/n_pos, clamped so it does not skew the other way.
    if class_weight:
        n_pos = int((y == 1).sum())
        n_neg = int((y == 0).sum())
        if n_pos > 0 and n_neg > 0:
            spw = n_neg / n_pos
            params["scale_pos_weight"] = float(min(max(spw, 0.25), 10.0))
    booster = lgb.train(
        params, ds, num_boost_round=rounds,
        init_model=init_model,  # warm start: fine-tuning on top of the expert model
    )
    return booster


def collect_rows(args):
    rows = []
    if args.seed_only:
        import expert_seed
        rows = list(expert_seed.dataset())
    else:
        if args.with_seed:
            import expert_seed
            rows += list(expert_seed.dataset())
        for p in args.data or []:
            rows += load_jsonl(p)
    if not rows:
        sys.exit("no data: pass --data ... or --seed-only")
    return rows


def main():
    ap = argparse.ArgumentParser(description="Train the supervised detector and export it to the node format")
    ap.add_argument("--data", action="append", help="jsonl with {path,query,body,label}; may be given several times")
    ap.add_argument("--seed-only", action="store_true", help="train ONLY on the expert seed corpus")
    ap.add_argument("--with-seed", action="store_true", help="mix the expert seed into --data")
    ap.add_argument("--init-model", default=None, help="LightGBM .txt to fine-tune on top of (warm start)")
    ap.add_argument("--out", default="model.json", help="output: model.json for the node")
    ap.add_argument("--lgb-out", default=None, help="save the native LightGBM .txt, for a future --init-model")
    ap.add_argument("--rounds", type=int, default=300)
    ap.add_argument("--lr", type=float, default=0.05)
    ap.add_argument("--leaves", type=int, default=31)
    ap.add_argument("--eval-frac", type=float, default=0.0, help="fraction held out for a quick evaluation (0 disables it)")
    args = ap.parse_args()

    rows = collect_rows(args)
    pos = sum(r["label"] for r in rows)
    print(f"data: {len(rows)} ({pos} attacks / {len(rows)-pos} normal)"
          + (f", init_model={args.init_model}" if args.init_model else ""))

    if args.eval_frac > 0:
        import random
        random.Random(0).shuffle(rows)
        k = int(len(rows) * (1 - args.eval_frac))
        train_rows, eval_rows = rows[:k], rows[k:]
    else:
        train_rows, eval_rows = rows, None

    booster = train(train_rows, init_model=args.init_model,
                    rounds=args.rounds, lr=args.lr, leaves=args.leaves)

    if args.lgb_out:
        booster.save_model(args.lgb_out)
        print(f"native model -> {args.lgb_out} (for --init-model when fine-tuning)")

    n_trees = export_node_model(booster, args.out)
    print(f"node model -> {args.out} ({n_trees} trees, feature_version={F.FEATURE_VERSION})")

    if eval_rows:
        evaluate(booster, eval_rows)


def metrics_at(booster, rows, thr=0.5):
    """Precision, recall and F1 over `rows` at threshold `thr`. Returns a dict."""
    import numpy as np
    if not rows:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "n": 0, "thr": thr}
    X, y = to_xy(rows)
    p = booster.predict(np.asarray(X, dtype=np.float32))
    y = np.asarray(y)
    pred = (p >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"precision": prec, "recall": rec, "f1": f1, "n": len(rows), "thr": thr,
            "tp": tp, "fp": fp, "fn": fn}


def best_threshold(booster, rows, target_precision=0.99):
    """Select an operating point (threshold) from the PR curve on the holdout set.
    Returns a dict:
      f1_opt  — the threshold maximising F1, a precision/recall compromise;
      p_floor — the threshold maximising recall subject to precision >= target_precision
                (for blocking: 'no more than X% false positives'); None when unattainable.
    Neither the model nor the features change; this only picks an operating point.
    """
    import numpy as np
    out = {"target_precision": float(target_precision)}
    if not rows:
        return out
    X, y = to_xy(rows)
    p = booster.predict(np.asarray(X, dtype=np.float32))
    y = np.asarray(y)
    if int((y == 1).sum()) == 0 or int((y == 0).sum()) == 0:
        return out
    cand = np.unique(p)
    if len(cand) > 512:
        cand = np.unique(np.quantile(p, np.linspace(0.0, 1.0, 512)))
    best_f1 = None
    best_floor = None
    for thr in cand:
        pred = (p >= thr).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        prec = tp / (tp + fp) if tp + fp else 1.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        cell = {"thr": float(thr), "precision": prec, "recall": rec, "f1": f1}
        if best_f1 is None or f1 > best_f1["f1"]:
            best_f1 = cell
        if prec >= target_precision and (best_floor is None or rec > best_floor["recall"]):
            best_floor = cell
    out["f1_opt"] = best_f1
    out["p_floor"] = best_floor
    return out


def evaluate(booster, rows):
    """Prints metrics at several thresholds and returns the metrics at thr=0.5."""
    out = None
    for thr in (0.5, 0.8):
        m = metrics_at(booster, rows, thr)
        print(f"  thr={thr}: precision={m['precision']:.3f} recall={m['recall']:.3f} "
              f"f1={m['f1']:.3f} (fp={m['fp']} fn={m['fn']})")
        if thr == 0.5:
            out = m
    return out


if __name__ == "__main__":
    main()
