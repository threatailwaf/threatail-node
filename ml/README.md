# Threatail ML — training the supervised detector

This pipeline trains a LightGBM model on labelled traffic and exports it to the JSON format the node loads (`src/mlmodel.rs`, env `THREATAIL_ML_MODEL_PATH`).

Two models come out of one pipeline:

- **Expert model** — trained on a curated seed corpus (`expert_seed.py`). Usable on day one with no customer data. This is the "default" model.
- **Fine-tuned model** — the expert model as `init_model`, warm-started with a larger corpus (synthetic, public or customer data) on top. More accurate and generalises better.

## Install

```bash
pip install lightgbm numpy    # see requirements.txt
```

`features.py` has no dependencies and STRICTLY mirrors `../src/features.rs`. Parity is verified against `../src/golden.json`:

```bash
python3 features.py
```

Run that after touching either implementation. It is the only thing standing between you and a model trained on features the node does not actually compute.

## 1. Expert (default) model

```bash
python3 train.py --seed-only --lgb-out expert.txt --out expert.model.json
```

- `expert.model.json` goes onto the node as the default (see Deployment).
- `expert.txt` is the native LightGBM model, needed as `--init-model` for fine-tuning.

## 2. Fine-tuning on top (warm start)

```bash
# synthetic corpus (public datasets can be mixed in, see below)
python3 synth.py --n 60000 --out synth.jsonl

python3 train.py --data synth.jsonl --init-model expert.txt \
                 --lgb-out prod.txt --out model.json --eval-frac 0.1
```

`--init-model` takes the expert model and **adds rounds on top**. `prod.txt` can be fed back as `--init-model` for the next iteration, for instance with customer data.

## 3. Fine-tuning on customer data

Quarantine review produces labelled examples. Export them as jsonl (`{"path","query","body","label"}`) and:

```bash
python3 train.py --data synth.jsonl --data client_labeled.jsonl \
                 --init-model prod.txt --out model.json --eval-frac 0.1
```

## Mixing in public datasets

Adapters in `datasets.py` normalise public corpora into `{path,query,body,label}`:

```bash
python3 datasets.py \
  --csic /path/csic_database.csv \
  --fwaf /path/Fwaf-Machine-Learning-driven-Web-Application-Firewall-master/ \
  --pat  /path/PayloadsAllTheThings-master/ \
  --good-sample 60000 --pat-per-file 400 \
  --out external.jsonl

python3 train.py --with-seed --data external.jsonl --init-model expert.txt \
                 --out model.json --eval-frac 0.1
```

- **CSIC 2010** — `csic_database.csv`, label in column 1 (Normal/Anomalous), URL plus body. Note that "Anomalous" in CSIC includes structurally unusual requests, not only clearly malicious ones. That is fine for a decision boundary, but do not read its accuracy figures as attack-detection accuracy.
- **FWAF** — `bad/goodqueries.txt`. The good set has around 1.3M entries, so subsample with `--good-sample`.
- **PayloadsAllTheThings** — `*/Intruder/*.txt` by vector, giving attacks distributed across request parts.

## Continuous retraining

Quarantine review produces labelled examples over time. Export them periodically and
warm-start from the previous model, as in section 3 above: each run takes seconds
because it adds rounds to an existing model rather than training from scratch.

Threatail Cloud automates this loop — labelling in the dashboard triggers retraining
and the node picks up the new model without a restart.

## Deploying to a node manually

1. Put `model.json` where the node looks:

   ```bash
   scp model.json node:/var/lib/threatail/ml-model.json
   ```

2. Point the node at it:

   ```
   THREATAIL_ML_MODEL_PATH=/var/lib/threatail/ml-model.json
   ```

   and enable `ml_enabled` for the site.

3. The node loads the model at startup. In cloud mode it also supports **hot swapping**: publish a new `model.json` and it is replaced in place (see `central.rs`).

Model format: [MODEL_FORMAT.md](MODEL_FORMAT.md). Feature list and ordering: [FEATURES.md](FEATURES.md).

## Compatibility

`feature_version` and `n_features` in `model.json` MUST match the node's values, or the model is refused at load. The node logs this rather than failing silently.

Training runs with `boost_from_average=False` and `sigmoid=1.0`, which makes the node's `sigmoid(sum of leaves)` match LightGBM exactly. **Do not change these two parameters.** Nothing checks them at runtime, so getting it wrong produces a model that loads cleanly and scores wrongly.
