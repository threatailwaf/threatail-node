"""
Trainer service: automates online fine-tuning WITHOUT manual import and export.

The full loop:
  an analyst labels in the dashboard -> /api/ml/label -> ml_feedback
    -> (at the RETRAIN_EVERY threshold) control calls TRAINER_URL/train
      -> THIS service: pulls the tenant's labels (/api/trainer/dataset),
        fine-tunes on top of the current model (warm start), exports to the node format,
        publishes (/api/trainer/model) -> ml_models(active=TRUE)
          -> the node fetches the active model and hot-swaps it. No manual steps.

Dependencies: lightgbm and numpy, as in train.py. HTTP uses the standard library, not requests.

Running it:
  CLOUD_URL=https://lk.threatail.com TRAINER_TOKEN=... \
  EXTERNAL_DATA=external.jsonl python3 trainer_service.py   # listens on :8077

Env:
  CLOUD_URL       base URL of control (required)
  TRAINER_TOKEN   shared secret, identical to control's TRAINER_TOKEN (required)
  EXTERNAL_DATA   path to external.jsonl (CSIC/FWAF/PAT); optional, mixed in
  EXPERT_MODEL    starting init_model (expert.txt); optional
  MODELS_DIR      where per-tenant init models are kept (default ./models)
  CLIENT_WEIGHT   how many times customer labels are duplicated (default 6)
  ROUNDS          boosting rounds per fine-tuning run (default 120)
  MIN_INTERVAL_SEC anti-churn: minimum interval per (tenant, domain) (default 300)
  WORKERS         parallel training workers (default 1)
  SHARD_INDEX/SHARD_COUNT  sharding by tenant_id (0/1 disables it)
  PORT            listen port (default 8077)
"""
from __future__ import annotations
import json
import os
import queue
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import features as F  # noqa: F401 (parity and constants)
import train
import expert_seed

CLOUD_URL = os.environ.get("CLOUD_URL", "").rstrip("/")
TRAINER_TOKEN = os.environ.get("TRAINER_TOKEN", "")
EXTERNAL_DATA = os.environ.get("EXTERNAL_DATA", "")
EXPERT_MODEL = os.environ.get("EXPERT_MODEL", "")
MODELS_DIR = os.environ.get("MODELS_DIR", "models")
CLIENT_WEIGHT = int(os.environ.get("CLIENT_WEIGHT", "6"))
ROUNDS = int(os.environ.get("ROUNDS", "120"))
PORT = int(os.environ.get("PORT", "8077"))
# load guard: at most one training run per (tenant, domain) within this interval
MIN_INTERVAL = int(os.environ.get("MIN_INTERVAL_SEC", "300"))
WORKERS = max(1, int(os.environ.get("WORKERS", "1")))
# sharding by tenant_id: this replica serves only its own slice
SHARD_INDEX = int(os.environ.get("SHARD_INDEX", "0"))
SHARD_COUNT = int(os.environ.get("SHARD_COUNT", "0"))  # 0 or 1 means no sharding


def fnv1a(s: str) -> int:
    """FNV-1a 64. MUST match shard_hash() in control (main.rs)."""
    h = 0xcbf29ce484222325
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h


def in_shard(tenant_id: str) -> bool:
    if SHARD_COUNT <= 1:
        return True
    return fnv1a(tenant_id) % SHARD_COUNT == SHARD_INDEX

os.makedirs(MODELS_DIR, exist_ok=True)

# task queue plus deduplication; training is CPU-heavy, so one worker runs them sequentially
_jobs: "queue.Queue[tuple[str,str]]" = queue.Queue()
_queued: set[tuple[str, str]] = set()
_last_trained: dict[tuple[str, str], float] = {}
_lock = threading.Lock()

# cache for the external data, loaded once
_external = None


def _http_json(method: str, url: str, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-Trainer-Token", TRAINER_TOKEN)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def fetch_labels(tenant_id: str, domain: str):
    url = f"{CLOUD_URL}/api/trainer/dataset?tenant_id={tenant_id}&domain={urllib.parse.quote(domain)}"
    try:
        j = _http_json("GET", url)
        return j.get("labels", [])
    except Exception as e:
        print(f"[trainer] could not fetch labels {tenant_id}/{domain}: {e}")
        return []


def publish_model(tenant_id: str, domain: str, model_json: str, n_attack: int, n_normal: int, metrics=None):
    url = f"{CLOUD_URL}/api/trainer/model"
    payload = {
        "tenant_id": tenant_id, "domain": domain, "model": model_json,
        "n_attack": n_attack, "n_normal": n_normal,
    }
    if metrics:
        payload.update({
            "eval_precision": metrics.get("precision"),
            "eval_recall": metrics.get("recall"),
            "eval_f1": metrics.get("f1"),
            "eval_n": metrics.get("n"),
            "rec_threshold": metrics.get("rec_threshold"),
            "rec_precision": metrics.get("rec_precision"),
            "rec_recall": metrics.get("rec_recall"),
        })
    return _http_json("POST", url, payload)


def load_external():
    global _external
    if _external is None:
        _external = []
        if EXTERNAL_DATA and os.path.exists(EXTERNAL_DATA):
            _external = train.load_jsonl(EXTERNAL_DATA)
            print(f"[trainer] external: {len(_external)} rows from {EXTERNAL_DATA}")
    return _external


def init_model_for(tenant_id: str, domain: str):
    """The current per-tenant model for warm starting, or the shared expert.txt."""
    p = os.path.join(MODELS_DIR, f"{tenant_id}__{domain or 'all'}.txt")
    if os.path.exists(p):
        return p
    if EXPERT_MODEL and os.path.exists(EXPERT_MODEL):
        return EXPERT_MODEL
    return None


# minimum F1 gain required to avoid a rollback (anti-regression): a candidate is published
# only when it is no worse than the current own model on the holdout by more than EPS.
PROMOTE_EPS = float(os.environ.get("PROMOTE_EPS", "0.02"))
# target precision for the recommended blocking threshold (max recall subject to precision >= this)
TARGET_PRECISION = float(os.environ.get("TARGET_PRECISION", "0.99"))


def stratified_holdout(rows, frac=0.15, seed=0):
    """Stratified holdout: a fraction of positives and of negatives go to evaluation, the rest to training."""
    import random
    rng = random.Random(seed)
    pos = [r for r in rows if r["label"] == 1]
    neg = [r for r in rows if r["label"] == 0]
    rng.shuffle(pos); rng.shuffle(neg)
    kp = max(1, int(len(pos) * frac)) if len(pos) >= 4 else 0
    kn = max(1, int(len(neg) * frac)) if len(neg) >= 4 else 0
    hold = pos[:kp] + neg[:kn]
    tr = pos[kp:] + neg[kn:]
    rng.shuffle(hold); rng.shuffle(tr)
    return tr, hold


def eval_prev(init, hold):
    """Metric of the previous OWN model (not the shared expert) on the holdout. None when there is none."""
    if not init or init == EXPERT_MODEL or not os.path.exists(init):
        return None
    try:
        import lightgbm as lgb
        prev = lgb.Booster(model_file=init)
        return train.metrics_at(prev, hold)
    except Exception as e:
        print(f"[trainer] could not evaluate the previous model: {e}")
        return None


def run_training(tenant_id: str, domain: str):
    import lightgbm  # noqa: F401 (fail early when the dependency is missing)
    client = fetch_labels(tenant_id, domain)
    # corpus composition: expert plus public plus CUSTOMER data, the latter oversampled for priority
    rows = list(expert_seed.dataset()) + list(load_external())
    rows += client * max(CLIENT_WEIGHT, 1)
    pos = sum(r["label"] for r in rows)
    print(f"[trainer] {tenant_id}/{domain or 'all'}: corpus={len(rows)} "
          f"(client={len(client)}×{CLIENT_WEIGHT}, attacks={pos})")
    if len(rows) < 50 or pos == 0 or pos == len(rows):
        print("[trainer] insufficient or unbalanced data, skipping")
        return

    init = init_model_for(tenant_id, domain)
    # holdout split: train on the training part, evaluate on the held-out part
    tr, hold = stratified_holdout(rows)
    booster = train.train(tr, init_model=init, rounds=ROUNDS)

    # evaluate the candidate and apply the anti-regression gate: no worse than the current own model
    cand = train.metrics_at(booster, hold)
    prev = eval_prev(init, hold)
    print(f"[trainer] holdout n={cand['n']}: f1={cand['f1']:.3f} "
          f"prec={cand['precision']:.3f} rec={cand['recall']:.3f}"
          + (f" | previous f1={prev['f1']:.3f}" if prev else " | no previous own model"))
    if prev is not None and cand["f1"] < prev["f1"] - PROMOTE_EPS:
        print(f"[trainer] candidate is WORSE (f1 {cand['f1']:.3f} < {prev['f1']:.3f}-{PROMOTE_EPS}) — "
              f"not publishing; keeping the current model")
        return

    # promote: save the native model for the next warm start, export it, publish with metrics
    native = os.path.join(MODELS_DIR, f"{tenant_id}__{domain or 'all'}.txt")
    booster.save_model(native)
    tmp = os.path.join(MODELS_DIR, f"{tenant_id}__{domain or 'all'}.model.json")
    train.export_node_model(booster, tmp)
    model_json = open(tmp, encoding="utf-8").read()

    n_attack = sum(1 for r in client if r["label"] == 1)
    n_normal = sum(1 for r in client if r["label"] == 0)

    # recommended operating point from the holdout PR curve; neither model nor features change, only the threshold
    rp = train.best_threshold(booster, hold, target_precision=TARGET_PRECISION)
    floor = rp.get("p_floor"); f1o = rp.get("f1_opt")
    pick = floor or f1o
    if floor:
        print(f"[trainer] recommended threshold (P>={TARGET_PRECISION:.2f}): ml_threshold≈{floor['thr']:.3f} "
              f"→ P={floor['precision']:.3f} R={floor['recall']:.3f}")
    elif f1o:
        print(f"[trainer] precision {TARGET_PRECISION:.2f} unattainable on the holdout; "
              f"F1 optimum: ml_threshold~{f1o['thr']:.3f} P={f1o['precision']:.3f} R={f1o['recall']:.3f}")
    if pick:
        cand["rec_threshold"] = pick["thr"]
        cand["rec_precision"] = pick["precision"]
        cand["rec_recall"] = pick["recall"]

    res = publish_model(tenant_id, domain, model_json, n_attack, n_normal, cand)
    print(f"[trainer] published {tenant_id}/{domain or 'all'} → version={res.get('version')} "
          f"(f1={cand['f1']:.3f})")


def worker():
    import time
    while True:
        tenant_id, domain = _jobs.get()
        with _lock:
            _queued.discard((tenant_id, domain))
        key = (tenant_id, domain)
        last = _last_trained.get(key, 0)
        if time.time() - last < MIN_INTERVAL:
            print(f"[trainer] cooldown {tenant_id}/{domain or 'all'} "
                  f"(elapsed {int(time.time()-last)}s < {MIN_INTERVAL}s), skipping")
            _jobs.task_done()
            continue
        try:
            run_training(tenant_id, domain)
            _last_trained[key] = time.time()
        except Exception as e:
            print(f"[trainer] TRAINING ERROR {tenant_id}/{domain}: {e}")
        finally:
            _jobs.task_done()


def enqueue(tenant_id: str, domain: str):
    key = (tenant_id, domain)
    with _lock:
        if key in _queued:
            return False
        _queued.add(key)
    _jobs.put(key)
    return True


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/health"):
            self._send(200, {"status": "ok", "queued": len(_queued)})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.startswith("/train"):
            self._send(404, {"error": "not found"})
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n).decode() or "{}")
        except Exception:
            self._send(400, {"error": "bad json"})
            return
        tenant_id = (body.get("tenant_id") or "").strip()
        domain = (body.get("domain") or "").strip()
        if not tenant_id:
            self._send(400, {"error": "tenant_id"})
            return
        if not in_shard(tenant_id):
            # arrived at the wrong replica, meaning misconfigured routing; signal it explicitly
            self._send(409, {"error": "wrong_shard", "shard": SHARD_INDEX, "of": SHARD_COUNT})
            return
        queued = enqueue(tenant_id, domain)
        self._send(202, {"status": "queued" if queued else "already_queued",
                         "tenant_id": tenant_id, "domain": domain})

    def log_message(self, *a):
        pass  # quiet


def main():
    if not CLOUD_URL or not TRAINER_TOKEN:
        raise SystemExit("CLOUD_URL and TRAINER_TOKEN are required")
    for _ in range(WORKERS):
        threading.Thread(target=worker, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[trainer] listening on :{PORT}, cloud={CLOUD_URL}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
