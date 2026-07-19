"""
Adapters that normalise public datasets into the training format {path,query,body,label}.

Supported:
  • CSIC 2010   — csic_database.csv (label in column 1, Normal/Anomalous; URL plus body)
  • FWAF        — badqueries.txt / goodqueries.txt (path?query, one per line)
  • PayloadsAllTheThings — */Intruder/*.txt (one payload per line; # starts a comment) -> attacks

Usage:
  python3 datasets.py --csic csic_database.csv \
                      --fwaf  /path/Fwaf-.../  \
                      --pat   /path/PayloadsAllTheThings-master/ \
                      --good-sample 60000 --pat-per-file 400 \
                      --out external.jsonl
The resulting external.jsonl is fed to train.py via --data.
"""
from __future__ import annotations
import argparse
import csv
import json
import os
import sys
from urllib.parse import urlsplit

csv.field_size_limit(10_000_000)


# ───────────────────────── CSIC 2010 ─────────────────────────
def load_csic(csv_path: str):
    rows = []
    with open(csv_path, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        # the unnamed first column (key '') carries the Normal/Anomalous label
        label_key = reader.fieldnames[0]
        for r in reader:
            lab = (r.get(label_key) or "").strip().lower()
            label = 1 if lab.startswith("anom") else 0
            url = (r.get("URL") or "").strip()
            # "http://host:port/path?query HTTP/1.1": strip the trailing protocol
            if url.upper().endswith(" HTTP/1.1") or url.upper().endswith(" HTTP/1.0"):
                url = url.rsplit(" ", 1)[0]
            sp = urlsplit(url)
            path, query = sp.path, sp.query
            body = (r.get("content") or "").strip()
            if not path:
                path = "/"
            rows.append({"path": path, "query": query, "body": body, "label": label})
    return rows


# ───────────────────────── FWAF ─────────────────────────
def _split_pq(line: str):
    line = line.strip()
    if not line:
        return None
    # lines of the form "/path?query"; taken as path plus query, with no host
    if "?" in line:
        path, query = line.split("?", 1)
    else:
        path, query = line, ""
    if not path.startswith("/"):
        path = "/" + path
    return path, query


def load_fwaf(fwaf_dir: str, good_sample: int = 60000, seed: int = 7):
    import random
    bad_f = _find(fwaf_dir, "badqueries.txt")
    good_f = _find(fwaf_dir, "goodqueries.txt")
    rows = []
    with open(bad_f, encoding="utf-8", errors="replace") as f:
        for line in f:
            pq = _split_pq(line)
            if pq:
                rows.append({"path": pq[0], "query": pq[1], "body": "", "label": 1})
    # there are very many good entries, so take a random reservoir subsample
    r = random.Random(seed)
    reservoir = []
    with open(good_f, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            pq = _split_pq(line)
            if not pq:
                continue
            ex = {"path": pq[0], "query": pq[1], "body": "", "label": 0}
            if len(reservoir) < good_sample:
                reservoir.append(ex)
            else:
                j = r.randint(0, i)
                if j < good_sample:
                    reservoir[j] = ex
    rows.extend(reservoir)
    return rows


# ───────────────────── PayloadsAllTheThings ─────────────────────
# Vector directory -> where to place the payload (which request part) and the parameter name.
PAT_MAP = {
    "SQL Injection":        ("query", "id"),
    "NoSQL Injection":      ("query", "id"),
    "LDAP Injection":       ("query", "user"),
    "XPATH Injection":      ("query", "q"),
    "XSS Injection":        ("query", "q"),
    "Command Injection":    ("query", "cmd"),
    "Directory Traversal":  ("query", "file"),
    "File Inclusion":       ("query", "page"),
    "Server Side Template Injection": ("query", "name"),
    "Server Side Request Forgery":    ("query", "url"),
    "XXE Injection":        ("body", None),     # raw XML into the body
    "CRLF Injection":       ("query", "redirect"),
    "Server Side Include Injection":  ("query", "q"),
}


def load_payloads(pat_root: str, per_file: int = 400):
    # archives are often doubly nested: .../PayloadsAllTheThings-master/PayloadsAllTheThings-master
    root = pat_root
    inner = os.path.join(pat_root, "PayloadsAllTheThings-master")
    if os.path.isdir(inner):
        root = inner
    rows = []
    for folder, (part, pname) in PAT_MAP.items():
        base = os.path.join(root, folder)
        if not os.path.isdir(base):
            continue
        for dirpath, _dirs, files in os.walk(base):
            for fn in files:
                if not fn.lower().endswith(".txt"):
                    continue
                fpath = os.path.join(dirpath, fn)
                cnt = 0
                with open(fpath, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        s = line.strip()
                        if not s or s.startswith("#") or s.startswith("//"):
                            continue
                        if len(s) > 2000:           # drop junk mega-lines
                            continue
                        rows.append(_pat_example(part, pname, s))
                        cnt += 1
                        if cnt >= per_file:
                            break
    return rows


def _pat_example(part: str, pname, payload: str):
    if part == "body":
        body = payload if pname is None else f"{pname}={payload}"
        return {"path": "/", "query": "", "body": body, "label": 1}
    # query
    return {"path": "/", "query": f"{pname}={payload}", "body": "", "label": 1}


# ───────────────────────── utilities ─────────────────────────
def _find(root: str, name: str) -> str:
    for dirpath, _d, files in os.walk(root):
        if name in files:
            return os.path.join(dirpath, name)
    sys.exit(f"not found: {name} in {root}")


def main():
    ap = argparse.ArgumentParser(description="Public datasets -> external.jsonl")
    ap.add_argument("--csic", help="csic_database.csv")
    ap.add_argument("--fwaf", help="FWAF directory (containing bad/goodqueries.txt)")
    ap.add_argument("--pat", help="PayloadsAllTheThings directory")
    ap.add_argument("--good-sample", type=int, default=60000, help="how many FWAF good entries to take")
    ap.add_argument("--pat-per-file", type=int, default=400, help="max lines from a single payload file")
    ap.add_argument("--out", default="external.jsonl")
    a = ap.parse_args()

    rows = []
    if a.csic:
        c = load_csic(a.csic); rows += c
        print(f"CSIC:  {len(c):>7} ({sum(x['label'] for x in c)} attacks)")
    if a.fwaf:
        fw = load_fwaf(a.fwaf, a.good_sample); rows += fw
        print(f"FWAF:  {len(fw):>7} ({sum(x['label'] for x in fw)} attacks)")
    if a.pat:
        pt = load_payloads(a.pat, a.pat_per_file); rows += pt
        print(f"PAT:   {len(pt):>7} ({sum(x['label'] for x in pt)} attacks)")
    if not rows:
        sys.exit("specify at least one of --csic, --fwaf, --pat")

    with open(a.out, "w", encoding="utf-8") as f:
        for ex in rows:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    pos = sum(x["label"] for x in rows)
    print(f"TOTAL: {len(rows)} ({pos} attacks / {len(rows)-pos} normal) -> {a.out}")


if __name__ == "__main__":
    main()
