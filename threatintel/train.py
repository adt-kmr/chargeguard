"""
Train and evaluate ChargeGuard's threat detectors.

    python -m threatintel.train          # needs data/raw (scripts/fetch_datasets.py)

Outputs
  threatintel/weights/sms_scam.npz       linear weights over hashed SMS features
  threatintel/weights/phishing_url.npz   linear weights over hashed hostname + lexical features
  benchmarks/results/threatintel_metrics.json   held-out metrics, splits and data caveats

Evaluation protocol
  SMS   duplicates removed before splitting; stratified 70/15/15 train/val/test.
  URLs  PhiUSIIL legitimate URLs are all "https://www.<domain>" with no path, so
        raw URLs leak the label. The model sees the hostname only (scheme, www
        and path removed), and the split is grouped by registrable domain so a
        site never appears in both train and test.
  The decision threshold is chosen on validation (max F1) and reported on test.
"""
from __future__ import annotations

import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import scipy.sparse as sp
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from threatintel import features as F

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
WEIGHTS = Path(__file__).resolve().parent / "weights"
METRICS = ROOT / "benchmarks" / "results" / "threatintel_metrics.json"
SEED = 20261124


def _metrics(y, p, thr):
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"threshold": round(float(thr), 4), "accuracy": round(accuracy_score(y, pred), 4),
            "precision": round(precision_score(y, pred, zero_division=0), 4),
            "recall": round(recall_score(y, pred), 4), "f1": round(f1_score(y, pred), 4),
            "roc_auc": round(roc_auc_score(y, p), 4), "pr_auc": round(average_precision_score(y, p), 4),
            "false_positive_rate": round(fp / max(1, fp + tn), 4),
            "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}, "n": int(len(y))}


def _best_threshold(y, p):
    grid = np.linspace(0.05, 0.95, 91)
    return float(grid[int(np.argmax([f1_score(y, (p >= t).astype(int)) for t in grid]))])


def _fit(X, y, C):
    clf = LogisticRegression(C=C, max_iter=2000, class_weight="balanced", solver="liblinear")
    t0 = time.perf_counter()
    clf.fit(X, y)
    return clf, time.perf_counter() - t0


# ── SMS scam detector ─────────────────────────────────────────────────────

def sms_features(texts):
    norm = [F.normalise_sms(t) for t in texts]
    return sp.hstack([F.SMS_WORD.transform(norm), F.SMS_CHAR.transform(norm)]).tocsr()


def train_sms():
    d = pd.read_csv(RAW / "sms_spam" / "SMSSpamCollection", sep="\t", header=None,
                    names=["label", "text"], quoting=3)
    n_raw = len(d)
    d = d.drop_duplicates("text")
    y = (d.label == "spam").astype(int).to_numpy()
    tr, rest = train_test_split(np.arange(len(d)), test_size=0.30, stratify=y, random_state=SEED)
    va, te = train_test_split(rest, test_size=0.50, stratify=y[rest], random_state=SEED)
    X = sms_features(d.text.tolist())
    best = None
    for C in (1.0, 4.0, 16.0):
        clf, secs = _fit(X[tr], y[tr], C)
        pv = clf.predict_proba(X[va])[:, 1]
        f = f1_score(y[va], (pv >= 0.5).astype(int))
        if best is None or f > best[0]:
            best = (f, C, clf, secs)
    _, C, clf, secs = best
    thr = _best_threshold(y[va], clf.predict_proba(X[va])[:, 1])
    pt = clf.predict_proba(X[te])[:, 1]
    w = clf.coef_.ravel().astype(np.float32)
    WEIGHTS.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(WEIGHTS / "sms_scam.npz", w_word=w[:F.N_HASH], w_char=w[F.N_HASH:],
                        bias=np.float32(clf.intercept_[0]), threshold=np.float32(thr))
    return {"dataset": "UCI SMS Spam Collection (CC BY 4.0)", "rows_raw": n_raw, "rows_deduplicated": len(d),
            "positives": int(y.sum()), "split": {"train": len(tr), "val": len(va), "test": len(te)},
            "model": f"logistic regression, hashed word 1-2 + char 3-5 grams, C={C}",
            "train_seconds": round(secs, 2), "test": _metrics(y[te], pt, thr),
            "test_at_0.5": _metrics(y[te], pt, 0.5)}


# ── Phishing URL detector ─────────────────────────────────────────────────

def url_features(hosts):
    lex = sp.csr_matrix(np.vstack([F.host_lexical(h) for h in hosts]))
    return sp.hstack([F.HOST_CHAR.transform(hosts), lex]).tocsr()


def train_urls():
    d = pd.read_csv(RAW / "phiusiil" / "PhiUSIIL_Phishing_URL_Dataset.csv", usecols=["URL", "label"],
                    encoding="utf-8", encoding_errors="replace")
    d["host"] = d.URL.map(F.host_of)
    d = d[d.host.str.len() > 0]
    d["y"] = (d.label == 0).astype(int)                # PhiUSIIL: 1 = legitimate, 0 = phishing
    n_rows = len(d)
    d = d.drop_duplicates(["host", "y"])
    d["group"] = d.host.map(F.registrable_domain)
    conflict = d.groupby("host").y.nunique()
    d = d[~d.host.isin(conflict[conflict > 1].index)]  # same host labelled both ways: drop
    gss = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=SEED)
    tr, rest = next(gss.split(d, groups=d.group))
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=SEED)
    va_i, te_i = next(gss2.split(rest, groups=d.group.iloc[rest]))
    va, te = rest[va_i], rest[te_i]
    hosts = d.host.tolist()
    y = d.y.to_numpy()
    X = url_features(hosts)
    best = None
    for C in (1.0, 4.0):
        clf, secs = _fit(X[tr], y[tr], C)
        pv = clf.predict_proba(X[va])[:, 1]
        f = f1_score(y[va], (pv >= 0.5).astype(int))
        if best is None or f > best[0]:
            best = (f, C, clf, secs)
    _, C, clf, secs = best
    thr = _best_threshold(y[va], clf.predict_proba(X[va])[:, 1])
    pt = clf.predict_proba(X[te])[:, 1]
    w = clf.coef_.ravel().astype(np.float32)
    np.savez_compressed(WEIGHTS / "phishing_url.npz", w_char=w[:F.N_HASH], w_lex=w[F.N_HASH:],
                        bias=np.float32(clf.intercept_[0]), threshold=np.float32(thr))
    overlap = len(set(d.group.iloc[tr]) & set(d.group.iloc[te]))
    return {"dataset": "UCI PhiUSIIL Phishing URL Dataset (CC BY 4.0)", "rows_raw": n_rows,
            "unique_hosts": len(d), "positives": int(y.sum()),
            "split": {"train": len(tr), "val": len(va), "test": len(te), "grouped_by": "registrable domain",
                      "domains_in_both_train_and_test": overlap},
            "model": f"logistic regression, hashed hostname char 3-5 grams + {F.N_LEXICAL} lexical features, C={C}",
            "train_seconds": round(secs, 2), "test": _metrics(y[te], pt, thr),
            "test_at_0.5": _metrics(y[te], pt, 0.5),
            "caveat": ("Hostname-only model. PhiUSIIL legitimate URLs are all https://www.<domain> with no path, "
                       "so full URLs leak the label; path keywords are handled by an explicit rule layer instead. "
                       "Legitimate hosts are mostly popular sites, so scores on unusual legitimate domains will be lower.")}


def main():
    out = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "seed": SEED, "host": {"machine": platform.machine(), "os": platform.platform(),
                                  "python": platform.python_version(), "sklearn": sklearn.__version__}}
    out["sms_scam"] = train_sms()
    print("sms:", out["sms_scam"]["test"])
    out["phishing_url"] = train_urls()
    print("url:", out["phishing_url"]["test"])
    METRICS.parent.mkdir(parents=True, exist_ok=True)
    METRICS.write_text(json.dumps(out, indent=2))
    print(f"written: {METRICS}")


if __name__ == "__main__":
    main()
