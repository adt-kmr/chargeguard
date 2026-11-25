"""
Train and evaluate the flow classifier on NF-UNSW-NB15 (NetFlow v1).

    python scripts/fetch_datasets.py nf_unsw_nb15
    python -m trafficml.train

Protocol
  * rows whose duration wrapped around (>= 1 h, an exporter artefact) are dropped
  * duplicate (features, label) rows are removed BEFORE splitting, so no test row has
    an identical twin in training (52% of rows are duplicates once addresses are removed)
  * stratified 70 / 15 / 15 split; the decision threshold is chosen on validation for a
    false-positive rate of at most 0.5%, then reported once on test
  * leave-one-attack-category-out: retrain without a category, measure recall on it
    (how the model does on attack types it never saw)
  * a gradient-boosted tree model is trained as a reference; the deployed model is a
    small MLP because it exports to ExecuTorch

Writes trafficml/weights/flow_mlp.npz and benchmarks/results/traffic_classifier_metrics.json.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from .features import DIM, MAX_DURATION_MS, NAMES, matrix

ROOT = Path(__file__).resolve().parents[1]
CSV = next((ROOT / "data" / "raw" / "nf_unsw_nb15").glob("*/data/NF-UNSW-NB15.csv"), None)
WEIGHTS = ROOT / "trafficml" / "weights" / "flow_mlp.npz"
METRICS = ROOT / "benchmarks" / "results" / "traffic_classifier_metrics.json"
TARGET_FPR = 0.005
SEED = 7


def load():
    df = pd.read_csv(CSV)
    n0 = len(df)
    df = df[df.FLOW_DURATION_MILLISECONDS < MAX_DURATION_MS]
    X, y, cat = matrix(df), df.Label.to_numpy(np.int8), df.Attack.to_numpy()
    key = np.concatenate([X, y[:, None].astype(np.float32)], axis=1)
    _, first = np.unique(key.view(np.dtype((np.void, key.dtype.itemsize * key.shape[1]))).ravel(), return_index=True)
    first.sort()
    info = {"rows": n0, "dropped_wrapped_duration": int(n0 - len(df)), "unique_rows": int(len(first)),
            "unique_benign": int((y[first] == 0).sum()), "unique_attack": int((y[first] == 1).sum())}
    return X[first], y[first], cat[first], info


HIDDEN = (128, 64)


class MLP(torch.nn.Module):
    def __init__(self, d=DIM, hidden=None):
        super().__init__()
        h1, h2 = hidden or HIDDEN
        self.net = torch.nn.Sequential(torch.nn.Linear(d, h1), torch.nn.ReLU(), torch.nn.Linear(h1, h2),
                                       torch.nn.ReLU(), torch.nn.Linear(h2, 1))

    def forward(self, x):
        return self.net(x).squeeze(-1)


def fit_mlp(X, y, mean, std, epochs=25, seed=SEED, hidden=None, lr=2e-3, decay=0.9):
    torch.manual_seed(seed)
    m = MLP(hidden=hidden)
    Xt = torch.from_numpy((X - mean) / std)
    yt = torch.from_numpy(y.astype(np.float32))
    pos_w = torch.tensor(min(20.0, (y == 0).sum() / max((y == 1).sum(), 1)))
    opt = torch.optim.Adam(m.parameters(), lr=lr, weight_decay=1e-5)
    lossf = torch.nn.BCEWithLogitsLoss(pos_weight=pos_w)
    g = torch.Generator().manual_seed(seed)
    for ep in range(epochs):
        perm = torch.randperm(len(Xt), generator=g)
        for i in range(0, len(Xt), 4096):
            idx = perm[i:i + 4096]
            opt.zero_grad()
            lossf(m(Xt[idx]), yt[idx]).backward()
            opt.step()
        for pg in opt.param_groups:
            pg["lr"] *= decay
    return m.eval()


def predict(m, X, mean, std):
    with torch.no_grad():
        return torch.sigmoid(m(torch.from_numpy((X - mean) / std))).numpy()


def threshold_for_fpr(p, y, fpr=TARGET_FPR):
    neg = np.sort(p[y == 0])
    return float(neg[min(len(neg) - 1, int(np.ceil((1 - fpr) * len(neg))))]) + 1e-6


def report(p, y, thr):
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"n": int(len(y)), "attacks": int(y.sum()), "precision": round(precision_score(y, pred), 4),
            "recall": round(recall_score(y, pred), 4), "f1": round(f1_score(y, pred), 4),
            "roc_auc": round(roc_auc_score(y, p), 4), "false_positive_rate": round(fp / (fp + tn), 5),
            "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}


def main():
    t0 = time.time()
    X, y, cat, info = load()
    print("data", info)
    idx = np.arange(len(y))
    tr, rest = train_test_split(idx, test_size=0.30, stratify=y, random_state=SEED)
    va, te = train_test_split(rest, test_size=0.50, stratify=y[rest], random_state=SEED)
    mean, std = X[tr].mean(0), X[tr].std(0) + 1e-6

    mlp = fit_mlp(X[tr], y[tr], mean, std)
    thr = threshold_for_fpr(predict(mlp, X[va], mean, std), y[va])
    p_te = predict(mlp, X[te], mean, std)
    res = {"dataset": "NF-UNSW-NB15 (NetFlow v1), University of Queensland", "data": info,
           "features": NAMES, "threshold": round(thr, 6), "target_validation_fpr": TARGET_FPR,
           "mlp_test": report(p_te, y[te], thr)}
    pred = p_te >= thr
    res["mlp_test_recall_by_category"] = {c: round(float(pred[(cat[te] == c)].mean()), 4)
                                          for c in sorted(set(cat[te])) if c != "Benign"}
    print("mlp test", res["mlp_test"])

    hgb = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, random_state=SEED).fit(X[tr], y[tr])
    hthr = threshold_for_fpr(hgb.predict_proba(X[va])[:, 1], y[va])
    res["reference_gradient_boosting_test"] = report(hgb.predict_proba(X[te])[:, 1], y[te], hthr)
    print("hgb test", res["reference_gradient_boosting_test"])

    loco = {}
    for c in ["Exploits", "Fuzzers", "Reconnaissance", "DoS", "Generic"]:
        keep = tr[cat[tr] != c]
        m = fit_mlp(X[keep], y[keep], mean, std, epochs=12)
        t = threshold_for_fpr(predict(m, X[va][cat[va] != c], mean, std), y[va][cat[va] != c])
        held = te[cat[te] == c]
        loco[c] = round(float((predict(m, X[held], mean, std) >= t).mean()), 4)
        print("unseen", c, loco[c])
    res["recall_on_unseen_category"] = loco

    W = [l for l in mlp.net if isinstance(l, torch.nn.Linear)]
    WEIGHTS.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(WEIGHTS, mean=mean.astype(np.float32), std=std.astype(np.float32), threshold=np.float32(thr),
                        **{f"W{i}": l.weight.detach().numpy().T.astype(np.float32) for i, l in enumerate(W)},
                        **{f"b{i}": l.bias.detach().numpy().astype(np.float32) for i, l in enumerate(W)})
    res["weights_bytes"] = WEIGHTS.stat().st_size
    res["parameters"] = int(sum(p.numel() for p in mlp.parameters()))
    res["train_seconds"] = round(time.time() - t0, 1)
    METRICS.write_text(json.dumps(res, indent=2))
    print(json.dumps({k: v for k, v in res.items() if k not in ("features",)}, indent=2))


if __name__ == "__main__":
    main()
