"""
On-device flow classifier: scores NetFlow records from the node's bridge and explains
each score by the features that pushed it up (gradient x input on the MLP).

Inference is NumPy (a 39-128-64-1 MLP, about 13k parameters); the same network is
exported to ExecuTorch by trafficml/executorch_export.py with verified parity.
"""
from __future__ import annotations

import time
from pathlib import Path

import numpy as np

from .features import NAMES, vector

WEIGHTS = Path(__file__).resolve().parent / "weights" / "flow_mlp.npz"
READABLE = {
    "log_in_bytes": "bytes sent", "log_out_bytes": "bytes received", "log_in_pkts": "packets sent",
    "log_out_pkts": "packets received", "log_duration_ms": "flow duration",
    "log_in_bytes_per_pkt": "size of packets sent", "log_out_bytes_per_pkt": "size of packets received",
    "log_out_in_byte_ratio": "reply/request byte ratio", "log_out_in_pkt_ratio": "reply/request packet ratio",
    "no_reply": "no reply from the peer", "log_pkt_rate": "packet rate",
}


def _readable(name: str) -> str:
    if name in READABLE:
        return READABLE[name]
    if name.startswith("flag_"):
        return f"TCP {name[5:]} flag"
    if name.startswith("proto_"):
        return f"protocol {name[6:].upper()}"
    if name.startswith("dport_"):
        return f"destination port class '{name[6:].replace('_', ' ')}'"
    return name


class FlowClassifier:
    def __init__(self, path: str | Path = WEIGHTS):
        w = np.load(path)
        self.mean, self.std, self.threshold = w["mean"], w["std"], float(w["threshold"])
        self.layers = [(w[f"W{i}"], w[f"b{i}"]) for i in range(3)]

    def _forward(self, X: np.ndarray):
        h = (X - self.mean) / self.std
        acts = [h]
        for i, (W, b) in enumerate(self.layers):
            h = h @ W + b
            if i < 2:
                h = np.maximum(h, 0)
            acts.append(h)
        return acts

    def scores(self, X: np.ndarray) -> np.ndarray:
        z = self._forward(np.atleast_2d(X).astype(np.float32))[-1][:, 0]
        return 1 / (1 + np.exp(-z))

    def explain(self, x: np.ndarray, top: int = 3) -> list[dict]:
        """Features that raised the score most for one flow (gradient x standardised input)."""
        acts = self._forward(x[None].astype(np.float32))
        g = np.ones((1, 1), np.float32)
        for i in (2, 1, 0):
            W, _ = self.layers[i]
            g = g @ W.T
            if i > 0:
                g = g * (acts[i] > 0)
        contrib = (g[0] * acts[0][0])
        order = np.argsort(-contrib)
        present = [j for j in order if contrib[j] > 0
                   and (NAMES[j].startswith("log") or x[j] != 0)]        # one-hot/flag features only when set
        return [{"feature": NAMES[j], "meaning": _readable(NAMES[j]), "weight": round(float(contrib[j]), 3)}
                for j in present[:top]]

    def analyse(self, records: list[dict]) -> dict:
        """Score the NetFlow part ("nf") of node flow records; returns per-flow hits above threshold."""
        t0 = time.perf_counter()
        rows = [(r, r["nf"]) for r in records if isinstance(r.get("nf"), dict)]
        if not rows:
            return {"scored": 0, "hits": [], "max_score": 0.0, "compute_ms": 0.0}
        X = np.stack([vector(nf) for _, nf in rows])
        s = self.scores(X)
        hits = []
        for (r, nf), x, sc in zip(rows, X, s):
            if sc >= self.threshold:
                hits.append({"peer": r.get("dst"), "dport": r.get("dport"), "proto": r.get("proto"),
                             "score": round(float(sc), 4), "why": self.explain(x)})
        return {"scored": len(rows), "hits": hits, "max_score": round(float(s.max()), 4),
                "threshold": self.threshold, "compute_ms": round((time.perf_counter() - t0) * 1000, 3)}


_DEFAULT: FlowClassifier | None = None


def default() -> FlowClassifier | None:
    global _DEFAULT
    if _DEFAULT is None and WEIGHTS.exists():
        _DEFAULT = FlowClassifier()
    return _DEFAULT
