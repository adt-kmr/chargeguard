"""
Export the threat detectors to ExecuTorch (.pte).

Each detector is a linear model over hashed sparse features. The exported
program takes the K active feature indices and their values (padded with
index 0 / value 0) and returns the probability:

    p = sigmoid( sum_k W[idx_k] * val_k + b )

so the .pte never sees the 2^18-wide dense vector. Feature hashing stays in
Python (threatintel/features.py) on the node.

    # in the ExecuTorch environment (Linux / WSL / Raspberry Pi):
    python -m threatintel.executorch_export          # writes threatintel/weights/*.pte
    python -m threatintel.executorch_export --check  # parity against the numpy path
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import torch
from torch import nn

from threatintel import features as F

WEIGHTS = Path(__file__).resolve().parent / "weights"
MAX_ACTIVE = 1024              # active hashed features per input (SMS and hostnames use far fewer)


class SparseLinearScorer(nn.Module):
    def __init__(self, table: np.ndarray, bias: float):
        super().__init__()
        self.table = nn.Embedding(len(table), 1)
        with torch.no_grad():
            self.table.weight.copy_(torch.from_numpy(table.astype(np.float32)).unsqueeze(1))
        self.bias = nn.Parameter(torch.tensor([bias], dtype=torch.float32))

    def forward(self, indices: torch.Tensor, values: torch.Tensor) -> torch.Tensor:
        w = self.table(indices).squeeze(-1)                 # [B, K]
        return torch.sigmoid((w * values).sum(dim=-1) + self.bias)


def sms_table():
    z = np.load(WEIGHTS / "sms_scam.npz")
    return np.concatenate([z["w_word"], z["w_char"]]), float(z["bias"])


def url_table():
    z = np.load(WEIGHTS / "phishing_url.npz")
    return np.concatenate([z["w_char"], z["w_lex"]]), float(z["bias"])


def pad(indices: np.ndarray, values: np.ndarray, k: int = MAX_ACTIVE):
    if len(indices) > k:                                     # keep the strongest features
        keep = np.argsort(-np.abs(values))[:k]
        indices, values = indices[keep], values[keep]
    idx = np.zeros((1, k), dtype=np.int64)
    val = np.zeros((1, k), dtype=np.float32)
    idx[0, :len(indices)] = indices
    val[0, :len(values)] = values
    return torch.from_numpy(idx), torch.from_numpy(val)


def sms_inputs(text: str):
    norm = F.normalise_sms(text)
    xw = F.SMS_WORD.transform([norm]).tocsr()
    xc = F.SMS_CHAR.transform([norm]).tocsr()
    return pad(np.concatenate([xw.indices, xc.indices + F.N_HASH]), np.concatenate([xw.data, xc.data]))


def url_inputs(host: str):
    xc = F.HOST_CHAR.transform([host]).tocsr()
    lex = F.host_lexical(host)
    nz = np.nonzero(lex)[0]
    return pad(np.concatenate([xc.indices, nz + F.N_HASH]), np.concatenate([xc.data, lex[nz]]))


def export(name: str, table, bias, example) -> Path:
    from executorch.backends.xnnpack.partition.xnnpack_partitioner import XnnpackPartitioner
    from executorch.exir import to_edge_transform_and_lower

    model = SparseLinearScorer(table, bias).eval()
    exported = torch.export.export(model, example)
    program = to_edge_transform_and_lower(exported, partitioner=[XnnpackPartitioner()]).to_executorch()
    out = WEIGHTS / f"{name}.pte"
    out.write_bytes(program.buffer)
    return out


def check(samples_sms, samples_url) -> dict:
    """Run every .pte through the ExecuTorch runtime and compare with the numpy detectors."""
    from executorch.runtime import Runtime
    from threatintel import detectors

    sms, url = detectors()
    rt = Runtime.get()
    res = {}

    def raw_url_score(host):            # the model alone, before rules and the known-good cap
        xc = F.HOST_CHAR.transform([host]).tocsr()
        z = float(xc.dot(url.w_char)[0] + F.host_lexical(host) @ url.w_lex + url.bias)
        return 1 / (1 + np.exp(-z))

    for name, samples, fn, ref in (("sms_scam", samples_sms, sms_inputs, lambda s: sms.analyse(s).score),
                                   ("phishing_url", samples_url, url_inputs, raw_url_score)):
        method = rt.load_program(WEIGHTS / f"{name}.pte").load_method("forward")
        diffs = []
        for s in samples:
            p = float(method.execute(list(fn(s)))[0][0])
            diffs.append(abs(p - ref(s)))
        res[name] = {"samples": len(samples), "max_abs_diff": float(max(diffs))}
    return res


def bench(out_path: Path, runs: int = 500) -> dict:
    """Parity on held-out-style inputs and per-inference latency of the ExecuTorch programs."""
    import platform
    import time
    import executorch
    from executorch.runtime import Runtime
    from threatintel import detectors

    rows = (Path(__file__).resolve().parent.parent / "data" / "raw" / "sms_spam" / "SMSSpamCollection")
    texts = [ln.split("\t", 1)[1] for ln in rows.read_text(encoding="utf-8", errors="replace").splitlines()[:300]]
    hosts = [F.host_of(u) for u in ("https://chargepoint.com/pay", "https://pay-chargepoint-verify.top/login",
                                    "https://evpay-secure-update.firebaseapp.com", "http://192.168.4.1/payment",
                                    "https://www.tatapower.com", "https://maria.susypro.com",
                                    "https://accounts.google.com.verify-login.xyz")]
    sms, url = detectors()
    rt = Runtime.get()
    result = {"executorch": executorch.__version__ if hasattr(executorch, "__version__") else "1.6.0",
              "torch": torch.__version__, "host": {"machine": platform.machine(), "os": platform.platform()},
              "backend": "XNNPACK (portable kernels for embedding lookup)", "max_active_features": MAX_ACTIVE}
    for name, items, fn, ref in (
            ("sms_scam", texts, sms_inputs, lambda s: sms.analyse(s).score),
            ("phishing_url", hosts, url_inputs, lambda h: 1 / (1 + np.exp(-(float(
                F.HOST_CHAR.transform([h]).tocsr().dot(url.w_char)[0] + F.host_lexical(h) @ url.w_lex + url.bias)))))):
        method = rt.load_program(WEIGHTS / f"{name}.pte").load_method("forward")
        diffs = [abs(float(method.execute(list(fn(x)))[0][0]) - ref(x)) for x in items]
        sample = fn(items[0])
        for _ in range(20):
            method.execute(list(sample))
        times = []
        for _ in range(runs):
            t0 = time.perf_counter()
            method.execute(list(sample))
            times.append((time.perf_counter() - t0) * 1000)
        times.sort()
        result[name] = {"pte_bytes": (WEIGHTS / f"{name}.pte").stat().st_size, "parity_inputs": len(items),
                        "max_abs_diff_vs_python": float(max(diffs)),
                        "decision_agreement": float(np.mean([(float(method.execute(list(fn(x)))[0][0]) >= 0.5) ==
                                                             (ref(x) >= 0.5) for x in items])),
                        "latency_ms": {"runs": runs, "p50": round(times[len(times) // 2], 4),
                                       "p95": round(times[int(len(times) * .95)], 4)}}
    out_path.write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--bench", action="store_true", help="write benchmarks/results/executorch_detectors_<machine>.json")
    a = ap.parse_args()
    if a.bench:
        import platform
        out = Path(__file__).resolve().parent.parent / "benchmarks" / "results" / \
            f"executorch_detectors_{platform.machine().lower()}-linux.json"
        print(json.dumps(bench(out), indent=2))
        raise SystemExit(0)
    sms_samples = ["Hi, see you at the charger at 6", "URGENT: your charging account is suspended, pay now",
                   "Congratulations! You won a free charging pass. Text WIN to 80888", "Your OTP is 482913"]
    url_samples = ["pay-chargepoint-verify.top", "tatapower.com", "evpay-secure-update.firebaseapp.com",
                   "192.168.4.1", "maria.susypro.com"]
    if not a.check:
        t, b = sms_table()
        print("wrote", export("sms_scam", t, b, sms_inputs(sms_samples[0])))
        t, b = url_table()
        print("wrote", export("phishing_url", t, b, url_inputs(url_samples[0])))
    print(json.dumps(check(sms_samples, url_samples), indent=2))
