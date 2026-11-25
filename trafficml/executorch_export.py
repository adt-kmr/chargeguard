"""
Export the two traffic models to ExecuTorch (.pte, XNNPACK) and check them.

  flow_mlp.pte       one NetFlow feature vector (39 floats) -> attack probability
  behaviour_ae.pte   one window feature vector (20 floats)  -> per-feature squared
                     reconstruction error (the anomaly score is its mean)

Standardisation is folded into the programs, so the node passes raw features. Run in
the ExecuTorch environment (WSL on Windows, or the Raspberry Pi):

    python -m trafficml.executorch_export            # export + parity check + latency
"""
from __future__ import annotations

import json
import platform
import time
from pathlib import Path

import numpy as np
import torch
from torch import nn

ROOT = Path(__file__).resolve().parents[1]
WEIGHTS = Path(__file__).resolve().parent / "weights"
RESULTS = ROOT / "benchmarks" / "results"


def _linear(W, b) -> nn.Linear:
    lin = nn.Linear(W.shape[0], W.shape[1])
    lin.weight.data = torch.from_numpy(np.ascontiguousarray(W.T))
    lin.bias.data = torch.from_numpy(b)
    return lin


class FlowMLP(nn.Module):
    def __init__(self, w):
        super().__init__()
        self.register_buffer("mean", torch.from_numpy(w["mean"]))
        self.register_buffer("std", torch.from_numpy(w["std"]))
        self.net = nn.Sequential(_linear(w["W0"], w["b0"]), nn.ReLU(), _linear(w["W1"], w["b1"]), nn.ReLU(),
                                 _linear(w["W2"], w["b2"]))

    def forward(self, x):
        return torch.sigmoid(self.net((x - self.mean) / self.std))


class BehaviourAE(nn.Module):
    def __init__(self, w):
        super().__init__()
        self.register_buffer("mean", torch.from_numpy(w["mean"]))
        self.register_buffer("std", torch.from_numpy(w["std"]))
        layers = []
        for i in range(4):
            layers.append(_linear(w[f"W{i}"], w[f"b{i}"]))
            if i < 3:
                layers.append(nn.ReLU())
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        z = (x - self.mean) / self.std
        return (self.net(z) - z) ** 2


def export(name: str, module: nn.Module, dim: int) -> Path:
    from executorch.backends.xnnpack.partition.xnnpack_partitioner import XnnpackPartitioner
    from executorch.exir import to_edge_transform_and_lower
    exported = torch.export.export(module.eval(), (torch.zeros(1, dim),))
    program = to_edge_transform_and_lower(exported, partitioner=[XnnpackPartitioner()]).to_executorch()
    out = WEIGHTS / f"{name}.pte"
    out.write_bytes(program.buffer)
    return out


def samples():
    """Real inputs: flows and windows from the charger traffic synthesiser."""
    import random
    from netflow import synth
    from netflow.exporter import to_node_record
    from trafficml.behaviour import BehaviourModel, window_vector
    from trafficml.features import vector
    random.seed(4)
    C, N = "10.20.0.15", "10.20.0.1"
    fr = []
    for s in range(30):
        fr += synth.ocpp_slice(C, N, 40001, 1000.0 + s, random.choice([1, 2, 3]))
    for i in range(30):
        fr += synth.syn_probe(C, "192.168.1.254", 45000 + i, random.randint(1, 65535), 1010.0 + i * 0.03)
    fr += synth.tcp_session(C, "203.0.113.66", 46000, 4444, 1012.0, [(220, 300)], rtt=0.08)
    recs = [to_node_record(nf, C) for nf in synth.flows_of(fr, active_timeout=1.0, idle_timeout=2.0, tcp_linger=0.3)]
    m = BehaviourModel()
    flows = np.stack([vector(r["nf"]) for r in recs]).astype(np.float32)
    wins = np.stack([window_vector([r for r in recs if t - 10 <= r["nf"]["LAST_SWITCHED"] < t], 10.0,
                                   m.known_peers, m.known_ports) for t in range(1005, 1031)]).astype(np.float32)
    return flows, wins


def check_and_bench(runs: int = 1000) -> dict:
    from executorch.runtime import Runtime
    from trafficml.behaviour import BehaviourModel
    from trafficml.detector import FlowClassifier
    clf, beh = FlowClassifier(), BehaviourModel()
    flows, wins = samples()
    rt = Runtime.get()
    res = {"torch": torch.__version__, "host": {"machine": platform.machine(), "os": platform.platform()},
           "backend": "XNNPACK"}
    for name, X, ref, decide in (
            ("flow_mlp", flows, lambda x: clf.scores(x)[0], lambda v: v >= clf.threshold),
            ("behaviour_ae", wins, lambda x: beh.score(x)[0], lambda v: v > beh.threshold)):
        method = rt.load_program(WEIGHTS / f"{name}.pte").load_method("forward")
        run = (lambda x, m=method: float(m.execute([torch.from_numpy(x[None])])[0].numpy().mean())
               if name == "behaviour_ae" else float(m.execute([torch.from_numpy(x[None])])[0].numpy().ravel()[0]))
        et = np.array([run(x) for x in X])
        py = np.array([ref(x) for x in X])
        for _ in range(50):
            run(X[0])
        t = []
        for _ in range(runs):
            t0 = time.perf_counter()
            run(X[0])
            t.append((time.perf_counter() - t0) * 1000)
        res[name] = {"pte_bytes": (WEIGHTS / f"{name}.pte").stat().st_size, "samples": int(len(X)),
                     "max_abs_diff_vs_numpy": float(np.abs(et - py).max()),
                     "decision_agreement": float(np.mean([decide(a) == decide(b) for a, b in zip(et, py)])),
                     "latency_ms": {"p50": round(float(np.percentile(t, 50)), 4), "p95": round(float(np.percentile(t, 95)), 4)}}
    out = RESULTS / f"executorch_traffic_{platform.machine().lower()}-{platform.system().lower()}.json"
    out.write_text(json.dumps(res, indent=2))
    return res


def main():
    from trafficml.behaviour import DIM as WDIM
    from trafficml.features import DIM as FDIM
    export("flow_mlp", FlowMLP(np.load(WEIGHTS / "flow_mlp.npz")), FDIM)
    export("behaviour_ae", BehaviourAE(np.load(WEIGHTS / "behaviour_ae.npz")), WDIM)
    print(json.dumps(check_and_bench(), indent=2))


if __name__ == "__main__":
    main()
