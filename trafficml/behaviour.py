"""
Learned per-charger baseline: an autoencoder over 10-second windows of the charger's
flow records, trained only on healthy traffic. A window it cannot reconstruct is a
deviation from how this charger normally behaves; the features with the largest
reconstruction error explain it.

This complements the per-flow classifier (trafficml.detector): scans, beacons, DNS
tunnels and floods consist of individually ordinary flows and only stand out in
aggregate. It needs no attack labels, so on the Raspberry Pi it is fitted on the
charger's own enrolment capture:

    python -m trafficml.behaviour fit --records enrolment.jsonl     # node flow records, one per line
"""
from __future__ import annotations

import argparse
import json
import math
import time
from collections import Counter
from pathlib import Path

import numpy as np

WEIGHTS = Path(__file__).resolve().parent / "weights" / "behaviour_ae.npz"
NAMES = ["log_flow_rate", "log_dst_hosts", "log_dst_ports", "frac_no_reply", "frac_refused", "frac_syn_only",
         "log_dns_queries", "log_max_dns_label", "max_dns_label_entropy", "frac_new_peers", "frac_new_ports",
         "log_bytes_sent_per_s", "log_bytes_received_per_s", "log_sent_received_ratio", "log_pkt_rate", "beacon_regularity",
         "dominant_service_share", "frac_udp", "log_ocpp_pkt_rate", "frac_txt_queries"]
READABLE = {
    "log_flow_rate": "connection rate", "log_dst_hosts": "number of destination hosts",
    "log_dst_ports": "number of destination ports", "frac_no_reply": "share of connections with no reply",
    "frac_refused": "share of refused connections", "frac_syn_only": "share of half-open (SYN-only) connections",
    "log_dns_queries": "DNS query count", "log_max_dns_label": "longest DNS name label",
    "max_dns_label_entropy": "randomness of DNS names", "frac_new_peers": "share of never-seen destinations",
    "frac_new_ports": "share of never-seen ports", "log_bytes_sent_per_s": "upload rate", "log_bytes_received_per_s": "download rate",
    "log_sent_received_ratio": "upload/download ratio", "log_pkt_rate": "packet rate",
    "beacon_regularity": "regular, beacon-like timing", "dominant_service_share": "share of the busiest service",
    "frac_udp": "share of UDP", "log_ocpp_pkt_rate": "OCPP packet rate", "frac_txt_queries": "share of DNS TXT queries",
}
DIM = len(NAMES)
OCPP_PORTS = {9000, 8080}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def window_vector(records: list[dict], window_s: float, known_peers: set, known_ports: set) -> np.ndarray:
    """Features of one window of node flow records (only records carrying a NetFlow "nf" part)."""
    nfs = [r for r in records if isinstance(r.get("nf"), dict)]
    x = np.zeros(DIM, dtype=np.float32)
    if not nfs:
        return x
    n = len(nfs)
    nf = [r["nf"] for r in nfs]
    dsts = {r["dst"] for r in nfs}
    ports = {r["dport"] for r in nfs}
    tcp = [f for f in nf if f["PROTOCOL"] == 6]
    dns = [f for f in nf if f.get("DNS_QUERY_TYPE")]
    labels = [(f.get("DNS_QUERY_NAME") or "").split(".")[0] for f in dns]
    sent = sum(f["IN_BYTES"] for f in nf)
    recv = sum(f["OUT_BYTES"] for f in nf)
    pkts = sum(f["IN_PKTS"] + f["OUT_PKTS"] for f in nf)
    by_service = Counter((r["dst"], r["dport"]) for r in nfs)
    starts: dict[tuple, list[float]] = {}
    for r in nfs:
        starts.setdefault((r["dst"], r["dport"]), []).append(r["nf"].get("FIRST_SWITCHED", 0.0))
    regular = 0.0
    for (dst, port), ts in starts.items():
        if len(ts) >= 3 and port not in OCPP_PORTS:
            gaps = np.diff(sorted(ts))
            if gaps.mean() > 0.2:
                regular = max(regular, 1.0 - min(1.0, float(gaps.std() / gaps.mean())))
    x[0], x[1], x[2] = math.log1p(n / window_s), math.log1p(len(dsts)), math.log1p(len(ports))
    x[3] = sum(f["OUT_PKTS"] == 0 for f in nf) / n
    x[4] = sum(bool(f["SERVER_TCP_FLAGS"] & 0x04) for f in tcp) / max(len(tcp), 1)
    x[5] = sum(f["CLIENT_TCP_FLAGS"] == 0x02 for f in tcp) / max(len(tcp), 1)
    x[6] = math.log1p(len(dns))
    x[7] = math.log1p(max((len(lb) for lb in labels), default=0))
    x[8] = max((_entropy(lb) for lb in labels), default=0.0)
    x[9] = sum(r["dst"] not in known_peers for r in nfs) / n
    x[10] = sum(r["dport"] not in known_ports for r in nfs) / n
    x[11], x[12] = math.log1p(sent / window_s), math.log1p(recv / window_s)
    x[13] = math.log((sent + 1) / (recv + 1))
    x[14] = math.log1p(pkts / window_s)
    x[15] = regular
    x[16] = max(by_service.values()) / n
    x[17] = sum(f["PROTOCOL"] == 17 for f in nf) / n
    x[18] = math.log1p(sum(f["IN_PKTS"] + f["OUT_PKTS"] for f in nf if f["L4_DST_PORT"] in OCPP_PORTS) / window_s)
    x[19] = sum(f.get("DNS_QUERY_TYPE") == 16 for f in dns) / max(len(dns), 1)
    return x


def windows(records: list[dict], window_s: float = 10.0, step_s: float = 1.0) -> list[list[dict]]:
    """Sliding windows over records ordered by flow end time (LAST_SWITCHED)."""
    recs = sorted((r for r in records if isinstance(r.get("nf"), dict)), key=lambda r: r["nf"]["LAST_SWITCHED"])
    if not recs:
        return []
    t0, t1 = recs[0]["nf"]["LAST_SWITCHED"], recs[-1]["nf"]["LAST_SWITCHED"]
    out, i, t = [], 0, t0 + window_s
    while t <= t1 + step_s:
        out.append([r for r in recs if t - window_s <= r["nf"]["LAST_SWITCHED"] < t])
        t += step_s
        i += 1
    return out


class BehaviourModel:
    def __init__(self, path: str | Path = WEIGHTS):
        w = np.load(path, allow_pickle=False)
        self.mean, self.std = w["mean"], w["std"]
        self.layers = [(w[f"W{i}"], w[f"b{i}"]) for i in range(4)]
        self.threshold = float(w["threshold"])
        meta = json.loads(str(w["meta"]))
        self.known_peers, self.known_ports = set(meta["known_peers"]), set(meta["known_ports"])
        self.window_s = float(meta["window_s"])

    def _reconstruct(self, Z: np.ndarray) -> np.ndarray:
        h = Z
        for i, (W, b) in enumerate(self.layers):
            h = h @ W + b
            if i < 3:
                h = np.maximum(h, 0)
        return h

    def errors(self, X: np.ndarray) -> np.ndarray:
        Z = (np.atleast_2d(X) - self.mean) / self.std
        return (self._reconstruct(Z) - Z) ** 2

    def score(self, X: np.ndarray) -> np.ndarray:
        return self.errors(X).mean(axis=1)

    def analyse(self, records: list[dict], window_s: float | None = None) -> dict:
        t0 = time.perf_counter()
        x = window_vector(records, window_s or self.window_s, self.known_peers, self.known_ports)
        err = self.errors(x)[0]
        s = float(err.mean())
        z = (x - self.mean) / self.std
        # explain by distance from this charger's normal range (clearer to an operator than per-feature
        # reconstruction error, which an autoencoder spreads across correlated features)
        top = [{"feature": NAMES[j], "meaning": READABLE[NAMES[j]], "direction": "higher" if z[j] > 0 else "lower",
                "deviation_sd": round(float(abs(z[j])), 1)} for j in np.argsort(-np.abs(z))[:3]]
        return {"score": round(s, 4), "threshold": round(self.threshold, 4), "anomalous": s > self.threshold,
                "why": top if s > self.threshold else [], "flows": sum(isinstance(r.get("nf"), dict) for r in records),
                "compute_ms": round((time.perf_counter() - t0) * 1000, 3)}


def fit(healthy_windows: list[list[dict]], window_s: float = 10.0, epochs: int = 60, seed: int = 3,
        out: Path = WEIGHTS, quantile: float = 0.999, margin: float = 1.25) -> dict:
    """Train on healthy windows: 85% for the autoencoder, 15% to set the threshold."""
    import torch
    rng = np.random.default_rng(seed)
    flat = [r for w in healthy_windows for r in w]
    peers = sorted({r["dst"] for r in flat})
    ports = sorted({int(r["dport"]) for r in flat})
    X = np.stack([window_vector(w, window_s, set(peers), set(ports)) for w in healthy_windows])
    idx = rng.permutation(len(X))
    cut = int(0.85 * len(X))
    tr, va = X[idx[:cut]], X[idx[cut:]]
    mean, std = tr.mean(0), np.maximum(tr.std(0), 0.15)   # floor: tolerate export-timing jitter, stay sensitive
    torch.manual_seed(seed)
    net = torch.nn.Sequential(torch.nn.Linear(DIM, 12), torch.nn.ReLU(), torch.nn.Linear(12, 6), torch.nn.ReLU(),
                              torch.nn.Linear(6, 12), torch.nn.ReLU(), torch.nn.Linear(12, DIM))
    opt = torch.optim.Adam(net.parameters(), lr=3e-3)
    Zt = torch.from_numpy((tr - mean) / std)
    for _ in range(epochs):
        for i in range(0, len(Zt), 128):
            b = Zt[torch.randperm(len(Zt))[:128]]
            opt.zero_grad()
            torch.nn.functional.mse_loss(net(b), b).backward()
            opt.step()
    lin = [m for m in net if isinstance(m, torch.nn.Linear)]
    with torch.no_grad():
        v = ((net(torch.from_numpy((va - mean) / std)) - torch.from_numpy((va - mean) / std)) ** 2).mean(1).numpy()
    thr = float(np.quantile(v, quantile) * margin)
    out.parent.mkdir(parents=True, exist_ok=True)
    meta = {"known_peers": peers, "known_ports": ports, "window_s": window_s, "train_windows": int(len(tr)),
            "threshold_windows": int(len(va)), "threshold_rule": f"{quantile} quantile x {margin}"}
    np.savez_compressed(out, mean=mean.astype(np.float32), std=std.astype(np.float32), threshold=np.float32(thr),
                        meta=np.array(json.dumps(meta)),
                        **{f"W{i}": m.weight.detach().numpy().T.astype(np.float32) for i, m in enumerate(lin)},
                        **{f"b{i}": m.bias.detach().numpy().astype(np.float32) for i, m in enumerate(lin)})
    return {"threshold": thr, **meta, "healthy_validation_max": float(v.max())}


_DEFAULT: BehaviourModel | None = None


def default() -> BehaviourModel | None:
    global _DEFAULT
    if _DEFAULT is None and WEIGHTS.exists():
        _DEFAULT = BehaviourModel()
    return _DEFAULT


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fit", help="fit the baseline on a healthy enrolment capture")
    f.add_argument("--records", required=True, help="JSONL of node flow records (with 'nf')")
    f.add_argument("--window", type=float, default=10.0)
    f.add_argument("--out", default=str(WEIGHTS))
    a = ap.parse_args()
    recs = [json.loads(line) for line in open(a.records) if line.strip()]
    print(json.dumps(fit(windows(recs, a.window), a.window, out=Path(a.out)), indent=2))


if __name__ == "__main__":
    main()
