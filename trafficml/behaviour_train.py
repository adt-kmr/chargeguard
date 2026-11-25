"""
Fit and evaluate the learned per-charger baseline (trafficml.behaviour) in software mode.

Healthy traffic is synthesised as real packets (netflow.synth) with the variation a real
charger shows: 1-3 OCPP messages a second, bursts at session start, WebSocket reconnects,
DNS lookups, NTP, a periodic firmware-update check. Attack windows add hostile traffic to
the same healthy background. Five attack shapes are ones the simulator's scenarios use;
four are NOT used anywhere else (slow scan, slow DNS tunnel, HTTPS exfiltration, SSH brute
force), to test whether the model generalises beyond what it was tuned on. The model never
sees attack traffic in training.

    python -m trafficml.behaviour_train

On the Raspberry Pi the same model is fitted on the charger's real enrolment capture
(python -m trafficml.behaviour fit --records ...).
"""
from __future__ import annotations

import base64
import json
import os
import random
from pathlib import Path

import numpy as np

from integrations.behavior.baseline import Baseline
from netflow import synth
from netflow.exporter import to_node_record

from .behaviour import BehaviourModel, fit, window_vector, windows

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "benchmarks" / "results" / "behaviour_model_metrics.json"
CHARGER, NODE, LAN, C2, RESOLVER, UPDATES, EXFIL = ("10.20.0.15", "10.20.0.1", "192.168.1.254", "203.0.113.66",
                                                    "8.8.8.8", "10.20.0.1", "198.51.100.77")
WINDOW = 10.0


def healthy_frames(seconds: int, t0: float, seed: int) -> synth.Frames:
    rnd = random.Random(seed)
    random.seed(seed)
    fr: synth.Frames = []
    ws = 40001
    for s in range(seconds):
        t = t0 + s
        if rnd.random() < 0.002:                                   # WebSocket reconnect
            ws += 1
            fr += synth.tcp_session(CHARGER, NODE, ws, 9000, t, [(260, 180)], close=False)
        burst = rnd.random() < 0.02                                # session start: Authorize, StartTransaction...
        fr += synth.ocpp_slice(CHARGER, NODE, ws, t, rnd.choice([4, 5, 6]) if burst else rnd.choice([1, 1, 1, 2, 2, 3]))
        if rnd.random() < 0.05:
            fr += synth.dns_lookup(CHARGER, NODE, 30000 + s % 20000, rnd.choice(["csms.site.local", "time.site.local"]), t + 0.4)
        if s % 64 == 7:
            fr += synth.ntp_sync(CHARGER, NODE, 31000 + s % 20000, t + 0.6)
        if s % 900 == 100:                                         # firmware update check (via the node)
            fr += synth.tcp_session(CHARGER, UPDATES, 32000 + s % 20000, 443, t + 0.8, [(517, 4200), (126, 280)], rtt=0.01)
    return fr


def to_records(frames: synth.Frames) -> list[dict]:
    return [to_node_record(nf, CHARGER) for nf in synth.flows_of(frames, active_timeout=1.0, idle_timeout=2.0, tcp_linger=0.3)]


def attack_frames(kind: str, t: float, rnd: random.Random) -> synth.Frames:
    fr: synth.Frames = []
    if kind == "port_scan":
        for i, p in enumerate(rnd.sample(range(1, 65535), 60)):
            fr += synth.syn_probe(CHARGER, LAN, 45000 + i, p, t + i * 0.02, rnd.choice(["closed"] * 6 + ["filtered", "open"]))
    elif kind == "slow_scan":                                      # novel: one probe every 2 s
        for i in range(5):
            fr += synth.syn_probe(CHARGER, LAN, 45100 + i, rnd.randint(1, 1024), t + i * 2.0, "closed")
    elif kind == "c2_beacon":
        for i in range(5):
            fr += synth.c2_beacon(CHARGER, C2, 46000 + i, t + i * 2.0 + rnd.uniform(-0.3, 0.3))
    elif kind == "dns_tunnel":
        for i in range(300):
            label = base64.b32encode(os.urandom(30)).decode().rstrip("=").lower()
            fr += synth.dns_lookup(CHARGER, RESOLVER, 47000 + i, f"{label}.{i:04x}.x7k2.example", t + i * 0.02, qtype=16)
    elif kind == "slow_dns_tunnel":                                # novel: A queries via the node's own resolver
        for i in range(8):
            label = base64.b32encode(os.urandom(20)).decode().rstrip("=").lower()
            fr += synth.dns_lookup(CHARGER, NODE, 47500 + i, f"{label}.cdn-sync.example", t + i * 1.1)
    elif kind == "ocpp_flood":
        for s in range(8):
            fr += synth.ocpp_slice(CHARGER, NODE, 40001, t + s, 50, avg=180)
    elif kind == "https_exfil":                                    # novel: large upload to an unknown host
        fr += synth.tcp_session(CHARGER, EXFIL, 48000, 443, t, [(220_000, 900), (180_000, 600)], rtt=0.05)
    elif kind == "ssh_bruteforce":                                 # novel: lateral movement to a LAN host
        for i in range(12):
            fr += synth.tcp_session(CHARGER, LAN, 48100 + i, 22, t + i * 0.7, [(640, 900), (96, 64)], rtt=0.004)
    elif kind == "unexpected_service":                             # novel: Modbus to a LAN PLC
        for i in range(6):
            fr += synth.tcp_session(CHARGER, LAN, 48200 + i, 502, t + i * 1.4, [(12, 12)], rtt=0.003)
    return fr


ATTACKS = ["port_scan", "c2_beacon", "dns_tunnel", "ocpp_flood", "slow_scan", "slow_dns_tunnel",
           "https_exfil", "ssh_bruteforce", "unexpected_service"]
NOVEL = {"slow_scan", "slow_dns_tunnel", "https_exfil", "ssh_bruteforce", "unexpected_service"}


def augment(ws: list[list[dict]], seed: int = 9) -> list[list[dict]]:
    """Each healthy window plus a copy with 0-40% of the OCPP slice records missing: on a real bridge the
    exporter's timing decides how many one-second slices of a long-lived flow land in a window."""
    rnd = random.Random(seed)
    out = []
    for w in ws:
        out.append(w)
        p = rnd.uniform(0.0, 0.4)
        out.append([r for r in w if r.get("app") != "OCPP" or rnd.random() > p])
    return out


def rules_flag(window_records: list[dict], base: Baseline) -> bool:
    """The hand-written baseline rules on the same window (flows only; the live node adds the OCPP transcript)."""
    per: dict[tuple, int] = {}
    for r in window_records:
        if r.get("app") == "OCPP":
            continue
        per[(r["dst"], r["dport"], r.get("app") or r["proto"])] = per.get((r["dst"], r["dport"], r.get("app") or r["proto"]), 0) + 1
    recs = [{"dst": d, "port": p, "proto": pr, "rate": n / WINDOW} for (d, p, pr), n in per.items()]
    return base.evaluate(recs).status != "normal"


def main():
    base = Baseline.load()
    train_recs = to_records(healthy_frames(7200, 10_000.0, seed=1))
    info = fit(augment(windows(train_recs, WINDOW, step_s=2.0)), WINDOW)
    model = BehaviourModel()
    print("fitted", {k: v for k, v in info.items() if k not in ("known_peers", "known_ports")})

    test_recs = to_records(healthy_frames(3600, 50_000.0, seed=2))          # unseen healthy traffic
    hw = windows(test_recs, WINDOW, step_s=2.0)
    hs = np.array([model.analyse(w, WINDOW)["score"] for w in hw])
    res = {"window_s": WINDOW, "threshold": model.threshold, "train": {k: v for k, v in info.items() if k not in ("known_peers",)},
           "healthy_test": {"windows": len(hw), "false_alarms": int((hs > model.threshold).sum()),
                            "false_alarm_rate": round(float((hs > model.threshold).mean()), 5),
                            "rules_false_alarms": int(sum(rules_flag(w, base) for w in hw))},
           "attacks": {}}
    rnd = random.Random(5)
    for kind in ATTACKS:
        det = rule = 0
        whys = Counter_ = {}
        trials = 40
        for k in range(trials):
            t = 90_000.0 + k * 100
            bg = healthy_frames(int(WINDOW) + 2, t - 1, seed=100 + k)
            recs = to_records(bg + attack_frames(kind, t, rnd))
            w = [r for r in recs if t - 0.5 <= r["nf"]["LAST_SWITCHED"] < t + WINDOW - 0.5]
            a = model.analyse(w, WINDOW)
            det += a["anomalous"]
            rule += rules_flag(w, base)
            for y in a["why"][:1]:
                whys[y["meaning"] + f" ({y['direction']})"] = whys.get(y["meaning"] + f" ({y['direction']})", 0) + 1
        res["attacks"][kind] = {"novel": kind in NOVEL, "windows": trials, "model_detection": round(det / trials, 3),
                                "rules_detection": round(rule / trials, 3),
                                "top_reason": max(whys, key=whys.get) if whys else None}
        print(kind, res["attacks"][kind])
    del Counter_
    OUT.write_text(json.dumps(res, indent=2))
    print(json.dumps(res["healthy_test"], indent=2))


if __name__ == "__main__":
    main()
