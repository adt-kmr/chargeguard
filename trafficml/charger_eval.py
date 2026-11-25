"""
How the flow classifier behaves on charger-shaped traffic.

Healthy traffic (OCPP WebSocket slices, DNS, NTP, a TLS update check) and hostile
traffic (port scan, C2 beacons, DNS tunnelling, OCPP flood) are built as real packets
with netflow.synth and aggregated by the same FlowTable the node runs on its bridge.
This is a domain check, not a benchmark: the traffic is synthetic, so it shows whether
the model trained on NF-UNSW-NB15 stays quiet on a healthy charger and which attack
shapes it recognises without charger-specific rules.

    python -m trafficml.charger_eval
"""
from __future__ import annotations

import base64
import json
import os
import random
from pathlib import Path

from netflow import synth

from .detector import FlowClassifier

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "benchmarks" / "results" / "traffic_classifier_charger_sim.json"
CHARGER, NODE, LAN_HOST, C2, RESOLVER, UPDATES = "10.20.0.15", "10.20.0.1", "192.168.1.254", "203.0.113.66", "8.8.8.8", "198.51.100.20"


def healthy(seconds: int = 600) -> list[dict]:
    fr = []
    for s in range(seconds):
        fr += synth.ocpp_slice(CHARGER, NODE, 40001, 1000.0 + s, random.choice([1, 1, 2, 3]))
        if s % 64 == 0:
            fr += synth.ntp_sync(CHARGER, NODE, 30000 + s, 1000.3 + s)
        if s % 30 == 0:
            fr += synth.dns_lookup(CHARGER, NODE, 31000 + s, random.choice(["csms.site.local", "time.site.local"]), 1000.5 + s)
        if s % 300 == 0:
            fr += synth.tcp_session(CHARGER, UPDATES, 32000 + s, 443, 1000.7 + s,
                                    [(517, 4200), (126, 280), (420, 9800)], rtt=0.04)
    # the OCPP WebSocket is long-lived: export one record per second, as the node's 1 s active timeout does
    return synth.flows_of(fr, active_timeout=1.0, idle_timeout=15.0)


def attacks() -> dict[str, list[dict]]:
    t = 5000.0
    scan = []
    ports = synth_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 502, 1883, 3389, 5900, 8080] + random.sample(range(1024, 65535), 84)
    for i, p in enumerate(synth_ports):
        scan += synth.syn_probe(CHARGER, LAN_HOST, 45000 + i, p, t + i * 0.02, random.choice(["closed"] * 8 + ["open", "filtered"]))
    c2 = []
    for i in range(30):
        c2 += synth.c2_beacon(CHARGER, C2, 46000 + i, t + i * 2.0 + random.uniform(-0.5, 0.5))
    exfil = []
    for i in range(300):
        label = base64.b32encode(os.urandom(30)).decode().rstrip("=").lower()
        exfil += synth.dns_lookup(CHARGER, RESOLVER, 47000 + i, f"{label}.{i:04x}.x7k2.example", t + i * 0.02, qtype=16)
    flood = []
    for s in range(10):
        flood += synth.ocpp_slice(CHARGER, NODE, 40001, t + s, 60, avg=180)
    del ports
    return {"port_scan": synth.flows_of(scan), "c2_beacon": synth.flows_of(c2),
            "dns_tunnel": synth.flows_of(exfil), "ocpp_flood": synth.flows_of(flood, active_timeout=1.0)}


def main():
    random.seed(11)
    clf = FlowClassifier()
    norm = healthy()
    s = clf.scores(__import__("numpy").stack([__import__("trafficml.features", fromlist=["vector"]).vector(r) for r in norm]))
    res = {"note": "synthetic charger traffic built as real packets and aggregated by netflow.FlowTable",
           "threshold": clf.threshold,
           "healthy": {"flows": len(norm), "flagged": int((s >= clf.threshold).sum()),
                       "false_positive_rate": round(float((s >= clf.threshold).mean()), 4),
                       "max_score": round(float(s.max()), 4)}}
    for name, recs in attacks().items():
        from trafficml.features import vector
        import numpy as np
        sc = clf.scores(np.stack([vector(r) for r in recs]))
        flagged = sc >= clf.threshold
        top = recs[int(np.argmax(sc))]
        res[name] = {"flows": len(recs), "flagged": int(flagged.sum()), "detection_rate": round(float(flagged.mean()), 4),
                     "max_score": round(float(sc.max()), 4), "why_top": clf.explain(vector(top))}
    OUT.write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
