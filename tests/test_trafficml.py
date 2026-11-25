"""Traffic models: shared features, flow classifier, learned per-charger baseline, node integration."""
import base64
import os
import random

import numpy as np
import pandas as pd
import pytest

from netflow import synth
from netflow.exporter import to_node_record
from trafficml.features import DIM, matrix, vector

C, NODE = "10.20.0.15", "10.20.0.1"


def _records(frames):
    return [to_node_record(nf, C) for nf in synth.flows_of(frames, active_timeout=1.0, idle_timeout=2.0, tcp_linger=0.3)]


def _healthy(t0=1000.0, seconds=12, seed=0):
    random.seed(seed)
    fr = []
    for s in range(seconds):
        fr += synth.ocpp_slice(C, NODE, 40001, t0 + s, random.choice([1, 2, 3]))
    return fr + synth.dns_lookup(C, NODE, 30000, "csms.site.local", t0 + 0.3)


def test_vector_and_matrix_agree():
    recs = synth.flows_of(synth.tcp_session(C, NODE, 1, 9000, 1.0, [(300, 100)]) +
                          synth.syn_probe(C, "192.168.1.2", 2, 445, 2.0) + synth.dns_lookup(C, NODE, 3, "a.b", 3.0))
    df = pd.DataFrame(recs)
    assert np.abs(matrix(df) - np.stack([vector(r) for r in recs])).max() == 0 and DIM == 39


def test_flow_classifier_scores_and_explains():
    from trafficml.detector import FlowClassifier
    clf = FlowClassifier()
    recs = _records(_healthy())
    r = clf.analyse(recs)
    assert r["scored"] == len(recs) and 0 <= r["max_score"] <= 1
    x = vector(recs[0]["nf"])
    assert all(w["weight"] > 0 for w in clf.explain(x))


def test_learned_baseline_quiet_on_healthy_and_flags_scan():
    from trafficml.behaviour import BehaviourModel
    m = BehaviourModel()
    healthy = _records(_healthy())
    w = [r for r in healthy if 1000.5 <= r["nf"]["LAST_SWITCHED"] < 1010.5]
    assert not m.analyse(w, 10.0)["anomalous"]
    scan = []
    for i, p in enumerate(random.sample(range(1, 65535), 40)):
        scan += synth.syn_probe(C, "192.168.1.254", 45000 + i, p, 1002.0 + i * 0.05, "closed")
    bad = [r for r in _records(_healthy() + scan) if 1000.5 <= r["nf"]["LAST_SWITCHED"] < 1010.5]
    a = m.analyse(bad, 10.0)
    assert a["anomalous"] and a["why"]


def test_learned_baseline_flags_dns_tunnel_through_approved_resolver():
    """No rule catches this one: DNS through the node's own resolver, but with random names."""
    from trafficml.behaviour import BehaviourModel
    m = BehaviourModel()
    fr = _healthy()
    for i in range(8):
        label = base64.b32encode(os.urandom(20)).decode().rstrip("=").lower()
        fr += synth.dns_lookup(C, NODE, 47500 + i, f"{label}.cdn-sync.example", 1001.0 + i * 1.1)
    w = [r for r in _records(fr) if 1000.5 <= r["nf"]["LAST_SWITCHED"] < 1010.5]
    assert m.analyse(w, 10.0)["anomalous"]


def test_check_behaviour_waits_for_a_full_window():
    from gateway.checks import check_behaviour
    recs = _records(_healthy())
    r = check_behaviour([], 10.0, flows=recs, span_s=3.0)
    assert r.evidence["learned"]["learned_baseline"]["status"] == "warming up"
    r = check_behaviour([], 10.0, flows=[x for x in recs if x["nf"]["LAST_SWITCHED"] < 1010.5], span_s=10.0)
    assert r.status == "pass" and r.evidence["learned"]["learned_baseline"]["anomalous"] is False


@pytest.mark.parametrize("peer,expect_fail", [(NODE, False), ("203.0.113.9", True)])
def test_flow_classifier_alone_never_fails_on_approved_peers(monkeypatch, peer, expect_fail):
    from gateway import checks
    from trafficml import detector

    class Always:
        threshold = 0.5

        def analyse(self, flows):
            return {"scored": 1, "hits": [{"peer": peer, "dport": 443, "proto": "TCP", "score": 0.99, "why": []}],
                    "max_score": 0.99, "compute_ms": 0.1}
    monkeypatch.setattr(detector, "default", lambda: Always())
    monkeypatch.setattr("trafficml.behaviour.default", lambda: None)
    r = checks.check_behaviour([], 10.0, flows=[{"nf": {}, "dst": peer}], span_s=10.0)
    assert any(a["rule"] == "ml-flow" for a in r.evidence["anomalies"]) is expect_fail
