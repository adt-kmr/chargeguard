"""Tests for the pure-Python parts of `integrations` (no external tools needed).

Run:  python -m pytest tests/  (or)  python tests/test_integrations.py
"""
import hashlib
import json
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from integrations import Finding, Severity, ToolResult, doctor  # noqa: E402
from integrations.behavior import Action, Baseline, render_wolfsentry_config  # noqa: E402
from integrations.evidence import build_bundle, build_sarif, verify_bundle  # noqa: E402
from integrations.integrity import parse_wolfboot, verify_wolfboot_hash  # noqa: E402
from integrations.vulnerability import (  # noqa: E402
    AuditStore, FirmwareAudit, classify, parse_checksec, parse_grype, parse_mithril,
)
from simulator.charger import AttackConfig, ChargerSimulator  # noqa: E402


def _flows(attack):
    s = ChargerSimulator()
    s.configure(AttackConfig(behavior_attack=attack))
    return s.get_traffic_sample()


# ── C4 behaviour ──────────────────────────────────────────────────────────

def test_baseline_normal_traffic():
    r = Baseline.load().evaluate(_flows("normal"))
    assert r.status == "normal" and r.action is Action.NONE


def test_baseline_attacks_isolate():
    b = Baseline.load()
    for attack, rule in [("port_scan", "port-scan"), ("c2", "c2-pattern"), ("dns_exfil", "exfiltration")]:
        r = b.evaluate(_flows(attack))
        assert r.status == "suspicious" and r.action is Action.ISOLATE, attack
        assert rule in {a.rule for a in r.anomalies}, attack


def test_baseline_burst_rate_limits():
    r = Baseline.load().evaluate(_flows("burst"))
    assert r.action is Action.BLOCK and "FLOOD" in r.rate_limited


def test_baseline_phase_order():
    b = Baseline.load()
    ok = [{"dst": "127.0.0.1", "port": 8080, "proto": "OCPP", "message": m}
          for m in ("BootNotification", "Heartbeat", "StartTransaction")]
    bad = [{"dst": "127.0.0.1", "port": 8080, "proto": "OCPP", "message": "MeterValues"}]
    assert b.evaluate(ok).status == "normal"
    assert "phase-violation" in {a.rule for a in b.evaluate(bad).anomalies}


def test_wolfsentry_isolate_policy():
    b = Baseline.load()
    cfg = render_wolfsentry_config(b.evaluate(_flows("c2")), b)
    assert cfg["default-policies"]["default-policy"] == "reject"
    assert all(r["green-listed"] for r in cfg["static-routes-insert"])
    cfg_ok = render_wolfsentry_config(b.evaluate(_flows("normal")), b)
    assert cfg_ok["default-policies"]["default-policy"] == "accept"


# ── C3 parsers + cache ───────────────────────────────────────────────────

def test_parsers():
    g = parse_grype({"matches": [{"vulnerability": {"id": "CVE-2022-0778", "severity": "High"},
                                  "artifact": {"name": "openssl", "version": "1.1.1k"}}]})
    assert g[0].rule_id == "CVE-2022-0778" and g[0].severity is Severity.HIGH
    m = parse_mithril({"keys": [{"type": "weak-rsa", "path": "/etc/ssl/k.pem"}], "secrets": []})
    assert m[0].severity is Severity.CRITICAL
    c = parse_checksec([{"name": "/bin/x", "checks": {"nx": "NX disabled", "pie": "PIE Enabled",
                                                       "relro": "No RELRO", "canary": "Canary Found"}}])
    assert {f.rule_id for f in c} == {"no-nx", "no-relro"}


def test_classify():
    cve = ToolResult("grype", True, [Finding("grype", "CVE-1", "x", Severity.HIGH)])
    weak = ToolResult("checksec", True, [Finding("checksec", "no-nx", "x", Severity.HIGH)])
    assert classify([cve, weak]) == "known-cves"
    assert classify([weak]) == "weak-config"
    assert classify([ToolResult("grype", True)]) == "none"


def test_audit_cache_by_hash():
    with tempfile.TemporaryDirectory() as d:
        fw = Path(d) / "fw.bin"
        fw.write_bytes(b"firmware-bytes")
        store = AuditStore(Path(d) / "cache.db")
        audit = FirmwareAudit(store, work_dir=d, steps=[])        # no external tools
        first = audit.audit(fw)
        assert first["sha256"] == hashlib.sha256(b"firmware-bytes").hexdigest()
        assert store.get(first["sha256"])["weaknesses"] == "none"
        assert audit.audit(fw)["audited_at"] == first["audited_at"]   # served from cache


# ── C2 wolfBoot header ───────────────────────────────────────────────────

def _wolfboot_image(fw: bytes, header_size=256, corrupt=False) -> bytes:
    hdr = bytearray(b"FLOW" + struct.pack("<I", len(fw)))
    hdr += struct.pack("<HHI", 0x01, 4, 7)                   # version 7
    sha_off = len(hdr)
    digest = hashlib.sha256(bytes(hdr) + fw).digest()
    hdr += struct.pack("<HH", 0x03, 32) + digest + struct.pack("<HH", 0x00, 0)
    hdr += b"\xff" * (header_size - len(hdr))
    assert sha_off
    return bytes(hdr) + (fw[:-1] + b"X" if corrupt else fw)


def test_wolfboot_hash():
    with tempfile.TemporaryDirectory() as d:
        good, bad = Path(d) / "good.bin", Path(d) / "bad.bin"
        good.write_bytes(_wolfboot_image(b"A" * 1000))
        bad.write_bytes(_wolfboot_image(b"A" * 1000, corrupt=True))
        assert parse_wolfboot(good.read_bytes()).version == 7
        assert verify_wolfboot_hash(good).ok
        r = verify_wolfboot_hash(bad)
        assert not r.ok and r.findings[0].rule_id == "wolfboot-hash-mismatch"


# ── C7 evidence ──────────────────────────────────────────────────────────

def test_sarif_shape():
    s = build_sarif(findings=[Finding("grype", "CVE-1", "openssl", Severity.CRITICAL, "openssl")])
    assert s["version"] == "2.1.0" and s["runs"][0]["results"][0]["level"] == "error"


def test_bundle_detects_tampering():
    with tempfile.TemporaryDirectory() as d:
        b = build_bundle(Path(d) / "bundle", {"verdict": "green"},
                         findings=[Finding("checksec", "no-pie", "x", Severity.MEDIUM)])
        ok, problems = verify_bundle(b)
        assert ok, problems
        (b / "verdict.json").write_text(json.dumps({"verdict": "red"}))
        ok, problems = verify_bundle(b)
        assert not ok and "modified: verdict.json" in problems


def test_doctor_lists_tools():
    report = doctor()
    for name in ("cosign", "syft", "grype", "unblob", "iotaudit", "renode"):
        assert name in report


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok ", name)
