"""
Measure ChargeGuard's verification path on the machine it runs on.

Two things are measured separately, because they mean different things:

  1. End-to-end verification per demo scenario, as the dashboard runs it.
     The simulated checks contain fixed asyncio.sleep() delays that stand in
     for TPM and network round-trips, so this number is dominated by those
     delays and shows the user-facing timeline, not compute cost.
  2. The compute on the hot path with no simulated delays: signature checks,
     registry lookups, the behaviour baseline, verdict fusion, report signing
     and the TPM quote/verify used by the attestation layer.

Usage:
    python benchmarks/bench_hotpath.py                 # writes benchmarks/results/<host>.json
    python benchmarks/bench_hotpath.py --runs 2000 --e2e-runs 5
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _cpu_name() -> str:
    if sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith(("model name", "hardware", "cpu part")):
                    return line.split(":", 1)[1].strip()
        except OSError:
            pass
    if sys.platform == "win32":
        import subprocess
        try:
            out = subprocess.run(["powershell", "-NoProfile", "-c", "(Get-CimInstance Win32_Processor).Name"],
                                 capture_output=True, text=True, timeout=10).stdout.strip()
            if out:
                return out
        except (OSError, subprocess.SubprocessError):
            pass
    return platform.processor() or "unknown"


def _stats(samples_s: list[float]) -> dict:
    ms = sorted(s * 1000 for s in samples_s)
    pick = lambda q: ms[min(len(ms) - 1, int(q * len(ms)))]  # noqa: E731
    return {"runs": len(ms), "p50_ms": round(statistics.median(ms), 4), "p95_ms": round(pick(0.95), 4),
            "p99_ms": round(pick(0.99), 4), "max_ms": round(ms[-1], 4), "mean_ms": round(statistics.fmean(ms), 4)}


def _time(fn, runs: int, warmup: int = 20) -> dict:
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t)
    return _stats(samples)


def setup() -> None:
    from db.database import init_db, seed_cves, seed_firmware, seed_identity
    from firmware.generator import generate_all
    init_db()
    fw, cves, ids = generate_all()
    seed_firmware(fw)
    seed_cves(cves)
    seed_identity(ids)


def bench_components(runs: int) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from db.database import lookup_cves, lookup_firmware, lookup_identity
    from evidence.signer import sign_verdict, verify_verdict
    from firmware.generator import get_hash_for_mode, get_vendor_pub_hex
    from integrations.behavior import Baseline
    from orchestrator.trust_engine import fuse
    from checks.identity.identity_check import CheckResult
    from simulator.charger import AttackConfig, ChargerSimulator
    from attestation import PCRSelection, get_backend, get_verifier

    sim = ChargerSimulator()
    fw_info = sim.get_firmware_info()
    vendor_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(get_vendor_pub_hex()))
    good_hash, vuln_hash = get_hash_for_mode("healthy"), get_hash_for_mode("vulnerable")
    nonce = os.urandom(32)
    baseline = Baseline.load()
    c2 = ChargerSimulator()
    c2.configure(AttackConfig(behavior_attack="c2"))
    flows_normal, flows_c2 = sim.get_traffic_sample(), c2.get_traffic_sample()
    results = {n: CheckResult(n, "pass", "ok") for n in ("identity", "integrity", "weaknesses", "behavior")}
    payload = {"session_id": "bench", "verdict": "green", "score": 100, "results": {}}
    sig = sign_verdict(payload)

    tpm = get_backend("software")
    tpm.extend_pcr(0, b"bootloader")
    ak = tpm.get_endorsement_key()
    sel = PCRSelection(indices=(0, 1, 7))
    evidence = tpm.collect_evidence("CG-CHARGER-001", nonce, sel)
    verifier = get_verifier("local")

    device_pub = sim._legit_key.public_key()

    def identity_sign_verify():
        device_pub.verify(sim.sign_nonce(nonce), nonce)

    import sqlite3
    from config import DB_PATH
    persistent = sqlite3.connect(str(DB_PATH))

    def lookup_persistent():
        persistent.execute("SELECT * FROM firmware_registry WHERE hash=?", (good_hash,)).fetchone()

    return {
        "identity_nonce_sign_and_verify_ed25519": _time(identity_sign_verify, runs),
        "identity_registry_lookup_sqlite": _time(lambda: lookup_identity("CG-CHARGER-001"), runs),
        "integrity_registry_lookup_sqlite": _time(lambda: lookup_firmware(good_hash), runs),
        "integrity_vendor_sig_verify_ed25519": _time(
            lambda: vendor_pub.verify(bytes.fromhex(fw_info["sig_hex"]), bytes.fromhex(fw_info["hash"])), runs),
        "reference_same_lookup_persistent_connection": _time(lookup_persistent, runs),
        "weakness_cve_lookup_by_hash_sqlite": _time(lambda: lookup_cves(vuln_hash), runs),
        "behavior_baseline_normal_traffic": _time(lambda: baseline.evaluate(flows_normal), runs),
        "behavior_baseline_c2_traffic": _time(lambda: baseline.evaluate(flows_c2), runs),
        "verdict_fusion": _time(lambda: fuse(results), runs),
        "verdict_sign_ed25519": _time(lambda: sign_verdict(payload), runs),
        "verdict_verify_ed25519": _time(lambda: verify_verdict(payload, sig), runs),
        "attestation_quote_software_tpm_p256": _time(lambda: tpm.quote(nonce, sel), runs),
        "attestation_verify_quote_p256": _time(lambda: verifier.verify(evidence, nonce, ak), runs),
    }


async def _one_e2e(mode: str) -> tuple[float, str, dict]:
    from orchestrator.orchestrator import run_verification
    from simulator.charger import ChargerSimulator
    sim = ChargerSimulator()
    sim.set_mode(mode)
    t = time.perf_counter()
    verdict, steps = None, {}
    async for ev in run_verification(sim, "bench"):
        if ev["event"] == "check_done":
            steps[ev["check"]] = ev["t"]
        if ev["event"] == "verdict":
            verdict = ev["verdict"]
    return time.perf_counter() - t, verdict, steps


def bench_e2e(runs: int) -> dict:
    out = {}
    for mode in ("healthy", "tampered", "vulnerable", "compromised"):
        samples, verdicts, last_steps = [], set(), {}
        for _ in range(runs):
            dt, verdict, steps = asyncio.run(_one_e2e(mode))
            samples.append(dt)
            verdicts.add(verdict)
            last_steps = steps
        out[mode] = {"verdict": sorted(verdicts), "wall": _stats(samples), "check_done_at_s": last_steps}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=1000, help="iterations per component")
    ap.add_argument("--e2e-runs", type=int, default=3, help="end-to-end runs per scenario")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    setup()
    import cryptography
    record = {
        "measured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": {"cpu": _cpu_name(), "machine": platform.machine(), "logical_cpus": os.cpu_count(),
                 "os": platform.platform(), "python": platform.python_version(),
                 "cryptography": cryptography.__version__},
        "method": "time.perf_counter around each call; warm-up 20 calls; single process, single thread",
        "components": bench_components(args.runs),
        "end_to_end": bench_e2e(args.e2e_runs),
        "simulated_delay_s": {"identity": 0.6, "integrity": 0.65, "weaknesses": 0.7, "behavior": 1.0,
                              "note": "fixed asyncio.sleep() calls in checks/*.py standing in for TPM and network I/O"},
    }
    out = args.out or ROOT / "benchmarks" / "results" / f"{platform.machine().lower()}-{sys.platform}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2))
    print(json.dumps({k: v["p50_ms"] for k, v in record["components"].items()}, indent=2))
    print({m: (r["verdict"], r["wall"]["p50_ms"]) for m, r in record["end_to_end"].items()})
    print(f"written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
