"""End-to-end tests: a real charger process speaking OCPP 1.6 to the live gateway.

Each scenario launches charger.agent as a subprocess plus the network tap, and
checks the verdict the gateway reaches and that its signed report verifies.
Takes about a minute. The gateway binds ports 9000/tcp and 9100/udp, so stop a
running dashboard before running these.

Run:  python -m pytest tests/test_live_gateway.py -q
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evidence.report_generator import verify_report  # noqa: E402
from simlab import run_headless  # noqa: E402
from simlab.scenarios import ScenarioRunner  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


async def _run(names):
    from firmware.provision import provision
    from gateway.csms import Gateway
    provision()
    gw = Gateway()
    await gw.start()
    runner = ScenarioRunner()
    try:
        return [await run_headless.run_one(gw, runner, n, verbose=False) for n in names]
    finally:
        await runner.stop()
        await gw.stop()


@pytest.fixture(scope="module")
def results():
    return {r["scenario"]: r for r in asyncio.run(_run(["healthy", "tampered", "vulnerable", "clone", "compromised"]))}


@pytest.mark.parametrize("name", ["healthy", "tampered", "vulnerable", "clone", "compromised"])
def test_verdict_matches_expectation(results, name):
    r = results[name]
    assert r["final_verdict"] == r["expected"], r


def test_healthy_charges_and_others_are_refused(results):
    assert results["healthy"]["session"]["energy_kwh"] > 0
    assert results["tampered"]["session"]["energy_kwh"] == 0
    assert results["clone"]["checks"]["identity"]["status"] == "fail"


def test_mid_session_compromise_is_isolated(results):
    r = results["compromised"]
    assert [v["verdict"] for v in r["verdicts"]] == ["green", "red"]
    assert r["verdicts"][-1]["mid_session"]
    assert r["enforcement"]["action"] == "isolate"
    assert r["session"]["stop_reason"] == "Remote"


@pytest.mark.parametrize("name", ["healthy", "compromised"])
def test_reports_are_signed_and_intact(results, name):
    sid = results[name]["report"].rsplit("/", 1)[-1]
    report = json.loads((ROOT / "evidence" / "reports" / f"{sid}.json").read_text(encoding="utf-8"))
    ok, detail = verify_report(report)
    assert ok, detail
