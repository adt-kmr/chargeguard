"""
Run demo scenarios end to end without the dashboard and print what the
gateway decided. Useful for rehearsal, CI and regression checks.

    python -m simlab.run_headless                       # all presets
    python -m simlab.run_headless healthy compromised   # selected presets
    python -m simlab.run_headless --json results.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from firmware.provision import provision  # noqa: E402
from gateway.csms import Gateway  # noqa: E402
from simlab.scenarios import EXPECTED, PRESETS, ScenarioRunner  # noqa: E402


async def run_one(gw: Gateway, runner: ScenarioRunner, name: str, verbose: bool) -> dict:
    sc = PRESETS[name]
    sc.session_seconds = 24.0 if sc.attack_timing == "mid_session" else 10.0
    session = gw.open_session(str(uuid.uuid4()), sc.to_dict())
    q = session.bus.subscribe()
    charger_log: list[str] = []
    await runner.start(sc, on_log=charger_log.append)
    out = {"scenario": name, "verdicts": [], "checks": {}, "enforcement": None, "report": None,
           "ocpp_frames": 0, "flows": 0, "session": {}}
    deadline = asyncio.get_running_loop().time() + sc.session_seconds + 20
    while asyncio.get_running_loop().time() < deadline:
        try:
            ev = await asyncio.wait_for(q.get(), timeout=1.0)
        except asyncio.TimeoutError:
            if runner.proc and runner.proc.returncode is not None and out["report"]:
                break
            continue
        e = ev["event"]
        if verbose and e not in ("traffic", "ocpp", "session", "monitor"):
            print(f"  {ev['t']:6.2f}s {e}: {json.dumps({k: v for k, v in ev.items() if k not in ('event', 't', 'results', 'evidence', 'artifacts')})[:160]}")
        if e == "check_done":
            out["checks"][ev["check"]] = {"status": ev["status"], "detail": ev["detail"], "compute_ms": ev["compute_ms"]}
        elif e == "verdict":
            out["verdicts"].append({"verdict": ev["verdict"], "t": ev["t"], "mid_session": ev.get("mid_session", False)})
        elif e == "enforcement":
            out["enforcement"] = {k: ev.get(k) for k in ("action", "when", "steps")}
        elif e == "report_ready":
            out["report"] = ev["download"]
        elif e == "advisory":
            out["advisory_engine"] = ev["engine"]
    await runner.stop()
    out["ocpp_frames"] = len(session.transcript)
    out["flows"] = len(session.flows)
    out["session"] = {k: session.charging.get(k) for k in ("state", "energy_kwh", "stop_reason")}
    out["final_verdict"] = out["verdicts"][-1]["verdict"] if out["verdicts"] else None
    out["expected"] = EXPECTED[name]
    out["pass"] = out["final_verdict"] == EXPECTED[name]
    out["charger_exit"] = runner.proc.returncode if runner.proc else None
    return out


async def main(names: list[str], verbose: bool, json_out: str | None) -> int:
    provision()
    gw = Gateway()
    await gw.start()
    runner = ScenarioRunner()
    results = []
    try:
        for n in names:
            print(f"\n=== {n} ===")
            r = await run_one(gw, runner, n, verbose)
            results.append(r)
            mid = " (mid-session)" if any(v["mid_session"] for v in r["verdicts"]) else ""
            print(f"  -> {r['final_verdict']}{mid}  expected {r['expected']}  {'PASS' if r['pass'] else 'FAIL'}"
                  f" | frames {r['ocpp_frames']} flows {r['flows']} | enforcement "
                  f"{(r['enforcement'] or {}).get('action')} | session {r['session']}")
    finally:
        await runner.stop()
        await gw.stop()
    if json_out:
        Path(json_out).write_text(json.dumps(results, indent=2))
    return 0 if all(r["pass"] for r in results) else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("scenarios", nargs="*", default=list(PRESETS))
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args()
    logging.basicConfig(level=logging.WARNING)
    sys.exit(asyncio.run(main(a.scenarios, a.verbose, a.json)))
