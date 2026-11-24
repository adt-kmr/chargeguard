"""
Demo scenarios and the runner that stages them.

A scenario launches the charger as its own OCPP process (charger.agent) with
the identity, firmware and OCPP-level behaviour under test, and runs the
network tap with the matching flow profile. Everything the dashboard shows is
then produced by the gateway observing those two sources.
"""
from __future__ import annotations

import asyncio
import logging
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from simlab.tap import Tap

ROOT = Path(__file__).resolve().parent.parent
IMAGES = ROOT / "firmware" / "images"
FIRMWARE = {"good": "good_v2.1.0.bin", "tampered": "tampered_v2.1.0.bin", "vulnerable": "vulnerable_v1.8.3.bin"}
log = logging.getLogger("simlab")


@dataclass
class Scenario:
    name: str = "custom"
    identity: str = "legitimate"        # legitimate | clone | unknown
    firmware: str = "good"              # good | tampered | vulnerable
    behaviour: str = "normal"           # normal | port_scan | c2 | dns_exfil | burst
    attack_timing: str = "plugin"       # plugin | mid_session
    attack_delay: float = 8.0           # seconds into charging, for mid_session
    target: str = "192.168.1.254"
    rate: int = 50
    session_seconds: float = 30.0
    payment_qr: str = "https://chargepoint.com/pay/CG-CHARGER-001"

    def to_dict(self) -> dict:
        return asdict(self)


PRESETS = {
    "healthy":     Scenario("healthy"),
    "tampered":    Scenario("tampered", firmware="tampered"),
    "vulnerable":  Scenario("vulnerable", firmware="vulnerable"),
    "compromised": Scenario("compromised", behaviour="port_scan", attack_timing="mid_session"),
    "clone":       Scenario("clone", identity="clone"),
    "rogue":       Scenario("rogue", identity="unknown"),
    "c2_beacon":   Scenario("c2_beacon", behaviour="c2"),
    "dns_exfil":   Scenario("dns_exfil", behaviour="dns_exfil"),
    "ocpp_flood":  Scenario("ocpp_flood", behaviour="burst"),
    "c2_mid_session": Scenario("c2_mid_session", behaviour="c2", attack_timing="mid_session"),
    "quishing":    Scenario("quishing", payment_qr="https://chargepoint-pay.top/verify?station=CG-001"),
}

# Verdict each scenario must produce (used by the headless runner and tests)
EXPECTED = {"healthy": "green", "tampered": "red", "vulnerable": "amber", "compromised": "red",
            "clone": "red", "rogue": "red", "c2_beacon": "red", "dns_exfil": "red", "ocpp_flood": "red",
            "c2_mid_session": "red", "quishing": "red"}


class ScenarioRunner:
    def __init__(self):
        self.proc: asyncio.subprocess.Process | None = None
        self.tap_task: asyncio.Task | None = None

    async def stop(self):
        if self.tap_task:
            self.tap_task.cancel()
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), 3)
            except asyncio.TimeoutError:
                self.proc.kill()

    async def start(self, sc: Scenario, on_log=None) -> None:
        await self.stop()
        ocpp_attack = {"burst": "burst", "c2": "c2"}.get(sc.behaviour, "none")
        tap_attack = sc.behaviour if sc.behaviour in ("port_scan", "c2", "dns_exfil") else "none"
        args = [sys.executable, "-m", "charger.agent", "--firmware", str(IMAGES / FIRMWARE[sc.firmware]),
                "--identity", sc.identity, "--attack", ocpp_attack, "--attack-at", sc.attack_timing,
                "--attack-delay", str(sc.attack_delay), "--attack-rate", str(min(sc.rate, 60)),
                "--session-seconds", str(sc.session_seconds), "--payment-qr", sc.payment_qr]
        self.proc = await asyncio.create_subprocess_exec(*args, cwd=str(ROOT),
                                                         stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.STDOUT)
        # Tap: in mid-session mode the network attack starts once charging is under way
        delay = 0.0 if sc.attack_timing == "plugin" else 5.5 + 0.5 + sc.attack_delay
        tap = Tap(tap_attack, sc.target, sc.rate, start_delay=delay)
        self.tap_task = asyncio.create_task(tap.run(sc.session_seconds + 15))
        asyncio.create_task(self._pump(on_log))

    async def _pump(self, on_log):
        assert self.proc and self.proc.stdout
        async for line in self.proc.stdout:
            text = line.decode(errors="replace").rstrip()
            log.info(text)
            if on_log:
                on_log(text)
