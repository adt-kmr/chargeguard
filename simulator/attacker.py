"""
C9 – Attack & Test Harness
Provides utility functions used by the demo to trigger attack scenarios.
In a full deployment this would drive real tools (Marauder, Facedancer, etc.).
Here it configures the simulator to present the chosen attack posture.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import MODE_HEALTHY, MODE_TAMPERED, MODE_VULNERABLE, MODE_COMPROMISED


ATTACK_DESCRIPTIONS = {
    MODE_HEALTHY: (
        "Scenario 1 — HEALTHY CHARGER\n"
        "Genuine device, authentic firmware v2.1.0, no CVEs, normal traffic.\n"
        "Expected: GREEN verdict in ~5 seconds."
    ),
    MODE_TAMPERED: (
        "Scenario 2 — TAMPERED FIRMWARE\n"
        "Firmware payload bit-flipped after vendor signing.\n"
        "Integrity check detects hash/signature mismatch.\n"
        "Expected: RED at step 2 (Integrity)."
    ),
    MODE_VULNERABLE: (
        "Scenario 3 — SIGNED BUT VULNERABLE\n"
        "Charger running authentic but outdated firmware v1.8.3.\n"
        "Contains CVE-2022-0778 (OpenSSL), CVE-2021-28831 (BusyBox), "
        "CVE-2022-37434 (zlib/CRITICAL).\n"
        "Expected: AMBER verdict — authentic but risky."
    ),
    MODE_COMPROMISED: (
        "Scenario 4 — LIVE COMPROMISE\n"
        "Firmware is authentic, but charger is scanning the LAN and "
        "contacting unknown external hosts (port 4444, 22, 8888).\n"
        "Expected: GREEN → RED mid-session. Session isolated."
    ),
}


def describe(mode: str) -> str:
    return ATTACK_DESCRIPTIONS.get(mode, f"Unknown mode: {mode}")


def get_all_scenarios() -> list:
    return [
        {"mode": m, "description": ATTACK_DESCRIPTIONS[m]}
        for m in [MODE_HEALTHY, MODE_TAMPERED, MODE_VULNERABLE, MODE_COMPROMISED]
    ]
