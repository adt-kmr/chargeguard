"""
C3 – Vulnerability & Supply-Chain Audit
Implements the "audit once, verify fast" design:
  - Heavy scan runs in Audit mode (audit_pipeline.py) and stores results keyed by hash.
  - At plug-in time this check only does a SQLite lookup (~milliseconds).
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from db.database import lookup_cves


async def run(simulator, firmware_hash: str = None) -> object:
    import time
    from checks.identity.identity_check import CheckResult
    t0 = time.monotonic()

    await asyncio.sleep(0.4)

    if firmware_hash is None:
        fw_info       = simulator.get_firmware_info()
        firmware_hash = fw_info["hash"]

    # Support manually injected CVEs (supply-chain simulation)
    injected = simulator.get_injected_cves() if hasattr(simulator, "get_injected_cves") else []
    cves = injected if injected else lookup_cves(firmware_hash)
    await asyncio.sleep(0.3)

    if not cves:
        return CheckResult(
            "weaknesses", "pass",
            "No known CVEs found for this firmware version.",
            evidence={"firmware_hash": firmware_hash[:20] + "…", "cve_count": 0},
            timing=time.monotonic() - t0,
        )

    # Classify severity
    critical = [c for c in cves if c["severity"] == "CRITICAL"]
    high     = [c for c in cves if c["severity"] == "HIGH"]

    summary = (
        f"{len(cves)} CVE(s) found: "
        f"{len(critical)} CRITICAL, {len(high)} HIGH. "
        f"Firmware is authentic but vulnerable — upgrade recommended."
    )

    cve_list = [
        {
            "id":          c["cve_id"],
            "severity":    c["severity"],
            "cvss":        c["cvss_score"],
            "component":   c["component"],
            "description": c["description"],
            "fixed_in":    c["fixed_in"],
        }
        for c in cves
    ]

    status = "warning"   # authenticated but has CVEs → amber
    return CheckResult(
        "weaknesses", status, summary,
        evidence={
            "firmware_hash": firmware_hash[:20] + "…",
            "cve_count":     len(cves),
            "cves":          cve_list,
        },
        timing=time.monotonic() - t0,
    )
