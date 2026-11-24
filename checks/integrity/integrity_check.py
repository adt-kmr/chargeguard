"""
C2 – Firmware Integrity
  1. Read firmware header from simulator (hash + vendor sig).
  2. Verify hash is in the registry (known-good).
  3. Verify vendor Ed25519 signature over that hash.
"""
import asyncio
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from db.database import lookup_firmware
from firmware.generator import get_vendor_pub_hex

VENDOR_PUB_HEX = None   # lazy-loaded once


def _get_vendor_pub() -> Ed25519PublicKey:
    global VENDOR_PUB_HEX
    if VENDOR_PUB_HEX is None:
        VENDOR_PUB_HEX = get_vendor_pub_hex()
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(VENDOR_PUB_HEX))


async def run(simulator) -> object:
    import time
    from checks.identity.identity_check import CheckResult
    t0 = time.monotonic()

    await asyncio.sleep(0.35)

    fw_info = simulator.get_firmware_info()
    fw_hash    = fw_info["hash"]
    sig_hex    = fw_info.get("sig_hex", "")
    version    = fw_info.get("version", "unknown")

    # Step 1 – hash registry lookup
    record = lookup_firmware(fw_hash)
    if not record:
        return CheckResult(
            "integrity", "fail",
            f"Firmware hash not in registry — image unrecognised or tampered. "
            f"Hash: {fw_hash[:12]}…",
            evidence={"hash": fw_hash[:20] + "…", "version": version},
            timing=time.monotonic() - t0,
        )

    await asyncio.sleep(0.3)

    # Step 2 – vendor signature verification
    try:
        pub_key = _get_vendor_pub()
        pub_key.verify(bytes.fromhex(sig_hex), bytes.fromhex(fw_hash))
    except (InvalidSignature, ValueError) as exc:
        return CheckResult(
            "integrity", "fail",
            f"Vendor signature INVALID — firmware modified after signing. ({exc})",
            evidence={"hash": fw_hash[:20] + "…", "version": version,
                      "sig": sig_hex[:16] + "…"},
            timing=time.monotonic() - t0,
        )

    return CheckResult(
        "integrity", "pass",
        f"Firmware v{version} authentic — hash verified and vendor signature valid.",
        evidence={
            "hash":    fw_hash[:20] + "…",
            "version": version,
            "vendor":  record.get("vendor"),
            "build_date": record.get("build_date"),
            "sig":     sig_hex[:16] + "…",
        },
        timing=time.monotonic() - t0,
    )
