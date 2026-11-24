"""
C1 – Identity & Attestation
Simulates a TPM-backed challenge-response:
  1. Node generates a random nonce.
  2. Charger signs it with its device key (TPM mock).
  3. Node looks up the enrolled public key and verifies the signature.
"""
import os
import asyncio
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from db.database import lookup_identity


class CheckResult:
    def __init__(self, name, status, detail, evidence=None, timing=None):
        self.name     = name
        self.status   = status   # "pass" | "fail" | "warning"
        self.detail   = detail
        self.evidence = evidence or {}
        self.timing   = timing or 0.0

    def to_dict(self):
        return {
            "check":    self.name,
            "status":   self.status,
            "detail":   self.detail,
            "evidence": self.evidence,
            "timing":   round(self.timing, 3),
        }


async def run(simulator) -> CheckResult:
    """
    simulator must expose:
      .device_id  : str
      .sign_nonce(nonce: bytes) -> bytes   (returns Ed25519 signature)
    """
    import time
    t0 = time.monotonic()

    await asyncio.sleep(0.3)   # simulate attestation round-trip

    device_id = simulator.effective_device_id   # may be spoofed
    nonce     = os.urandom(32)

    # Charger signs the nonce (TPM operation)
    try:
        signature = simulator.sign_nonce(nonce)
    except Exception as exc:
        return CheckResult(
            "identity", "fail",
            f"Charger failed to sign nonce: {exc}",
            timing=time.monotonic() - t0,
        )

    await asyncio.sleep(0.3)

    # Look up enrolled public key
    record = lookup_identity(device_id)
    if not record:
        return CheckResult(
            "identity", "fail",
            f"Device '{device_id}' not in identity registry — unknown charger.",
            evidence={"device_id": device_id},
            timing=time.monotonic() - t0,
        )

    pub_bytes = bytes.fromhex(record["pub_key_hex"])
    pub_key   = Ed25519PublicKey.from_public_bytes(pub_bytes)

    try:
        pub_key.verify(signature, nonce)
    except InvalidSignature:
        return CheckResult(
            "identity", "fail",
            "Nonce signature invalid — device key mismatch or spoofed identity.",
            evidence={"device_id": device_id, "nonce_hex": nonce.hex()[:16] + "…"},
            timing=time.monotonic() - t0,
        )

    return CheckResult(
        "identity", "pass",
        f"Device '{device_id}' authenticated via TPM-backed Ed25519 attestation.",
        evidence={
            "device_id":    device_id,
            "charger_model": record.get("charger_model", "unknown"),
            "vendor":        record.get("vendor", "unknown"),
            "pub_key_hex":   record["pub_key_hex"][:16] + "…",
        },
        timing=time.monotonic() - t0,
    )
