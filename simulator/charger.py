"""
C10 – Charger Simulator (v2 — fully configurable attack params)
Accepts granular attack configuration so the control panel
can compose arbitrary attack combinations.
"""
import sys
from pathlib import Path
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import DEVICE_ID, VENDOR, MODE_HEALTHY, MODE_TAMPERED, MODE_VULNERABLE, MODE_COMPROMISED
from firmware.generator import get_device_key, get_hash_for_mode

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_private_key,
)


# ── Attack config dataclass ───────────────────────────────────────────────

@dataclass
class AttackConfig:
    # Identity
    identity_attack: str = "legitimate"   # legitimate | unknown | clone
    # Firmware
    firmware_mode: str = "good"           # good | tampered | vulnerable
    # CVE injection (overrides firmware mode's CVE lookup)
    inject_cves: list = field(default_factory=list)
    # Behavior / traffic
    behavior_attack: str = "normal"       # normal | port_scan | c2 | dns_exfil | burst
    behavior_target: str = "192.168.1.254"
    behavior_rate: int = 50


