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


# ── Simulator ─────────────────────────────────────────────────────────────

class ChargerSimulator:
    def __init__(self):
        self.device_id = DEVICE_ID
        self.attack = AttackConfig()
        self._legit_key = get_device_key()

    def configure(self, cfg: AttackConfig) -> None:
        self.attack = cfg

    # Legacy compatibility: set_mode maps to AttackConfig presets
    def set_mode(self, mode: str) -> None:
        preset_map = {
            "healthy":     AttackConfig(),
            "tampered":    AttackConfig(firmware_mode="tampered"),
            "vulnerable":  AttackConfig(firmware_mode="vulnerable"),
            "compromised": AttackConfig(behavior_attack="port_scan"),
        }
        self.attack = preset_map.get(mode, AttackConfig())

    # ── Identity ──────────────────────────────────────────────────────────

    def sign_nonce(self, nonce: bytes) -> bytes:
        """
        legitimate → correct key (passes)
        clone      → different generated key (sig will fail registry check)
        unknown    → correct key but device_id will be unknown
        """
        if self.attack.identity_attack == "clone":
            # Use a fresh ephemeral key — signature won't match enrolled key
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K
            return K.generate().sign(nonce)
        return self._legit_key.sign(nonce)

    @property
    def effective_device_id(self) -> str:
        if self.attack.identity_attack == "unknown":
            return "ROGUE-CHARGER-999"
        return self.device_id

    # ── Firmware info ─────────────────────────────────────────────────────

