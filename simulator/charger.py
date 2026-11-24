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

    def get_firmware_info(self) -> dict:
        from db.database import lookup_firmware
        from config import KEYS_DIR
        from firmware.generator import _load_or_create

        mode = self.attack.firmware_mode

        if mode == "tampered":
            tampered_hash = get_hash_for_mode("tampered")
            # Provide the GOOD sig (won't verify against tampered hash)
            good_hash_bytes = bytes.fromhex(get_hash_for_mode(MODE_HEALTHY))
            vendor_key = _load_or_create(KEYS_DIR / "vendor_private.pem")
            good_sig = vendor_key.sign(good_hash_bytes)
            return {
                "hash":    tampered_hash,
                "version": "2.1.0",
                "vendor":  VENDOR,
                "sig_hex": good_sig.hex(),
            }

        elif mode == "vulnerable":
            vuln_hash = get_hash_for_mode("vulnerable")
            record = lookup_firmware(vuln_hash)
            sig_hex = record["sig_hex"] if record else "00" * 64
            return {
                "hash":    vuln_hash,
                "version": "1.8.3",
                "vendor":  VENDOR,
                "sig_hex": sig_hex,
            }

        else:  # good
            good_hash = get_hash_for_mode(MODE_HEALTHY)   # "healthy"
            record = lookup_firmware(good_hash)
            sig_hex = record["sig_hex"] if record else "00" * 64
            return {
                "hash":    good_hash,
                "version": "2.1.0",
                "vendor":  VENDOR,
                "sig_hex": sig_hex,
            }

    # ── CVE lookup override ───────────────────────────────────────────────

    def get_injected_cves(self) -> list:
        """
        Returns manually injected CVE records for supply-chain simulation.
        Each entry matches the cve_entries table schema.
        """
        all_cves = {
            "CVE-2022-0778": {
                "cve_id":      "CVE-2022-0778",
                "severity":    "HIGH",
                "cvss_score":  7.5,
                "component":   "openssl/1.1.1k",
                "description": "OpenSSL infinite loop in BN_mod_sqrt() — allows DoS via crafted certificate.",
                "fixed_in":    "openssl/1.1.1n",
                "firmware_hash": "injected",
            },
            "CVE-2021-28831": {
                "cve_id":      "CVE-2021-28831",
                "severity":    "HIGH",
                "cvss_score":  7.5,
                "component":   "busybox/1.33.0",
                "description": "BusyBox gunzip invalid free — arbitrary code execution via crafted archive.",
                "fixed_in":    "busybox/1.33.2",
                "firmware_hash": "injected",
            },
            "CVE-2022-37434": {
                "cve_id":      "CVE-2022-37434",
                "severity":    "CRITICAL",
                "cvss_score":  9.8,
                "component":   "zlib/1.2.11",
                "description": "zlib heap buffer overflow in inflate() — remote code execution via crafted input.",
                "fixed_in":    "zlib/1.2.13",
                "firmware_hash": "injected",
            },
        }
        return [all_cves[c] for c in self.attack.inject_cves if c in all_cves]

    # ── Traffic sample ────────────────────────────────────────────────────

    def get_traffic_sample(self) -> list:
        normal = [
            {"dst": "localhost", "port": 8080, "proto": "HEARTBEAT", "rate": 1},
            {"dst": "localhost", "port": 8080, "proto": "STATUS",    "rate": 1},
            {"dst": "localhost", "port": 8080, "proto": "METER",     "rate": 2},
            {"dst": "127.0.0.1", "port": 8080, "proto": "OCPP",      "rate": 1},
        ]

        atk = self.attack.behavior_attack
        tgt = self.attack.behavior_target
        rate = self.attack.behavior_rate

        if atk == "port_scan":
            return normal + [
                {"dst": tgt,        "port": 22,   "proto": "SSH",    "rate": rate},
                {"dst": tgt,        "port": 3389, "proto": "RDP",    "rate": rate},
                {"dst": tgt,        "port": 445,  "proto": "SMB",    "rate": rate},
                {"dst": tgt,        "port": 9999, "proto": "SCAN",   "rate": rate * 2},
            ]
        elif atk == "c2":
            return normal + [
                {"dst": tgt,        "port": 4444, "proto": "UNKNOWN", "rate": rate},
                {"dst": "attacker.local", "port": 8080, "proto": "HTTP", "rate": rate},
            ]
        elif atk == "dns_exfil":
            return normal + [
                {"dst": "8.8.8.8",  "port": 53,   "proto": "DNS",    "rate": rate},
                {"dst": "1.1.1.1",  "port": 53,   "proto": "DNS",    "rate": rate * 3},
            ]
        elif atk == "burst":
            return normal + [
                {"dst": "localhost", "port": 8080, "proto": "FLOOD",  "rate": rate},
                {"dst": "localhost", "port": 8080, "proto": "FLOOD",  "rate": rate},
                {"dst": "localhost", "port": 8080, "proto": "FLOOD",  "rate": rate},
            ]

        return normal
