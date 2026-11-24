"""
Generates three firmware images and returns seed data for the DB:
  good_v2.1.0.bin       – authentic, signed, 0 CVEs
  tampered_v2.1.0.bin   – payload bit-flipped; original sig present (mismatch)
  vulnerable_v1.8.3.bin – authentic, signed, 3 CVEs
"""
import hashlib
import random
import sys
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_pem_private_key,
)

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import FIRMWARE_DIR, KEYS_DIR, DEVICE_ID, VENDOR

MAGIC = b"CGFW"
HEADER_SIZE = 256
SIG_OFFSET = 4 + 16 + 32 + 16 + 32   # magic + version + device_id + vendor + hash


def _load_or_create(path: Path, is_private=True):
    if path.exists():
        with open(path, "rb") as f:
            return load_pem_private_key(f.read(), password=None) if is_private else f.read()
    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    pub_path = path.with_suffix(".pub.pem")
    with open(pub_path, "wb") as f:
        f.write(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    return key


def _build_header(version: str, device_id: str, vendor: str,
                  payload_hash: bytes, sig: bytes, timestamp: int) -> bytes:
    hdr = bytearray(HEADER_SIZE)
    hdr[0:4]   = MAGIC
    hdr[4:20]  = version.encode().ljust(16, b"\x00")[:16]
    hdr[20:52] = device_id.encode().ljust(32, b"\x00")[:32]
    hdr[52:68] = vendor.encode().ljust(16, b"\x00")[:16]
    hdr[68:100] = payload_hash
    hdr[SIG_OFFSET:SIG_OFFSET+64] = sig
    hdr[164:172] = timestamp.to_bytes(8, "little")
    hdr[172:176] = (1).to_bytes(4, "little")  # flags: signed
    return bytes(hdr)


def _make_payload(seed: str, size: int = 8192, tamper: bool = False) -> bytes:
    rng = random.Random(seed)
    data = bytearray(rng.randint(0, 255) for _ in range(size))
    if tamper:
        data[42]  ^= 0xFF
        data[100] ^= 0xAA
        data[200] ^= 0x55
    return bytes(data)


def generate_all() -> tuple[list, list, list]:
    """
    Returns:
        firmware_rows  – list of dicts for firmware_registry
        cve_rows       – list of dicts for cve_entries
        identity_rows  – list of dicts for identity_registry
    """
    FIRMWARE_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    vendor_key   = _load_or_create(KEYS_DIR / "vendor_private.pem")
    device_key   = _load_or_create(KEYS_DIR / f"{DEVICE_ID}_private.pem")

    vendor_pub_hex = vendor_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw).hex()
    device_pub_hex = device_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw).hex()

    ts = int(datetime(2024, 11, 1).timestamp())
    firmware_rows = []
    cve_rows      = []

    # ── 1. Good firmware v2.1.0 ───────────────────────────────────────────
    payload_good = _make_payload("good-2.1.0", tamper=False)
    hash_good    = hashlib.sha256(payload_good).digest()
    hash_good_hex = hash_good.hex()
    sig_good     = vendor_key.sign(hash_good)

    hdr_good = _build_header("2.1.0", DEVICE_ID, VENDOR, hash_good, sig_good, ts)
    (FIRMWARE_DIR / "good_v2.1.0.bin").write_bytes(hdr_good + payload_good)

    firmware_rows.append({
        "hash": hash_good_hex, "device_id": DEVICE_ID, "version": "2.1.0",
        "vendor": VENDOR, "build_date": "2024-11-01T00:00:00",
        "is_signed": 1, "is_authentic": 1,
        "pub_key_hex": vendor_pub_hex, "sig_hex": sig_good.hex(),
    })

    # ── 2. Tampered v2.1.0 (bit-flipped payload, original sig → mismatch) ─
    payload_tamper = _make_payload("good-2.1.0", tamper=True)
    hash_tamper    = hashlib.sha256(payload_tamper).digest()
    hash_tamper_hex = hash_tamper.hex()

    # Reuse the GOOD header bytes but write tampered payload
    hdr_tamper = _build_header("2.1.0", DEVICE_ID, VENDOR,
                               hash_tamper, sig_good, ts)   # sig won't verify
    (FIRMWARE_DIR / "tampered_v2.1.0.bin").write_bytes(hdr_tamper + payload_tamper)

    # NOTE: tampered hash is NOT inserted into firmware_registry on purpose
    # (lookup will return None → integrity fail)

    # ── 3. Vulnerable but authentic v1.8.3 ───────────────────────────────
    ts_old = int(datetime(2023, 1, 15).timestamp())
    payload_vuln = _make_payload("vuln-1.8.3", tamper=False)
    hash_vuln    = hashlib.sha256(payload_vuln).digest()
    hash_vuln_hex = hash_vuln.hex()
    sig_vuln     = vendor_key.sign(hash_vuln)

    hdr_vuln = _build_header("1.8.3", DEVICE_ID, VENDOR, hash_vuln, sig_vuln, ts_old)
    (FIRMWARE_DIR / "vulnerable_v1.8.3.bin").write_bytes(hdr_vuln + payload_vuln)

    firmware_rows.append({
        "hash": hash_vuln_hex, "device_id": DEVICE_ID, "version": "1.8.3",
        "vendor": VENDOR, "build_date": "2023-01-15T00:00:00",
        "is_signed": 1, "is_authentic": 1,
        "pub_key_hex": vendor_pub_hex, "sig_hex": sig_vuln.hex(),
    })

    cve_rows += [
        {
            "firmware_hash": hash_vuln_hex,
            "cve_id": "CVE-2022-0778",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "component": "openssl/1.1.1k",
            "description": "OpenSSL infinite loop in BN_mod_sqrt() — allows DoS via crafted certificate.",
            "fixed_in": "openssl/1.1.1n",
        },
        {
            "firmware_hash": hash_vuln_hex,
            "cve_id": "CVE-2021-28831",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "component": "busybox/1.33.0",
            "description": "BusyBox gunzip invalid free — arbitrary code execution via crafted archive.",
            "fixed_in": "busybox/1.33.2",
        },
        {
            "firmware_hash": hash_vuln_hex,
            "cve_id": "CVE-2022-37434",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "component": "zlib/1.2.11",
            "description": "zlib heap buffer overflow in inflate() — remote code execution via crafted input.",
            "fixed_in": "zlib/1.2.13",
        },
    ]

    identity_rows = [{
        "device_id": DEVICE_ID,
        "pub_key_hex": device_pub_hex,
        "enrolled_at": "2024-10-01T00:00:00",
        "charger_model": "ChargeCo AC-7 Pro",
        "vendor": VENDOR,
    }]

    return firmware_rows, cve_rows, identity_rows

