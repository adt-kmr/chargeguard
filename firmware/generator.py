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
from config import FIRMWARE_DIR, KEYS_DIR, DEVICE_ID, VENDOR, CHARGER_MODEL

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


# Component banners compiled into each build, exactly as the upstream
# projects embed them. The audit (audit/lite_audit.py) finds these.
COMPONENTS = {
    "good-2.1.0": [
        b"OpenSSL 3.0.18 30 Sep 2025\x00",
        b" inflate 1.3.1 Copyright 1995-2024 Mark Adler \x00",
        b"BusyBox v1.37.0 (2024-11-01 00:00:00 UTC) multi-call binary.\x00",
    ],
    "vuln-1.8.3": [
        b"OpenSSL 1.1.1k  25 Mar 2021\x00",
        b" inflate 1.2.11 Copyright 1995-2017 Mark Adler \x00",
        b"BusyBox v1.33.0 (2023-01-15 00:00:00 UTC) multi-call binary.\x00",
    ],
}


def _make_payload(seed: str, size: int = 8192, tamper: bool = False) -> bytes:
    rng = random.Random(seed)
    data = bytearray(rng.randint(0, 255) for _ in range(size))
    offset = 1024
    for banner in COMPONENTS.get(seed, []):
        data[offset:offset + len(banner)] = banner
        offset += len(banner) + 512
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

    # Known weaknesses come from auditing the images themselves (audit once)
    from audit.lite_audit import audit_bytes
    for payload, digest in ((payload_good, hash_good_hex), (payload_vuln, hash_vuln_hex)):
        for cve in audit_bytes(payload)["cves"]:
            cve_rows.append({"firmware_hash": digest, **cve})

    identity_rows = [{
        "device_id": DEVICE_ID,
        "pub_key_hex": device_pub_hex,
        "enrolled_at": "2024-10-01T00:00:00",
        "charger_model": CHARGER_MODEL,
        "vendor": VENDOR,
    }]

    return firmware_rows, cve_rows, identity_rows


def get_vendor_pub_hex() -> str:
    key = _load_or_create(KEYS_DIR / "vendor_private.pem")
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def get_device_key() -> Ed25519PrivateKey:
    return _load_or_create(KEYS_DIR / f"{DEVICE_ID}_private.pem")


def get_hash_for_mode(mode: str) -> str:
    """Return the firmware hash the simulator reports for a given mode."""
    if mode in ("healthy", "compromised"):
        payload = _make_payload("good-2.1.0", tamper=False)
    elif mode == "tampered":
        payload = _make_payload("good-2.1.0", tamper=True)
    else:  # vulnerable
        payload = _make_payload("vuln-1.8.3", tamper=False)
    return hashlib.sha256(payload).hexdigest()


# ── Attestation enrolment (measured boot) ────────────────────────────────

def measure_image(image: bytes) -> str:
    """PCR0 after the charger's boot ROM extends the full firmware image into it."""
    pcr0 = hashlib.sha256(b"\x00" * 32 + hashlib.sha256(image).digest()).digest()
    return pcr0.hex()


def attestation_key_path(device_id: str = DEVICE_ID) -> Path:
    return KEYS_DIR / f"{device_id}_ak.pem"


def generate_attestation_enrollment() -> tuple[list, list]:
    """
    Enrol the charger's TPM attestation key and record the golden PCR0 value of
    every vendor-registered image.

    Returns:
        ak_rows           – rows for attestation_registry (device_id, AK public key)
        measurement_rows  – rows for firmware_measurements (payload hash, golden PCR0)
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    path = attestation_key_path()
    if path.exists():
        ak = load_pem_private_key(path.read_bytes(), password=None)
    else:
        ak = ec.generate_private_key(ec.SECP256R1())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(ak.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    ak_der = ak.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    ak_rows = [{"device_id": DEVICE_ID, "ak_pub_der_hex": ak_der.hex(), "ak_algorithm": "ecc-p256"}]

    measurement_rows = []
    for name in ("good_v2.1.0.bin", "vulnerable_v1.8.3.bin"):
        image = (FIRMWARE_DIR / name).read_bytes()
        payload_hash = image[68:100].hex()
        measurement_rows.append({"firmware_hash": payload_hash, "image_name": name,
                                 "golden_pcr0": measure_image(image)})
    return ak_rows, measurement_rows
