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


