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


