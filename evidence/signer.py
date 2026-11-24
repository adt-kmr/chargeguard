"""
Ed25519 signing for the verdict file (Cosign-equivalent mock).
Signs a JSON payload with the vendor private key and returns
a detached signature hex string.
"""
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import KEYS_DIR


def _get_key():
    path = KEYS_DIR / "vendor_private.pem"
    if not path.exists():
        raise FileNotFoundError(
            "Vendor key not found — run setup first (python main.py)."
        )
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=None)


def sign_verdict(payload: dict) -> str:
    """Sign the JSON payload and return a hex signature string."""
    key   = _get_key()
    data  = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig   = key.sign(data)
    return sig.hex()


def verify_verdict(payload: dict, sig_hex: str) -> bool:
    """Verify a signed verdict payload. Returns True if valid."""
    try:
        key    = _get_key()
        pub    = key.public_key()
        data   = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        pub.verify(bytes.fromhex(sig_hex), data)
        return True
    except Exception:
        return False
