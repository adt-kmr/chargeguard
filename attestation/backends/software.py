"""
Pure-Python software TPM.

Models the parts of a TPM 2.0 that attestation needs (PCR banks, extend,
an ECC P-256 attestation key, signed quotes) with no native dependencies.
Use it for development, tests and the demo; swap to the tpm2-tss backend
against the IBM emulator or real hardware without changing callers.
"""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..base import TPMBackend
from ..config import AttestationConfig
from ..formats import encode_software_quote, hash_fn, pcr_composite_digest
from ..registry import register_backend
from ..types import EndorsementKey, HashAlg, PCRSelection, PCRValues, Quote

NUM_PCRS = 24


@register_backend("software")
class SoftwareTPM(TPMBackend):
    def __init__(self, config: AttestationConfig | None = None, key_path: str | Path | None = None):
        self.config = config or AttestationConfig()
        self._key = self._load_or_create_key(Path(key_path)) if key_path else ec.generate_private_key(ec.SECP256R1())
        self._banks: dict[HashAlg, list[bytes]] = {
            bank: [b"\x00" * hash_fn(bank)().digest_size for _ in range(NUM_PCRS)] for bank in HashAlg
        }

    @staticmethod
    def _load_or_create_key(path: Path) -> ec.EllipticCurvePrivateKey:
        if path.exists():
            return serialization.load_pem_private_key(path.read_bytes(), password=None)
        key = ec.generate_private_key(ec.SECP256R1())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        return key

    # ── TPMBackend ────────────────────────────────────────────────────────

    def get_random(self, size: int) -> bytes:
        return os.urandom(size)

    def get_endorsement_key(self) -> EndorsementKey:
        der = self._key.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
        return EndorsementKey(algorithm="ecc-p256", public_der=der)

    def read_pcrs(self, selection: PCRSelection) -> PCRValues:
        bank = self._banks[selection.bank]
        return PCRValues(selection.bank, {i: bank[i] for i in selection.indices})

    def reset_pcr(self, index: int) -> None:
        if index not in (16, 23):
            raise ValueError(f"PCR {index} is not resettable")
        for bank in self._banks:
            self._banks[bank][index] = bytes(len(self._banks[bank][index]))

    def extend_pcr(self, index: int, data: bytes, bank: HashAlg = HashAlg.SHA256) -> None:
        if not 0 <= index < NUM_PCRS:
            raise ValueError(f"PCR index out of range: {index}")
        h = hash_fn(bank)
        self._banks[bank][index] = h(self._banks[bank][index] + h(data).digest()).digest()

    def quote(self, nonce: bytes, selection: PCRSelection) -> Quote:
        pcrs = self.read_pcrs(selection).values
        digest = pcr_composite_digest(pcrs, selection.indices)
        blob = encode_software_quote(nonce, selection.bank, selection.indices, digest)
        sig = self._key.sign(blob, ec.ECDSA(hashes.SHA256()))
        return Quote(nonce=nonce, selection=selection, pcr_digest=digest, attest_blob=blob,
                     signature=sig, signing_key=self.get_endorsement_key(), backend=self.name)
