"""
Encoding helpers shared by backends and verifiers.

Two quote formats are understood:
  * software  – ChargeGuard's own compact structure (prefix b"CGSWQ1")
  * TPMS_ATTEST – the real TPM 2.0 structure produced by TPM2_Quote
Parsing is pure Python so verifiers need no native TPM library.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from .types import HashAlg

SOFTWARE_MAGIC = b"CGSWQ1"
TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018

_TPM_ALG = {0x0004: HashAlg.SHA1, 0x000B: HashAlg.SHA256, 0x000C: HashAlg.SHA384}


def hash_fn(bank: HashAlg):
    return {HashAlg.SHA1: hashlib.sha1, HashAlg.SHA256: hashlib.sha256,
            HashAlg.SHA384: hashlib.sha384}[bank]


def pcr_composite_digest(values: dict[int, bytes], indices) -> bytes:
    """Digest over selected PCR values in ascending index order, as TPM2_Quote computes it.
    The digest uses the signing scheme's hash; ChargeGuard attestation keys are always
    ECDSA-SHA256, so this is SHA-256 whichever PCR bank is quoted."""
    h = hashlib.sha256()
    for i in sorted(indices):
        h.update(values[i])
    return h.digest()


@dataclass
class ParsedQuote:
    nonce: bytes
    pcr_digest: bytes
    bank: HashAlg | None
    indices: tuple[int, ...]


# ── Software format ───────────────────────────────────────────────────────

def encode_software_quote(nonce: bytes, bank: HashAlg, indices, pcr_digest: bytes) -> bytes:
    sel = ",".join(str(i) for i in sorted(indices)).encode()
    out = bytearray(SOFTWARE_MAGIC)
    for part in (nonce, bank.value.encode(), sel, pcr_digest):
        out += struct.pack(">H", len(part)) + part
    return bytes(out)


def decode_software_quote(blob: bytes) -> ParsedQuote:
    if not blob.startswith(SOFTWARE_MAGIC):
        raise ValueError("not a software quote")
    pos, parts = len(SOFTWARE_MAGIC), []
    for _ in range(4):
        (n,) = struct.unpack_from(">H", blob, pos)
        pos += 2
        parts.append(blob[pos:pos + n])
        pos += n
    nonce, bank, sel, digest = parts
    indices = tuple(int(x) for x in sel.decode().split(",") if x)
    return ParsedQuote(nonce, digest, HashAlg(bank.decode()), indices)


# ── TPM 2.0 TPMS_ATTEST ───────────────────────────────────────────────────

def decode_tpms_attest(blob: bytes) -> ParsedQuote:
    def tpm2b(pos):
        (n,) = struct.unpack_from(">H", blob, pos)
        return blob[pos + 2:pos + 2 + n], pos + 2 + n

    magic, st = struct.unpack_from(">IH", blob, 0)
    if magic != TPM_GENERATED_VALUE or st != TPM_ST_ATTEST_QUOTE:
        raise ValueError("not a TPM2 quote (bad magic/type)")
    pos = 6
    _signer, pos = tpm2b(pos)
    nonce, pos = tpm2b(pos)
    pos += 17 + 8                                  # TPMS_CLOCK_INFO + firmwareVersion
    (count,) = struct.unpack_from(">I", blob, pos)
    pos += 4
    bank, indices = None, []
    for _ in range(count):
        alg, size = struct.unpack_from(">HB", blob, pos)
        pos += 3
        bitmap = blob[pos:pos + size]
        pos += size
        bank = _TPM_ALG.get(alg, bank)
        indices += [byte_i * 8 + bit for byte_i, b in enumerate(bitmap) for bit in range(8) if b >> bit & 1]
    digest, pos = tpm2b(pos)
    return ParsedQuote(nonce, digest, bank, tuple(indices))


def decode_quote(blob: bytes) -> ParsedQuote:
    if blob.startswith(SOFTWARE_MAGIC):
        return decode_software_quote(blob)
    return decode_tpms_attest(blob)
