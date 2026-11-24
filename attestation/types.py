"""
Backend-neutral data types for TPM attestation.

Every backend (software, tpm2-tss, wolfTPM, Keylime) exchanges these
types so callers never depend on a specific TPM stack.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class HashAlg(str, Enum):
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA384 = "sha384"


@dataclass(frozen=True)
class PCRSelection:
    """Which PCRs to read or quote, in one hash bank."""
    bank: HashAlg = HashAlg.SHA256
    indices: tuple[int, ...] = (0, 1, 2, 3, 4, 5, 6, 7)

    def to_tss_string(self) -> str:
        """Format used by tpm2-tools / tpm2-pytss, e.g. 'sha256:0,1,2'."""
        return f"{self.bank.value}:{','.join(str(i) for i in self.indices)}"


@dataclass
class PCRValues:
    bank: HashAlg
    values: dict[int, bytes]          # pcr index -> digest

    def to_dict(self) -> dict[str, Any]:
        return {"bank": self.bank.value,
                "values": {str(k): v.hex() for k, v in sorted(self.values.items())}}


@dataclass
class EndorsementKey:
    """Public part of the device identity key (EK or AK)."""
    algorithm: str                    # e.g. "ecc-p256", "rsa2048", "ed25519"
    public_der: bytes
    certificate_der: bytes | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"algorithm": self.algorithm,
                "public_der": self.public_der.hex(),
                "certificate_der": self.certificate_der.hex() if self.certificate_der else None}


@dataclass
class Quote:
    """A signed statement of PCR state bound to a verifier nonce."""
    nonce: bytes
    selection: PCRSelection
    pcr_digest: bytes                 # hash over the selected PCR values
    attest_blob: bytes                # raw signed structure (TPMS_ATTEST or software equivalent)
    signature: bytes
    signing_key: EndorsementKey
    backend: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "nonce": self.nonce.hex(),
            "selection": self.selection.to_tss_string(),
            "pcr_digest": self.pcr_digest.hex(),
            "attest_blob": self.attest_blob.hex(),
            "signature": self.signature.hex(),
            "signing_key": self.signing_key.to_dict(),
        }


@dataclass
class AttestationEvidence:
    """Everything a verifier needs to appraise one device."""
    device_id: str
    quote: Quote
    pcrs: PCRValues
    event_log: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"device_id": self.device_id,
                "quote": self.quote.to_dict(),
                "pcrs": self.pcrs.to_dict(),
                "event_log": self.event_log.hex() if self.event_log else None,
                "metadata": self.metadata}


class AttestationStatus(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"               # verifier could not decide (e.g. unreachable)


@dataclass
class AttestationResult:
    status: AttestationStatus
    reason: str
    verifier: str
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def trusted(self) -> bool:
        return self.status is AttestationStatus.TRUSTED

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d
