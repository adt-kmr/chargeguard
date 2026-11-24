"""
Abstract interfaces every attestation backend implements.

  TPMBackend  – the device / prover side (talks to a TPM: real, emulated or software)
  Verifier    – the appraiser side (checks evidence produced by a TPMBackend)
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from .types import (
    AttestationEvidence, AttestationResult, EndorsementKey,
    HashAlg, PCRSelection, PCRValues, Quote,
)


class AttestationError(RuntimeError):
    """Raised when a backend cannot complete a TPM operation."""


class BackendUnavailable(AttestationError):
    """Raised when a backend's native library, device or service is missing."""


class TPMBackend(ABC):
    """Prover side: produces identity, PCR values and quotes."""

    #: registry name, e.g. "software", "tpm2-tss"
    name: str = ""

    @classmethod
    def is_available(cls) -> bool:
        """Cheap check that the backend's dependencies are importable/present."""
        return True

    def open(self) -> None:
        """Acquire the TPM connection. Called automatically by the context manager."""

    def close(self) -> None:
        """Release the TPM connection."""

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    @abstractmethod
    def get_random(self, size: int) -> bytes: ...

    @abstractmethod
    def get_endorsement_key(self) -> EndorsementKey: ...

    @abstractmethod
    def read_pcrs(self, selection: PCRSelection) -> PCRValues: ...

    @abstractmethod
    def extend_pcr(self, index: int, data: bytes, bank: HashAlg = HashAlg.SHA256) -> None:
        """Hash `data` with `bank` and extend it into PCR `index` (measured boot style)."""

    @abstractmethod
    def quote(self, nonce: bytes, selection: PCRSelection) -> Quote: ...

    def collect_evidence(self, device_id: str, nonce: bytes,
                         selection: PCRSelection | None = None) -> AttestationEvidence:
        """Convenience: PCRs + quote in one call."""
        selection = selection or PCRSelection()
        return AttestationEvidence(
            device_id=device_id,
            quote=self.quote(nonce, selection),
            pcrs=self.read_pcrs(selection),
        )


class Verifier(ABC):
    """Appraiser side: decides whether evidence is trustworthy."""

    name: str = ""

    @abstractmethod
    def verify(self, evidence: AttestationEvidence, expected_nonce: bytes,
               trusted_key: EndorsementKey | None = None,
               golden_pcrs: dict[int, bytes] | None = None) -> AttestationResult: ...
