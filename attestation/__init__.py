"""
ChargeGuard attestation layer.

A backend-neutral API over TPM 2.0 attestation. Callers depend only on
the interfaces here; the concrete TPM stack is chosen by name or by the
CHARGEGUARD_TPM_BACKEND environment variable.

    from attestation import get_backend, get_verifier, PCRSelection

    with get_backend("software") as tpm:
        nonce = tpm.get_random(32)
        evidence = tpm.collect_evidence("CG-CHARGER-001", nonce)
        ak = tpm.get_endorsement_key()

    result = get_verifier("local").verify(evidence, nonce, trusted_key=ak)

Backends:  software (built in) · tpm2-tss (needs tpm2-pytss) · wolftpm (contract only)
Verifiers: local (in-process) · keylime (REST client)

Not yet wired into the dashboard or checks/ – see attestation/README.md.
"""
from . import backends as _backends  # noqa: F401  (registers backends)
from . import verifiers as _verifiers  # noqa: F401  (registers verifiers)
from .base import AttestationError, BackendUnavailable, TPMBackend, Verifier
from .config import AttestationConfig
from .emulator import TPMEmulator
from .registry import (
    available_backends, available_verifiers, get_backend, get_verifier,
    register_backend, register_verifier,
)
from .types import (
    AttestationEvidence, AttestationResult, AttestationStatus, EndorsementKey,
    HashAlg, PCRSelection, PCRValues, Quote,
)

__all__ = [
    "AttestationConfig", "AttestationError", "AttestationEvidence", "AttestationResult",
    "AttestationStatus", "BackendUnavailable", "EndorsementKey", "HashAlg", "PCRSelection",
    "PCRValues", "Quote", "TPMBackend", "TPMEmulator", "Verifier",
    "available_backends", "available_verifiers", "get_backend", "get_verifier",
    "register_backend", "register_verifier",
]
