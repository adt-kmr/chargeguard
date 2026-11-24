"""
In-process verifier.

Appraises evidence from any backend (software quotes or real TPMS_ATTEST)
using only `cryptography`:
  1. quote signature is valid for the trusted attestation key
  2. quote nonce equals the nonce this verifier issued (freshness)
  3. PCR values supplied with the evidence hash to the quoted PCR digest
  4. PCR values match the golden (reference) measurements, if given
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..base import Verifier
from ..config import AttestationConfig
from ..formats import decode_quote, pcr_composite_digest
from ..registry import register_verifier
from ..types import AttestationEvidence, AttestationResult, AttestationStatus, EndorsementKey


@register_verifier("local")
class LocalVerifier(Verifier):
    def __init__(self, config: AttestationConfig | None = None):
        self.config = config or AttestationConfig()

    def _fail(self, reason: str, **details) -> AttestationResult:
        return AttestationResult(AttestationStatus.UNTRUSTED, reason, self.name, details)

    def verify(self, evidence: AttestationEvidence, expected_nonce: bytes,
               trusted_key: EndorsementKey | None = None,
               golden_pcrs: dict[int, bytes] | None = None) -> AttestationResult:
        q = evidence.quote
        key = trusted_key or q.signing_key
        details = {"key_pinned": trusted_key is not None}

        if trusted_key is not None and trusted_key.public_der != q.signing_key.public_der:
            return self._fail("Quote signed by an unenrolled key", **details)

        try:
            pub = serialization.load_der_public_key(key.public_der)
            pub.verify(q.signature, q.attest_blob, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError, TypeError) as e:
            return self._fail("Quote signature invalid", error=type(e).__name__, **details)

        try:
            parsed = decode_quote(q.attest_blob)
        except (ValueError, IndexError) as e:
            return self._fail("Malformed quote structure", error=str(e), **details)

        if parsed.nonce != expected_nonce:
            return self._fail("Nonce mismatch (stale or replayed quote)", **details)

        indices = parsed.indices or q.selection.indices
        missing = [i for i in indices if i not in evidence.pcrs.values]
        if missing:
            return self._fail("Evidence is missing quoted PCRs", missing=missing, **details)
        if pcr_composite_digest(evidence.pcrs.values, indices) != parsed.pcr_digest:
            return self._fail("Reported PCRs do not match the signed PCR digest", **details)

        if golden_pcrs:
            drift = sorted(i for i, v in golden_pcrs.items() if evidence.pcrs.values.get(i) != v)
            if drift:
                return self._fail("Measured state differs from golden values", pcrs=drift, **details)
            details["golden_checked"] = sorted(golden_pcrs)

        reason = "Quote verified" + ("" if trusted_key else " (key not pinned: identity unproven)")
        return AttestationResult(AttestationStatus.TRUSTED, reason, self.name, details)
