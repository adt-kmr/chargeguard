"""
wolfTPM backend (embedded charger side).

wolfTPM targets microcontrollers that talk to a discrete TPM over SPI/I2C,
which is how a production EV charger controller would hold its identity.
The C sources live in third_party/tpm/wolftpm; there is no official Python
binding, so this backend is a placeholder that defines the integration
contract. Two intended integration routes:

  1. On-device: firmware built with wolfTPM exposes quotes over the charger
     link (e.g. an OCPP data-transfer message). A transport adapter here
     forwards ChargeGuard's nonce and parses the returned TPMS_ATTEST.
  2. Host-side: a small C shim (ctypes / cffi) over libwolftpm on a gateway.

Both return TPMS_ATTEST + ECDSA, which `attestation.verifiers.local`
already understands, so only the transport needs implementing.
"""
from __future__ import annotations

from ..base import BackendUnavailable, TPMBackend
from ..config import AttestationConfig
from ..registry import register_backend
from ..types import EndorsementKey, HashAlg, PCRSelection, PCRValues, Quote


@register_backend("wolftpm")
class WolfTPMBackend(TPMBackend):
    def __init__(self, config: AttestationConfig | None = None, transport=None):
        self.config = config or AttestationConfig()
        self.transport = transport

    @classmethod
    def is_available(cls) -> bool:
        return False                    # flips to True once a transport is implemented

    def _todo(self):
        raise BackendUnavailable("wolfTPM backend has no transport yet; see module docstring.")

    def get_random(self, size: int) -> bytes: self._todo()
    def get_endorsement_key(self) -> EndorsementKey: self._todo()
    def read_pcrs(self, selection: PCRSelection) -> PCRValues: self._todo()
    def extend_pcr(self, index: int, data: bytes, bank: HashAlg = HashAlg.SHA256) -> None: self._todo()
    def quote(self, nonce: bytes, selection: PCRSelection) -> Quote: self._todo()
