"""
tpm2-tss backend (via the tpm2-pytss bindings).

Talks to any TPM that tpm2-tss can reach through a TCTI:
  * IBM software TPM emulator   ->  "mssim:host=127.0.0.1,port=2321"
  * swtpm                       ->  "swtpm:port=2321"
  * Linux hardware TPM          ->  "device:/dev/tpmrm0"

Requirements (optional, not in requirements.txt):
  - tpm2-tss native libraries (vendor/tpm/tpm2-tss, or the distro package)
  - pip install tpm2-pytss

Status: experimental – written against the tpm2-pytss 2.x ESAPI and not yet
exercised in CI. Quotes are produced with a restricted ECC P-256 attestation
key under the endorsement hierarchy; signatures are returned DER-encoded so
the local verifier can check them with `cryptography` alone.
"""
from __future__ import annotations

import importlib.util

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ..base import AttestationError, BackendUnavailable, TPMBackend
from ..config import AttestationConfig
from ..formats import decode_tpms_attest
from ..registry import register_backend
from ..types import EndorsementKey, HashAlg, PCRSelection, PCRValues, Quote

_AK_TEMPLATE = "ecc256:ecdsa-sha256"
_AK_ATTRS = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign"


@register_backend("tpm2-tss")
class TSSBackend(TPMBackend):
    def __init__(self, config: AttestationConfig | None = None, tcti: str | None = None,
                 startup: bool = True):
        self.config = config or AttestationConfig()
        self.tcti = tcti or self.config.tcti
        self.startup = startup          # emulators need TPM2_Startup after power-on
        self._esys = None
        self._ak = None
        self._ak_public = None

    @classmethod
    def is_available(cls) -> bool:
        return importlib.util.find_spec("tpm2_pytss") is not None

    # ── lifecycle ─────────────────────────────────────────────────────────

    def open(self) -> None:
        if self._esys is not None:
            return
        try:
            from tpm2_pytss import ESAPI, TPM2_SU
        except ImportError as e:  # pragma: no cover - depends on host
            raise BackendUnavailable("tpm2-pytss is not installed") from e
        try:
            self._esys = ESAPI(self.tcti)
            if self.startup:
                try:
                    self._esys.startup(TPM2_SU.CLEAR)
                except Exception:
                    pass                # already started (hardware / long-running emulator)
        except Exception as e:
            raise AttestationError(f"cannot open TPM via TCTI '{self.tcti}': {e}") from e

    def close(self) -> None:
        if self._esys is None:
            return
        if self._ak is not None:
            try:
                self._esys.flush_context(self._ak)
            except Exception:
                pass
        self._esys.close()
        self._esys, self._ak, self._ak_public = None, None, None

    def _require(self):
        if self._esys is None:
            self.open()
        return self._esys

    def _attestation_key(self):
        if self._ak is None:
            from tpm2_pytss import ESYS_TR, TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE
            esys = self._require()
            in_public = TPM2B_PUBLIC.parse(_AK_TEMPLATE, objectAttributes=_AK_ATTRS)
            handle, out_public, *_ = esys.create_primary(TPM2B_SENSITIVE_CREATE(), in_public,
                                                         ESYS_TR.ENDORSEMENT)
            self._ak, self._ak_public = handle, out_public
        return self._ak

    # ── TPMBackend ────────────────────────────────────────────────────────

    def get_random(self, size: int) -> bytes:
        return bytes(self._require().get_random(size))

    def get_endorsement_key(self) -> EndorsementKey:
        self._attestation_key()
        point = self._ak_public.publicArea.unique.ecc
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(bytes(point.x), "big"),
                                            int.from_bytes(bytes(point.y), "big"),
                                            ec.SECP256R1()).public_key()
        der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return EndorsementKey(algorithm="ecc-p256", public_der=der)

    def read_pcrs(self, selection: PCRSelection) -> PCRValues:
        from tpm2_pytss import TPML_PCR_SELECTION
        _, _, digests = self._require().pcr_read(TPML_PCR_SELECTION.parse(selection.to_tss_string()))
        values = [bytes(d) for d in digests]
        return PCRValues(selection.bank, dict(zip(sorted(selection.indices), values)))

    def reset_pcr(self, index: int) -> None:
        from tpm2_pytss import ESYS_TR
        self._require().pcr_reset(ESYS_TR.parse(f"pcr{index}"))

    def extend_pcr(self, index: int, data: bytes, bank: HashAlg = HashAlg.SHA256) -> None:
        from tpm2_pytss import ESYS_TR, TPM2_ALG, TPML_DIGEST_VALUES, TPMT_HA
        from ..formats import hash_fn
        alg = {HashAlg.SHA1: TPM2_ALG.SHA1, HashAlg.SHA256: TPM2_ALG.SHA256,
               HashAlg.SHA384: TPM2_ALG.SHA384}[bank]
        digest = hash_fn(bank)(data).digest()
        ha = TPMT_HA(hashAlg=alg)
        getattr(ha.digest, bank.value)[:] = digest
        self._require().pcr_extend(ESYS_TR.parse(f"pcr{index}"), TPML_DIGEST_VALUES([ha]))

    def quote(self, nonce: bytes, selection: PCRSelection) -> Quote:
        from tpm2_pytss import TPM2B_DATA, TPML_PCR_SELECTION
        ak = self._attestation_key()
        quoted, signature = self._require().quote(
            ak, TPML_PCR_SELECTION.parse(selection.to_tss_string()), TPM2B_DATA(nonce))
        blob = bytes(quoted.marshal())[2:]            # strip TPM2B size -> TPMS_ATTEST
        ecdsa = signature.signature.ecdsa
        der_sig = encode_dss_signature(int.from_bytes(bytes(ecdsa.signatureR), "big"),
                                       int.from_bytes(bytes(ecdsa.signatureS), "big"))
        parsed = decode_tpms_attest(blob)
        return Quote(nonce=nonce, selection=selection, pcr_digest=parsed.pcr_digest,
                     attest_blob=blob, signature=der_sig,
                     signing_key=self.get_endorsement_key(), backend=self.name)
