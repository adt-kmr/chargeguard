"""Tests for the attestation layer (software backend + local/Keylime verifiers).

Run:  python -m pytest tests/  (or)  python tests/test_attestation.py
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attestation import (  # noqa: E402
    AttestationStatus, PCRSelection, available_backends, get_backend, get_verifier,
)
from attestation.formats import decode_tpms_attest  # noqa: E402

SEL = PCRSelection(indices=(0, 1, 7))


def _evidence():
    tpm = get_backend("software")
    tpm.extend_pcr(0, b"bootloader-v1")
    tpm.extend_pcr(7, b"secure-boot-policy")
    nonce = tpm.get_random(32)
    return tpm, nonce, tpm.collect_evidence("CG-CHARGER-001", nonce, SEL)


def test_registry_lists_backends():
    av = available_backends()
    assert av["software"] is True and av["wolftpm"] is False and "tpm2-tss" in av


def test_valid_quote_is_trusted():
    tpm, nonce, ev = _evidence()
    golden = {i: ev.pcrs.values[i] for i in SEL.indices}
    r = get_verifier("local").verify(ev, nonce, tpm.get_endorsement_key(), golden)
    assert r.status is AttestationStatus.TRUSTED, r.reason


def test_replayed_nonce_rejected():
    tpm, _, ev = _evidence()
    r = get_verifier("local").verify(ev, b"\x00" * 32, tpm.get_endorsement_key())
    assert r.status is AttestationStatus.UNTRUSTED and "Nonce" in r.reason


def test_unenrolled_key_rejected():
    _, nonce, ev = _evidence()
    other = get_backend("software").get_endorsement_key()
    r = get_verifier("local").verify(ev, nonce, other)
    assert r.status is AttestationStatus.UNTRUSTED


def test_tampered_pcrs_rejected():
    tpm, nonce, ev = _evidence()
    ev.pcrs.values[0] = b"\x11" * 32
    r = get_verifier("local").verify(ev, nonce, tpm.get_endorsement_key())
    assert r.status is AttestationStatus.UNTRUSTED and "digest" in r.reason


def test_golden_drift_rejected():
    tpm, nonce, ev = _evidence()
    r = get_verifier("local").verify(ev, nonce, tpm.get_endorsement_key(), {7: b"\x00" * 32})
    assert r.status is AttestationStatus.UNTRUSTED and r.details["pcrs"] == [7]


def test_tpms_attest_parser():
    nonce, digest = b"N" * 32, b"D" * 32
    blob = (struct.pack(">IH", 0xFF544347, 0x8018) + struct.pack(">H", 2) + b"QS"
            + struct.pack(">H", 32) + nonce + b"\x00" * 25
            + struct.pack(">I", 1) + struct.pack(">HB", 0x000B, 3) + bytes([0b10000011, 0, 0])
            + struct.pack(">H", 32) + digest)
    p = decode_tpms_attest(blob)
    assert p.nonce == nonce and p.pcr_digest == digest and p.indices == (0, 1, 7)


def test_keylime_states():
    _, nonce, ev = _evidence()
    ok = get_verifier("keylime", opener=lambda url: {"results": {"operational_state": 3}})
    bad = get_verifier("keylime", opener=lambda url: {"results": {"operational_state": 9}})
    assert ok.verify(ev, nonce).status is AttestationStatus.TRUSTED
    assert bad.verify(ev, nonce).status is AttestationStatus.UNTRUSTED


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok ", name)
