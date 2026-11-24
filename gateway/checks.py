"""
Live C1–C4 checks, run by the gateway against the real charger connection.

Inputs are what the node actually observed: the charger's attestation
response (nonce signature, TPM quote, firmware metadata), the inline OCPP
transcript and the flow records from the tap. Each check returns the same
CheckResult type the report generator and trust engine already use.
"""
from __future__ import annotations

import hashlib
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from attestation import (
    AttestationEvidence, AttestationStatus, EndorsementKey, HashAlg, PCRSelection, PCRValues, Quote,
    get_verifier,
)
from checks.identity.identity_check import CheckResult
from db.database import (
    lookup_attestation_key, lookup_cves, lookup_firmware, lookup_golden_pcr0, lookup_identity,
)
from firmware.generator import get_vendor_pub_hex
from integrations.behavior import Baseline

_BASELINE = Baseline.load()


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 3)


def _evidence_from_response(resp: dict) -> AttestationEvidence:
    q, p = resp["quote"], resp["pcrs"]
    sel_bank, sel_idx = q["selection"].split(":")
    selection = PCRSelection(HashAlg(sel_bank), tuple(int(i) for i in sel_idx.split(",") if i))
    key = q["signing_key"]
    quote = Quote(nonce=bytes.fromhex(q["nonce"]), selection=selection,
                  pcr_digest=bytes.fromhex(q["pcr_digest"]), attest_blob=bytes.fromhex(q["attest_blob"]),
                  signature=bytes.fromhex(q["signature"]),
                  signing_key=EndorsementKey(key["algorithm"], bytes.fromhex(key["public_der"])),
                  backend=q["backend"])
    pcrs = PCRValues(HashAlg(p["bank"]), {int(k): bytes.fromhex(v) for k, v in p["values"].items()})
    return AttestationEvidence(resp["device_id"], quote, pcrs)


def check_identity(connected_id: str, nonce: bytes, resp: dict | None, rtt_ms: float) -> CheckResult:
    t0 = time.perf_counter()
    ev = {"device_id": connected_id, "nonce": nonce.hex()[:16] + "…", "attestation_rtt_ms": rtt_ms}
    if resp is None:
        return CheckResult("identity", "fail", "Charger did not answer the attestation request.", ev)
    record = lookup_identity(connected_id)
    if record is None:
        return CheckResult("identity", "fail",
                           f"Device '{connected_id}' is not enrolled — unknown or rogue charger.", ev)
    ev.update(charger_model=record.get("charger_model"), vendor=record.get("vendor"))
    if resp.get("device_id") != connected_id:
        return CheckResult("identity", "fail", "Attestation answered for a different device ID.", ev)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(record["pub_key_hex"])).verify(
            bytes.fromhex(resp["nonce_signature"]), nonce)
        ev["device_key"] = "Ed25519 signature over nonce verified"
    except (InvalidSignature, ValueError):
        ev["device_key"] = "signature does not match the enrolled device key"
        return CheckResult("identity", "fail",
                           "Nonce signature does not match the enrolled device key — cloned or spoofed charger.", ev)
    ak = lookup_attestation_key(connected_id)
    evidence = _evidence_from_response(resp)
    trusted = EndorsementKey(ak["ak_algorithm"], bytes.fromhex(ak["ak_pub_der_hex"])) if ak else None
    result = get_verifier("local").verify(evidence, nonce, trusted_key=trusted)
    ev["tpm_quote"] = result.reason
    ev["ak_fingerprint"] = hashlib.sha256(evidence.quote.signing_key.public_der).hexdigest()[:16]
    ev["compute_ms"] = _ms(t0)
    if result.status is not AttestationStatus.TRUSTED:
        return CheckResult("identity", "fail", f"TPM quote rejected: {result.reason}.", ev)
    return CheckResult("identity", "pass",
                       f"'{connected_id}' proved possession of its enrolled device key and TPM attestation key.", ev)


def check_integrity(resp: dict | None, identity: CheckResult | None = None) -> CheckResult:
    t0 = time.perf_counter()
    if resp is None:
        return CheckResult("integrity", "fail", "No firmware measurement available.", {})
    if identity is not None and identity.status == "fail":
        fw = resp.get("firmware", {})
        return CheckResult("integrity", "fail",
                           "Firmware measurement cannot be trusted: it was not delivered under a valid "
                           "attestation from the enrolled device.",
                           {"version": fw.get("version"), "reported_sha256": (fw.get("payload_sha256") or "")[:20] + "…",
                            "measured_boot": "unverified (attestation failed)", "compute_ms": _ms(t0)})
    fw = resp["firmware"]
    digest = fw["payload_sha256"]
    pcr0 = resp["pcrs"]["values"].get("0")
    ev = {"version": fw["version"], "vendor": fw["vendor"], "payload_sha256": digest[:20] + "…",
          "measured_pcr0": (pcr0 or "")[:20] + "…"}
    record = lookup_firmware(digest)
    golden = lookup_golden_pcr0(digest)
    if record is None:
        ev["registry"] = "not found"
        ev["compute_ms"] = _ms(t0)
        return CheckResult("integrity", "fail",
                           f"Firmware {fw['version']} hash {digest[:12]}… is not in the vendor registry — "
                           "image modified after signing.", ev)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(get_vendor_pub_hex())).verify(
            bytes.fromhex(fw["vendor_signature"]), bytes.fromhex(digest))
        ev["vendor_signature"] = "valid (Ed25519)"
    except (InvalidSignature, ValueError):
        ev["vendor_signature"] = "invalid"
        ev["compute_ms"] = _ms(t0)
        return CheckResult("integrity", "fail", "Vendor signature over the firmware hash is invalid.", ev)
    if golden is None or golden["golden_pcr0"] != pcr0:
        ev["measured_boot"] = "PCR0 differs from the golden value"
        ev["compute_ms"] = _ms(t0)
        return CheckResult("integrity", "fail",
                           "Measured boot disagrees: PCR0 does not match the golden value for the claimed image.", ev)
    ev["measured_boot"] = "PCR0 matches golden value"
    ev["build_date"] = record.get("build_date")
    ev["compute_ms"] = _ms(t0)
    return CheckResult("integrity", "pass",
                       f"Firmware {fw['version']} is vendor-signed, registered and matches measured boot (PCR0).", ev)


def check_weaknesses(resp: dict | None) -> CheckResult:
    t0 = time.perf_counter()
    digest = (resp or {}).get("firmware", {}).get("payload_sha256", "")
    rows = lookup_cves(digest)
    cves = [{"id": r["cve_id"], "severity": r["severity"], "cvss": r["cvss_score"],
             "component": r["component"], "description": r["description"], "fixed_in": r["fixed_in"]}
            for r in sorted(rows, key=lambda r: -r["cvss_score"])]
    ev = {"firmware_hash": digest[:20] + "…", "cve_count": len(cves), "cves": cves,
          "source": "pre-audit cache (audit once, verify fast)", "compute_ms": _ms(t0)}
    if lookup_firmware(digest) is None:
        ev["audited"] = False
        return CheckResult("weaknesses", "warning",
                           "Unaudited firmware: no audit record exists for this hash, so its weaknesses are unknown.", ev)
    ev["audited"] = True
    if not cves:
        return CheckResult("weaknesses", "pass", "No known CVEs recorded for this firmware in the audit cache.", ev)
    crit = sum(c["severity"] == "CRITICAL" for c in cves)
    return CheckResult("weaknesses", "warning",
                       f"{len(cves)} known CVE(s) in this firmware ({crit} critical). Authentic but vulnerable.", ev)


def check_behaviour(records: list[dict], window_s: float, prior_messages: list[str] = ()) -> CheckResult:
    t0 = time.perf_counter()
    report = _BASELINE.evaluate(records, start_phase=_BASELINE.phase_reached(prior_messages))
    ev = {"records": len(records), "window_s": window_s, "action": report.action.value,
          "blocked_peers": report.blocked_peers, "rate_limited": report.rate_limited,
          "anomalies": [{"rule": a.rule, "message": a.message, "peer": a.peer, "severity": a.severity}
                        for a in report.anomalies[:12]],
          "compute_ms": _ms(t0)}
    if report.status == "normal":
        return CheckResult("behavior", "pass",
                           f"{len(records)} observed messages and flows match the charger baseline.", ev)
    rules = sorted({a.rule for a in report.anomalies})
    return CheckResult("behavior", "fail", f"Anomalous behaviour: {', '.join(rules)}.", ev)


def baseline():
    return _BASELINE
