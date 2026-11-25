"""Paths used on the Raspberry Pi: nftables enforcement, hardware-TPM measured launch, enrolment, node mode."""
import hashlib
import json

import pytest

from attestation.backends.software import SoftwareTPM
from attestation.types import HashAlg, PCRSelection
from integrations.behavior.firewall import Firewall


def test_firewall_renders_bridge_and_input_tables():
    fw = Firewall("render", protect=("10.20.0.1",))
    res = fw.enforce(quarantine=["10.20.0.15"], block=["203.0.113.66"])
    text = "\n".join(res.commands)
    assert "table bridge chargeguard" in text and "table inet chargeguard" in text
    assert "add element bridge chargeguard quarantine { 10.20.0.15 }" in text
    assert "add element inet chargeguard quarantine { 10.20.0.15 }" in text
    assert "add element bridge chargeguard blocked { 203.0.113.66 }" in text
    assert not res.applied and res.error is None


@pytest.mark.parametrize("bad", ["8.8.8.8; flush ruleset", "8.8.8.8 }", "not-an-ip", "::1", "0.0.0.0", "10.20.0.1"])
def test_firewall_refuses_unsafe_or_protected_addresses(bad):
    cmds, skipped = Firewall("render", protect=("10.20.0.1",)).commands([], [bad])
    assert bad in skipped and not any("blocked" in c and "add element" in c for c in cmds)


def test_firewall_check_mode_reports_missing_nft(monkeypatch):
    monkeypatch.setattr("integrations.behavior.firewall.shutil.which", lambda _: None)
    res = Firewall("check").enforce(quarantine=["10.20.0.15"])
    assert not res.applied and "nft not found" in res.error


def test_measured_launch_into_resettable_pcr_matches_golden_formula():
    from charger.agent import measure_launch
    image = b"firmware image bytes"
    tpm = SoftwareTPM()
    tpm.extend_pcr(23, b"left over from a previous start")
    measure_launch(tpm, image, 23)
    measure_launch(tpm, image, 23)                       # a restart gives the same value
    golden = hashlib.sha256(b"\0" * 32 + hashlib.sha256(image).digest()).digest()
    assert tpm.read_pcrs(PCRSelection(HashAlg.SHA256, (23,))).values[23] == golden
    with pytest.raises(ValueError):
        tpm.reset_pcr(0)


def test_enrolment_import_replaces_the_simulated_attestation_key(tmp_path, monkeypatch):
    from db.database import lookup_attestation_key
    from firmware import provision
    monkeypatch.setattr(provision, "ENROLLED_DIR", tmp_path)
    ak = "3059301306072a8648ce3d020106082a8648ce3d03010703420004" + "11" * 64
    (tmp_path / "CG-CHARGER-001.json").write_text(json.dumps(
        {"device_id": "CG-CHARGER-001", "device_pub_hex": "22" * 32, "ak_pub_der_hex": ak, "ak_algorithm": "ecc-p256"}))
    try:
        provision.provision()
        assert lookup_attestation_key("CG-CHARGER-001")["ak_pub_der_hex"] == ak
    finally:
        monkeypatch.setattr(provision, "ENROLLED_DIR", tmp_path / "none")
        provision.provision()                            # back to the simulated enrolment
    assert lookup_attestation_key("CG-CHARGER-001")["ak_pub_der_hex"] != ak


@pytest.mark.parametrize("mode,kept", [("demo", False), ("node", True)])
def test_quarantine_persists_across_sessions_only_in_node_mode(monkeypatch, mode, kept):
    from gateway import csms
    monkeypatch.setattr(csms, "NODE_MODE", mode)
    gw = csms.Gateway()
    gw.quarantine.add("CG-CHARGER-001")
    gw.open_session("s2", {"name": "live"})
    assert ("CG-CHARGER-001" in gw.quarantine) is kept
