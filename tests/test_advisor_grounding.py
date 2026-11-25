"""The checks that decide whether Llama's explanation may be shown (no model needed)."""
import pytest

from advisor.engines import Advisor, LlamaExecuTorchAdvisor as L

PASSED = {k: {"status": "pass"} for k in ("identity", "integrity", "weaknesses", "behavior")}


@pytest.mark.parametrize("text,facts,checks", [
    ("The message is safe. The main reason is that the link is a phishing attempt.", {"verdict": "phishing"}, None),
    ("It has two known vulnerabilities in OpenSSL and zlib, but they are not exploitable.", {"verdict": "amber"}, None),
    ("This charger was compromised by an attacker on the network.", {"verdict": "green"}, PASSED),
    ("The charger runs firmware with CVE-2020-1111, which is serious.", {"verdict": "amber", "cves": ["CVE-2021-3711"]}, None),
    ("The charger contacted 10.0.0.9, an unknown host on the network.", {"verdict": "red"}, None),
    ("The firmware was tampered with and is also vulnerable to a weakness.", {"verdict": "red"},
     {"integrity": {"status": "fail", "detail": "Firmware hash not in vendor registry"},
      "weaknesses": {"status": "skip", "detail": "Unaudited firmware"}}),
])
def test_rejects_ungrounded_or_contradicting_text(text, facts, checks):
    with pytest.raises(RuntimeError):
        L.clean(text, facts, checks)


@pytest.mark.parametrize("text,facts,checks", [
    ("The charger runs authentic firmware and has no known vulnerabilities. Nothing suspicious was seen.",
     {"verdict": "green"}, PASSED),
    ("This link is not safe: it imitates a payment page on a look-alike domain.", {"verdict": "phishing"}, None),
    ("The firmware contains CVE-2021-3711 in openssl 1.1.1k, a critical flaw that attackers can use.",
     {"verdict": "amber", "cves": ["CVE-2021-3711 in openssl 1.1.1k"]}, None),
])
def test_accepts_grounded_text(text, facts, checks):
    assert L.clean(text, facts, checks)


def test_tidy_strips_preamble_and_meta_sentences():
    out = L.tidy("**Here are two sentences:** The charger was refused. "
                 "This version of the finding conveys the same information as the original.")
    assert out == "The charger was refused."


def test_falls_back_to_grounded_template_when_llama_is_absent(monkeypatch):
    adv = Advisor()
    monkeypatch.setattr(adv.llama, "available", lambda: False)
    a = adv.explain({"verdict": "red", "checks": {"integrity": {"status": "fail", "evidence": {}}}})
    assert a.engine.startswith("rule-based") and a.fallback_reason and a.steps


def test_llama_text_with_grounded_steps(monkeypatch):
    adv = Advisor()
    monkeypatch.setattr(adv.llama, "available", lambda: True)
    monkeypatch.setattr(adv.llama, "_text", lambda prompt: "The firmware was modified after signing. Charging was refused.")
    ctx = {"verdict": "red", "checks": {"integrity": {"status": "fail", "detail": "hash not in registry", "evidence": {}},
                                        "identity": {"status": "pass"}}, "enforcement": {"action": "deny"}}
    a = adv.explain(ctx)
    assert a.engine.startswith("Llama") and a.fallback_reason is None
    assert a.steps == adv.template.explain(ctx).steps and a.steps_source == "grounded rules"


def test_rejected_llama_text_falls_back(monkeypatch):
    adv = Advisor()
    monkeypatch.setattr(adv.llama, "available", lambda: True)
    monkeypatch.setattr(adv.llama, "_text", lambda prompt: "Everything is safe and secure here, nothing to worry about.")
    a = adv.explain({"verdict": "red", "checks": {"integrity": {"status": "fail", "detail": "x", "evidence": {}}}})
    assert a.engine.startswith("rule-based") and "safe" in a.fallback_reason
