"""Tests for the on-device threat detectors (scam messages, phishing URLs) and their advisor output."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from advisor import Advisor  # noqa: E402
from threatintel import analyse_message, analyse_url, extract_urls  # noqa: E402
from threatintel import features as F  # noqa: E402
from threatintel.detectors import _hash_index  # noqa: E402


def test_explanations_use_the_same_hash_buckets_as_training():
    x = F.SMS_WORD.transform(["free prize now"]).tocsr()
    assert sorted(x.indices.tolist()) == sorted({_hash_index(t) for t in F.SMS_WORD.build_analyzer()("free prize now")})


@pytest.mark.parametrize("text", [
    "Congratulations! You've won a free 1 year charging pass. Text WIN to 80888 to claim, T&C apply",
    "URGENT: Your EV charging account is suspended. Verify payment now at chargepoint-billing.top/verify",
])
def test_scam_messages_are_flagged(text):
    assert analyse_message(text)["verdict"] == "malicious"


@pytest.mark.parametrize("text", [
    "Hi, I'll be at the charging station around 6, see you there",
    "Your OTP for the charging session is 482913. Do not share it with anyone.",
])
def test_ordinary_messages_pass(text):
    assert analyse_message(text)["verdict"] == "legitimate"


@pytest.mark.parametrize("url,expected", [
    ("https://pay-chargepoint-verify.top/login", "phishing"),
    ("http://192.168.4.1/payment", "phishing"),
    ("https://xn--chargepint-5kb.com/pay", "phishing"),
    ("https://sites.google.com/view/chargepoint-refund", "phishing"),
    ("https://accounts.google.com.verify-login.xyz/signin", "phishing"),
    ("https://chargepoint.com/pay/CG-CHARGER-001", "legitimate"),
    ("https://www.tatapower.com/ev/charging", "legitimate"),
    ("https://www.google.com/maps", "legitimate"),
])
def test_urls(url, expected):
    assert analyse_url(url)["verdict"] == expected


def test_known_good_list_never_hides_hard_red_flags():
    r = analyse_url("http://chargepoint.com@203.0.113.9/pay")
    assert r["verdict"] == "phishing" and not r["details"]["known_good_domain"]


def test_links_are_extracted_from_messages():
    assert "chargepoint-billing.top/verify" in extract_urls("pay at chargepoint-billing.top/verify now")


def test_advisor_explains_threats_without_internal_tokens():
    adv = Advisor().explain_threat(analyse_message("Claim your prize at win-prize.top/claim, call +44 7700 900123"))
    text = adv.summary + " ".join(adv.steps)
    assert "token" not in text and adv.steps


def test_published_metrics_match_the_evaluation_protocol():
    m = json.loads((ROOT / "benchmarks" / "results" / "threatintel_metrics.json").read_text())
    assert m["phishing_url"]["split"]["domains_in_both_train_and_test"] == 0
    assert m["sms_scam"]["test"]["f1"] > 0.9
    assert 0 < m["phishing_url"]["test"]["roc_auc"] <= 1
