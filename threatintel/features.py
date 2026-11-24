"""
Feature extraction for the threat detectors.

Both detectors are linear models over hashed n-gram features, so they need no
vocabulary file, run in microseconds on an Arm CPU, export cleanly to
ExecuTorch as a single linear layer, and can explain every score: each
n-gram's contribution is its hashed weight.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer

N_HASH = 2 ** 18

# ── SMS ───────────────────────────────────────────────────────────────────

_URL_RX = re.compile(r"(https?://\S+|www\.\S+|\b[a-z0-9-]+\.(?:com|net|org|io|ly|co|info|biz|xyz|top)\b\S*)", re.I)
_PHONE_RX = re.compile(r"\+?\d[\d\s-]{7,}\d")
_MONEY_RX = re.compile(r"[£$€₹]\s?\d+|\d+\s?(?:p|pence|usd|eur|gbp|inr|rs)\b", re.I)


def normalise_sms(text: str) -> str:
    """Lower-case and replace volatile tokens with stable placeholders."""
    t = text.lower()
    t = _URL_RX.sub(" urltoken ", t)
    t = _PHONE_RX.sub(" phonetoken ", t)
    t = _MONEY_RX.sub(" moneytoken ", t)
    return re.sub(r"\s+", " ", t).strip()


SMS_WORD = HashingVectorizer(n_features=N_HASH, analyzer="word", ngram_range=(1, 2),
                             alternate_sign=False, norm="l2", token_pattern=r"(?u)\b\w+\b")
SMS_CHAR = HashingVectorizer(n_features=N_HASH, analyzer="char_wb", ngram_range=(3, 5),
                             alternate_sign=False, norm="l2")


# ── URLs ──────────────────────────────────────────────────────────────────

SECOND_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.in", "org.in", "co.jp",
                "com.br", "com.cn", "co.za", "com.mx", "co.nz", "com.sg", "com.tr", "co.kr"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "icu", "cyou", "click",
                   "link", "rest", "monster", "buzz", "sbs", "cfd", "lol", "live"}
HOSTING_SUFFIXES = ("firebaseapp.com", "web.app", "ipfs.io", "infura-ipfs.io", "dweb.link", "pages.dev",
                    "workers.dev", "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com",
                    "github.io", "glitch.me", "netlify.app", "vercel.app", "herokuapp.com",
                    "sharepoint.com", "r2.dev", "repl.co", "square.site", "godaddysites.com",
                    "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com",
                    "storage.googleapis.com", "firebasestorage.googleapis.com", "notion.site", "canva.site")
BRANDS = ("paypal", "apple", "icloud", "microsoft", "office365", "outlook", "netflix", "amazon", "google",
          "facebook", "instagram", "whatsapp", "dhl", "fedex", "usps", "chase", "wellsfargo", "hsbc",
          "barclays", "sbi", "hdfc", "icici", "coinbase", "binance", "metamask", "tesla", "chargepoint",
          "ionity", "shell", "bp", "tata", "adani", "jio", "airtel")
PATH_KEYWORDS = ("login", "signin", "verify", "verification", "account", "update", "secure", "wallet",
                 "payment", "billing", "unlock", "confirm", "password", "reset", "invoice", "refund")


def host_of(url: str) -> str:
    u = url.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", u, re.I):
        u = "http://" + u
    host = (urlsplit(u).hostname or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def registrable_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def host_lexical(host: str) -> np.ndarray:
    """Hand-built lexical signals over the hostname (scheme, www and path removed)."""
    try:
        ipaddress.ip_address(host)
        is_ip = 1.0
    except ValueError:
        is_ip = 0.0
    labels = host.split(".")
    reg = registrable_domain(host)
    sub = host[: -len(reg)].rstrip(".") if host.endswith(reg) else ""
    tld = labels[-1] if labels else ""
    digits = sum(ch.isdigit() for ch in host)
    brand_in_sub = float(any(b in sub for b in BRANDS))
    brand_in_reg = float(any(b in reg.split(".")[0] for b in BRANDS))
    return np.array([
        len(host) / 50, len(labels) / 5, len(sub) / 30, digits / 10, host.count("-") / 5,
        _entropy(host) / 5, is_ip, float(tld in SUSPICIOUS_TLDS), float(host.endswith(HOSTING_SUFFIXES)),
        brand_in_sub, brand_in_reg * float(len(reg.split(".")[0]) > 12), float("xn--" in host),
    ], dtype=np.float32)


HOST_CHAR = HashingVectorizer(n_features=N_HASH, analyzer="char", ngram_range=(3, 5),
                              alternate_sign=False, norm="l2")
N_LEXICAL = 12
