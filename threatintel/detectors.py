"""
Runtime threat detectors (no training dependencies beyond scikit-learn's hasher).

    from threatintel import ScamMessageDetector, PhishingUrlDetector
    ScamMessageDetector().analyse("Your charging account is suspended, pay now: bit.ly/x")
    PhishingUrlDetector().analyse("https://pay-chargepoint-verify.top/login")

Each result carries the score, the decision threshold chosen on validation
data, and the signals that drove it (top n-grams by weight, rules fired), so
the advisor and the dashboard can explain the decision.
"""
from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np
from sklearn.utils import murmurhash3_32

from threatintel import features as F

WEIGHTS = Path(__file__).resolve().parent / "weights"


def _sigmoid(z: float) -> float:
    return float(1 / (1 + np.exp(-z)))


def _hash_index(token: str, n: int = F.N_HASH) -> int:
    """Same bucket HashingVectorizer assigns to a token (alternate_sign=False)."""
    return abs(murmurhash3_32(token, seed=0)) % n


@dataclass
class Signal:
    feature: str
    contribution: float


@dataclass
class Detection:
    kind: str                       # "sms" | "url"
    verdict: str                    # "scam" | "phishing" | "legitimate"
    score: float                    # probability-like score in [0, 1]
    threshold: float
    signals: list[Signal] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    model: str = ""
    latency_ms: float = 0.0
    details: dict = field(default_factory=dict)

    @property
    def malicious(self) -> bool:
        return self.verdict != "legitimate"

    def to_dict(self) -> dict:
        return asdict(self)


def _top_ngrams(analyzer, text, x_row, weights, k=6):
    """Map the strongest active hashed features back to the n-grams that produced them."""
    contrib = {}
    for tok in set(analyzer(text)):
        idx = _hash_index(tok)
        pos = np.searchsorted(x_row.indices, idx) if x_row.nnz else 0
        if pos < x_row.nnz and x_row.indices[pos] == idx:
            contrib[tok] = float(x_row.data[pos] * weights[idx])
    return [Signal(t.strip(), round(c, 4)) for t, c in
            sorted(contrib.items(), key=lambda kv: -abs(kv[1]))[:k] if abs(c) > 1e-4]


class ScamMessageDetector:
    model_name = "sms_scam v1 · logistic regression · hashed word+char n-grams"

    def __init__(self, path: Path = WEIGHTS / "sms_scam.npz"):
        z = np.load(path)
        self.w_word, self.w_char = z["w_word"], z["w_char"]
        self.bias, self.threshold = float(z["bias"]), float(z["threshold"])
        self._wa, self._ca = F.SMS_WORD.build_analyzer(), F.SMS_CHAR.build_analyzer()

    def analyse(self, text: str) -> Detection:
        t0 = time.perf_counter()
        norm = F.normalise_sms(text)
        xw = F.SMS_WORD.transform([norm]).tocsr()
        xc = F.SMS_CHAR.transform([norm]).tocsr()
        xw.sort_indices(); xc.sort_indices()
        z = float(xw.dot(self.w_word)[0] + xc.dot(self.w_char)[0] + self.bias)
        score = _sigmoid(z)
        signals = _top_ngrams(self._wa, norm, xw, self.w_word, 5)
        signals = [s for s in signals if s.contribution > 0] or signals
        for s in signals:                                  # readable names for normalised tokens
            for tok, label in (("urltoken", "a web link"), ("phonetoken", "a phone number"),
                               ("moneytoken", "a money amount")):
                s.feature = s.feature.replace(tok, label)
        return Detection("sms", "scam" if score >= self.threshold else "legitimate", round(score, 4),
                         round(self.threshold, 4), signals[:5], model=self.model_name,
                         latency_ms=round((time.perf_counter() - t0) * 1000, 3),
                         details={"normalised": norm})


def _tokens(s: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", s.lower()) if t}


def _brand_misuse(host: str, path: str) -> bool:
    """A brand appears as a whole token, but the site is not that brand's own domain."""
    reg_label = F.registrable_domain(host).split(".")[0]
    if host.endswith(F.HOSTING_SUFFIXES):              # user content on a platform: judge the path
        return bool(_tokens(host.split(".")[0] + " " + path) & set(F.BRANDS))
    if reg_label in F.BRANDS:
        return False                                   # e.g. chargepoint.com itself
    sub = host[: -len(F.registrable_domain(host))]
    return bool(_tokens(sub + " " + reg_label + " " + path) & set(F.BRANDS))


# Explicit URL rules (documented, not learned): signals the hostname model cannot
# see because the training data leaks them (see threatintel/train.py).
URL_RULES = [
    ("credential or payment keyword in path", 0.30,
     lambda u, h, p: any(k in p for k in F.PATH_KEYWORDS)),
    ("brand name used outside the brand's own domain", 0.35, lambda u, h, p: _brand_misuse(h, p)),
    ("raw IP address instead of a domain", 0.45, lambda u, h, p: F.host_lexical(h)[6] == 1.0),
    ("'@' in URL (credential-style redirect)", 0.40, lambda u, h, p: "@" in u.split("//", 1)[-1].split("/", 1)[0]),
    ("punycode / look-alike characters", 0.35, lambda u, h, p: "xn--" in h),
    ("unencrypted http", 0.10, lambda u, h, p: u.lower().startswith("http://")),
    ("URL shortener hides the destination", 0.25,
     lambda u, h, p: F.registrable_domain(h) in {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "t.ly"}),
    ("free hosting / app-platform subdomain", 0.20, lambda u, h, p: h.endswith(F.HOSTING_SUFFIXES)),
]


HARD_FLAGS = {"raw IP address instead of a domain", "'@' in URL (credential-style redirect)",
              "punycode / look-alike characters"}
KNOWN_GOOD_CAP = 0.05
KNOWN_GOOD = {line.strip().lower() for line in (Path(__file__).with_name("known_good.txt"))
              .read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")}


class PhishingUrlDetector:
    model_name = "phishing_url v1 · logistic regression · hostname char n-grams + lexical features + rules"

    def __init__(self, path: Path = WEIGHTS / "phishing_url.npz"):
        z = np.load(path)
        self.w_char, self.w_lex = z["w_char"], z["w_lex"]
        self.bias, self.threshold = float(z["bias"]), float(z["threshold"])
        self._ca = F.HOST_CHAR.build_analyzer()

    def analyse(self, url: str) -> Detection:
        t0 = time.perf_counter()
        url = url.strip()
        host = F.host_of(url)
        path = re.sub(r"^[a-z][a-z0-9+.-]*://[^/]*", "", url, flags=re.I).lower()
        xc = F.HOST_CHAR.transform([host]).tocsr(); xc.sort_indices()
        lex = F.host_lexical(host)
        model = _sigmoid(float(xc.dot(self.w_char)[0] + lex @ self.w_lex + self.bias))
        fired = [(name, w) for name, w, test in URL_RULES if test(url, host, path)]
        reg = F.registrable_domain(host)
        known_good = reg in KNOWN_GOOD and not host.endswith(F.HOSTING_SUFFIXES)
        hard = [n for n, _ in fired if n in HARD_FLAGS]
        if known_good and not hard:
            # first-party site on the curated list: reputation outweighs the model
            fired = [(n, w) for n, w in fired if n == "unencrypted http"]
            model = min(model, KNOWN_GOOD_CAP)
        # noisy-OR: each rule independently raises the probability of phishing
        score = 1 - (1 - model) * float(np.prod([1 - w for _, w in fired])) if fired else model
        signals = [s for s in _top_ngrams(self._ca, host, xc, self.w_char, 5) if s.contribution > 0][:4]
        return Detection("url", "phishing" if score >= self.threshold else "legitimate", round(score, 4),
                         round(self.threshold, 4), signals, [n for n, _ in fired], self.model_name,
                         round((time.perf_counter() - t0) * 1000, 3),
                         {"host": host, "registrable_domain": reg, "known_good_domain": known_good and not hard,
                          "model_score": round(model, 4)})


_URL_IN_TEXT = re.compile(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|ly|co|info|biz|xyz|top|in|uk|me|site|online|link|click|app|dev|shop)\b(?:/[^\s<>\"']*)?)", re.I)


def extract_urls(text: str) -> list[str]:
    return [m.rstrip(".,);:!?") for m in _URL_IN_TEXT.findall(text)]
