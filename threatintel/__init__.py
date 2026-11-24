"""
On-device threat detectors for EV-charging users and operators.

  ScamMessageDetector   SMS / chat messages: charging-account, payment and prize scams
  PhishingUrlDetector   links and QR-code payloads: fake payment and login pages
  analyse_message       a message plus every link inside it, combined

Trained on public datasets (UCI SMS Spam Collection, UCI PhiUSIIL) by
threatintel/train.py; held-out metrics in benchmarks/results/threatintel_metrics.json.
"""
from .detectors import Detection, PhishingUrlDetector, ScamMessageDetector, Signal, extract_urls

_sms: ScamMessageDetector | None = None
_url: PhishingUrlDetector | None = None


def detectors() -> tuple[ScamMessageDetector, PhishingUrlDetector]:
    global _sms, _url
    if _sms is None:
        _sms, _url = ScamMessageDetector(), PhishingUrlDetector()
    return _sms, _url


def analyse_message(text: str) -> dict:
    """Score a message and every URL in it; the message is malicious if either part is."""
    sms, url = detectors()
    msg = sms.analyse(text)
    links = [url.analyse(u) for u in extract_urls(text)]
    worst_link = max(links, key=lambda d: d.score, default=None)
    malicious = msg.malicious or any(l.malicious for l in links)
    return {"verdict": "malicious" if malicious else "legitimate", "message": msg.to_dict(),
            "links": [l.to_dict() for l in links],
            "worst_link": worst_link.to_dict() if worst_link else None}


def analyse_url(u: str) -> dict:
    return detectors()[1].analyse(u).to_dict()


__all__ = ["Detection", "PhishingUrlDetector", "ScamMessageDetector", "Signal", "analyse_message",
           "analyse_url", "detectors", "extract_urls"]
