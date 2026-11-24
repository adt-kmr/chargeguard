"""
C5 – Trust Engine
Fuses results from C1-C4 into a single verdict (green / amber / red)
with a plain-English reason sentence.
"""
from config import VERDICT_GREEN, VERDICT_AMBER, VERDICT_RED


def fuse(results: dict) -> dict:
    """
    results: { "identity": CheckResult, "integrity": CheckResult,
                "weaknesses": CheckResult, "behavior": CheckResult }
    Returns: { "verdict": str, "reason": str, "score": int }
    """
    identity   = results.get("identity")
    integrity  = results.get("integrity")
    weaknesses = results.get("weaknesses")
    behavior   = results.get("behavior")

    def status(r):
        return r.status if r else "unknown"

    # RED conditions (hard failures)
    if status(identity) == "fail":
        return {
            "verdict": VERDICT_RED,
            "reason":  "UNTRUSTED — device identity could not be verified. "
                       "Possible rogue or spoofed charger.",
            "score":   0,
        }

    if status(integrity) == "fail":
        return {
            "verdict": VERDICT_RED,
            "reason":  "UNTRUSTED — firmware integrity check failed. "
                       "Image tampered or unrecognised.",
            "score":   10,
        }

    if status(behavior) == "fail":
        return {
            "verdict": VERDICT_RED,
            "reason":  "UNTRUSTED — anomalous live traffic detected. "
                       "Charger may be compromised; session isolated.",
            "score":   15,
        }

    # AMBER condition (authentic but vulnerable)
    if status(weaknesses) == "warning":
        cve_count = weaknesses.evidence.get("cve_count", 0)
        cves      = weaknesses.evidence.get("cves", [])
        worst     = max((c["cvss"] for c in cves), default=0)
        return {
            "verdict": VERDICT_AMBER,
            "reason":  f"CAUTION — charger runs authentic firmware but contains "
                       f"{cve_count} known CVE(s) (max CVSS {worst:.1f}). "
                       f"Firmware upgrade recommended before production use.",
            "score":   60,
        }

    # GREEN — all clear
    return {
        "verdict": VERDICT_GREEN,
        "reason":  "TRUSTED — identity verified, firmware authentic and unmodified, "
                   "no known vulnerabilities, traffic nominal.",
        "score":   100,
    }
