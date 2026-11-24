"""
Built-in firmware audit (C3, "audit once").

Scans the raw bytes of a firmware image for the version banners that common
embedded components compile into their binaries, then matches the versions
against an offline CVE feed. Runs once per firmware version; the result is
stored keyed by the image's payload SHA-256 so verification is a lookup.

This is the dependency-free path used by the demo and on nodes without the
external toolchain. When Syft/Grype are installed, integrations.vulnerability
produces the same kind of result from a full SBOM.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FEED_PATH = ROOT / "audit" / "cve_feed.json"

# Banners exactly as these projects embed them in their binaries.
BANNERS = {
    "openssl": re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]*)\s"),
    "zlib":    re.compile(rb" inflate (\d+\.\d+\.\d+(?:\.\d+)?) Copyright"),
    "busybox": re.compile(rb"BusyBox v(\d+\.\d+\.\d+)"),
}


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    offset: int

    @property
    def purl(self) -> str:
        return f"pkg:generic/{self.name}@{self.version}"


def _vkey(v: str) -> tuple:
    """Comparable key for versions like 1.1.1k, 1.0.2zd, 3.0.13, 1.2.11."""
    m = re.fullmatch(r"(\d+(?:\.\d+)*)([a-z]*)", v)
    if not m:
        return (v,)
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums = nums + (0,) * (4 - len(nums))
    letters = m.group(2)
    # OpenSSL letter releases: "" < "a" < ... < "z" < "za" < "zb" ...
    return nums + (len(letters), letters)


def in_range(version: str, lo: str, hi_exclusive: str) -> bool:
    return _vkey(lo) <= _vkey(version) < _vkey(hi_exclusive)


def find_components(data: bytes) -> list[Component]:
    found = []
    for name, rx in BANNERS.items():
        for m in rx.finditer(data):
            found.append(Component(name, m.group(1).decode(), m.start()))
    unique = {(c.name, c.version): c for c in found}
    return sorted(unique.values(), key=lambda c: c.offset)


def load_feed(path: Path = FEED_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def match_cves(components: list[Component], feed: dict | None = None) -> list[dict]:
    feed = feed or load_feed()
    hits = []
    for c in components:
        for e in feed["entries"]:
            if e["component"] == c.name and any(in_range(c.version, lo, hi) for lo, hi in e["affected"]):
                hits.append({
                    "cve_id": e["cve_id"], "severity": e["severity"], "cvss_score": e["cvss"],
                    "component": f"{c.name}/{c.version}", "description": e["description"],
                    "fixed_in": f"{c.name}/{e['fixed_in']}",
                })
    return sorted(hits, key=lambda h: -h["cvss_score"])


def audit_bytes(data: bytes, feed: dict | None = None) -> dict:
    components = find_components(data)
    cves = match_cves(components, feed)
    return {
        "components": [{"name": c.name, "version": c.version, "purl": c.purl, "offset": c.offset}
                       for c in components],
        "cves": cves,
        "weaknesses": "known-cves" if cves else "none",
        "feed": (feed or load_feed())["feed"],
    }
