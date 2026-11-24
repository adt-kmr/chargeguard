"""
Tamper-evident evidence bundle (C7).

Layout of one bundle directory:

    verdict.json            final verdict + per-check results (from the orchestrator)
    findings.sarif          all findings, SARIF 2.1.0
    sbom.cdx.json           CycloneDX SBOM (from Syft), if available
    <extra files>           e.g. grype.sarif, iotaudit.json, attestation quote
    manifest.json           SHA-256 of every file above + a bundle digest
    manifest.json.sigstore.json   Cosign signature over the manifest (optional)

Signing the manifest anchors every file by hash, so changing any byte of
any file breaks verification.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from ..core import Finding, ToolResult
from .sarif import build_sarif

MANIFEST = "manifest.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_bundle(out_dir: str | Path, verdict: dict,
                 results: Iterable[ToolResult] = (), findings: Iterable[Finding] = (),
                 sbom: str | Path | None = None, extra_files: dict[str, str | Path] | None = None,
                 sign_key: str | Path | None = None) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    results = list(results)

    (out / "verdict.json").write_text(json.dumps(verdict, indent=2, sort_keys=True))
    (out / "findings.sarif").write_text(json.dumps(build_sarif(results, findings), indent=2))
    if sbom:
        shutil.copyfile(sbom, out / "sbom.cdx.json")
    for name, src in (extra_files or {}).items():
        shutil.copyfile(src, out / name)

    files = {p.name: _sha256(p) for p in sorted(out.iterdir())
             if p.is_file() and not p.name.startswith(MANIFEST)}
    digest = hashlib.sha256("".join(f"{n}:{h}\n" for n, h in sorted(files.items())).encode()).hexdigest()
    manifest = {"format": "chargeguard-evidence/1", "created_at": datetime.now(timezone.utc).isoformat(),
                "files": files, "bundle_sha256": digest}
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True))

    if sign_key:
        from ..integrity.cosign import sign_blob
        res = sign_blob(out / MANIFEST, key=sign_key)
        if not res.ok:
            raise RuntimeError(f"signing failed: {res.error}")
    return out


def verify_bundle(bundle_dir: str | Path, pubkey: str | Path | None = None) -> tuple[bool, list[str]]:
    """Recheck every file hash; if pubkey is given, also verify the Cosign signature."""
    d = Path(bundle_dir)
    problems: list[str] = []
    manifest = json.loads((d / MANIFEST).read_text())
    for name, expected in manifest["files"].items():
        p = d / name
        if not p.exists():
            problems.append(f"missing: {name}")
        elif _sha256(p) != expected:
            problems.append(f"modified: {name}")
    listed = set(manifest["files"])
    for p in d.iterdir():
        if p.is_file() and not p.name.startswith(MANIFEST) and p.name not in listed:
            problems.append(f"unlisted: {p.name}")
    if pubkey:
        from ..integrity.cosign import verify_blob
        res = verify_blob(d / MANIFEST, d / f"{MANIFEST}.sigstore.json", pubkey)
        if not res.ok:
            problems.append(f"signature: {res.error or 'invalid'}")
    return not problems, problems
