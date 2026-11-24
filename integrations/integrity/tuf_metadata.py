"""
The Update Framework (python-tuf): secure update metadata.

A TUF repository describes which firmware versions are current and signed
by the vendor's offline root, protecting against rollback, freeze and
mix-and-match attacks. Uptane builds on the same model for vehicles.

ChargeGuard uses the ngclient to ask: "is this firmware hash the one the
vendor's update repository currently publishes for this target?"

Requires: pip install tuf   (source vendored in vendor/update/python-tuf)
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

from ..core import Finding, Severity, ToolResult, ToolUnavailable, timed


def tuf_available() -> bool:
    return importlib.util.find_spec("tuf") is not None


def check_target(metadata_url: str, targets_url: str, metadata_dir: str | Path,
                 target_name: str, firmware: bytes | str | Path,
                 trusted_root: str | Path | None = None) -> ToolResult:
    """
    metadata_dir must contain a trusted root.json (copied at enrolment), or pass
    trusted_root to bootstrap it. The firmware's SHA-256 must match the target
    entry in the signed, unexpired targets metadata.
    """
    result = ToolResult(tool="tuf", ok=False)
    with timed(result):
        if not tuf_available():
            raise ToolUnavailable("python-tuf is not installed (pip install tuf)")
        from tuf.ngclient import Updater

        metadata_dir = Path(metadata_dir)
        metadata_dir.mkdir(parents=True, exist_ok=True)
        root_bytes = Path(trusted_root).read_bytes() if trusted_root else None
        updater = Updater(metadata_dir=str(metadata_dir), metadata_base_url=metadata_url,
                          target_base_url=targets_url, bootstrap=root_bytes)
        updater.refresh()                      # verifies root -> timestamp -> snapshot -> targets
        info = updater.get_targetinfo(target_name)
        if info is None:
            result.findings.append(Finding("tuf", "target-unknown",
                                           f"'{target_name}' is not published in signed TUF metadata",
                                           Severity.HIGH, target_name))
            return result
        data = firmware if isinstance(firmware, bytes) else Path(firmware).read_bytes()
        expected = info.hashes.get("sha256")
        actual = hashlib.sha256(data).hexdigest()
        result.ok = expected == actual and info.length == len(data)
        result.raw = {"target": target_name, "expected_sha256": expected,
                      "actual_sha256": actual, "length": info.length}
        if not result.ok:
            result.findings.append(Finding("tuf", "target-mismatch",
                                           "Firmware differs from the version published by the vendor",
                                           Severity.CRITICAL, target_name, result.raw))
    return result
