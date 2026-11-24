"""
Embedded-Linux update bundles: RAUC and SWUpdate.

Both tools verify the bundle's CMS signature against a trusted keyring
before any install. ChargeGuard only runs their *check* modes, never install.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..core import Finding, Severity, Tool, ToolResult, register_tool, run, timed

RAUC = register_tool(Tool(
    name="rauc", executables=("rauc",), feature="C2", vendored="update/rauc",
    install_hint="Build with meson (vendor/update/rauc) or install the distro package.",
))
SWUPDATE = register_tool(Tool(
    name="swupdate", executables=("swupdate",), feature="C2", vendored="update/swupdate",
    install_hint="Build vendor/update/swupdate with CONFIG_SIGNED_IMAGES=y.",
))


def verify_rauc_bundle(bundle: str | Path, keyring: str | Path, timeout: float = 30.0) -> ToolResult:
    """`rauc info` verifies the bundle signature and returns its manifest."""
    result = ToolResult(tool="rauc", ok=False)
    with timed(result):
        proc = run(RAUC, ["info", f"--keyring={keyring}", "--output-format=json", bundle],
                   timeout=timeout, check=False)
        result.ok = proc.returncode == 0
        if result.ok:
            result.raw = json.loads(proc.stdout or "{}")
        else:
            result.raw = proc.stderr
            result.findings.append(Finding("rauc", "bundle-signature-invalid",
                                           "RAUC bundle failed signature verification",
                                           Severity.CRITICAL, str(bundle), {"stderr": proc.stderr[-500:]}))
    return result


def verify_swupdate_image(swu: str | Path, pubkey: str | Path, timeout: float = 30.0) -> ToolResult:
    """`swupdate -c` checks the .swu (including sw-description signature) without installing."""
    result = ToolResult(tool="swupdate", ok=False)
    with timed(result):
        proc = run(SWUPDATE, ["-c", "-i", swu, "-k", pubkey], timeout=timeout, check=False)
        result.ok = proc.returncode == 0
        result.raw = (proc.stdout + proc.stderr)[-2000:]
        if not result.ok:
            result.findings.append(Finding("swupdate", "swu-verify-failed",
                                           "SWUpdate image failed verification",
                                           Severity.CRITICAL, str(swu)))
    return result
