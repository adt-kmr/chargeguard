"""
Sigstore Cosign: sign and verify arbitrary blobs (firmware images, verdict files).

Key-based, offline mode by default (no transparency log, no Sigstore services),
which suits a charger lab or air-gapped depot. Uses the Cosign v3 bundle format.

    cosign generate-key-pair            # once, produces cosign.key / cosign.pub
    sign_blob("verdict.json", key="cosign.key")
    verify_blob("verdict.json", bundle="verdict.json.sigstore.json", pubkey="cosign.pub")
"""
from __future__ import annotations

import os
from pathlib import Path

from ..core import Finding, Severity, Tool, ToolResult, register_tool, run, timed

COSIGN = register_tool(Tool(
    name="cosign", executables=("cosign",), feature="C2/C7",
    vendored="signing/cosign",
    install_hint="Build with `cd third_party/signing/cosign && make cosign`, or install a release binary.",
))


def sign_blob(path: str | Path, key: str | Path, bundle: str | Path | None = None,
              password_env: str = "COSIGN_PASSWORD", timeout: float = 30.0) -> ToolResult:
    path = Path(path)
    bundle = Path(bundle or f"{path}.sigstore.json")
    result = ToolResult(tool="cosign", ok=True)
    with timed(result):
        os.environ.setdefault(password_env, "")
        run(COSIGN, ["sign-blob", "--key", key, "--bundle", bundle,
                     "--no-signing-config", "--yes", path], timeout=timeout)
        result.artifacts["bundle"] = str(bundle)
    return result


def verify_blob(path: str | Path, bundle: str | Path, pubkey: str | Path,
                require_tlog: bool = False, timeout: float = 30.0) -> ToolResult:
    """ok=True only when Cosign accepts the signature."""
    args = ["verify-blob", "--key", pubkey, "--bundle", bundle]
    if not require_tlog:
        args.append("--insecure-ignore-tlog")
    result = ToolResult(tool="cosign", ok=False)
    with timed(result):
        proc = run(COSIGN, args + [path], timeout=timeout, check=False)
        result.ok = proc.returncode == 0
        result.raw = {"stdout": proc.stdout, "stderr": proc.stderr}
        if not result.ok:
            result.findings.append(Finding("cosign", "signature-invalid",
                                           "Cosign signature verification failed",
                                           Severity.CRITICAL, str(path),
                                           {"stderr": proc.stderr.strip()[-500:]}))
    return result
