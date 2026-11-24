"""
Attestation settings. Every value can be overridden with an environment
variable so deployments can switch backends without code changes.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
THIRD_PARTY_TPM = PROJECT_ROOT / "third_party" / "tpm"


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


@dataclass
class AttestationConfig:
    # Which prover backend get_backend() returns by default
    backend: str = field(default_factory=lambda: _env("CHARGEGUARD_TPM_BACKEND", "software"))

    # tpm2-tss TCTI: "mssim:host=127.0.0.1,port=2321" (IBM simulator),
    # "swtpm:port=2321", or "device:/dev/tpmrm0" (hardware)
    tcti: str = field(default_factory=lambda: _env(
        "CHARGEGUARD_TPM_TCTI", "mssim:host=127.0.0.1,port=2321"))

    # IBM software TPM emulator
    emulator_binary: Path = field(default_factory=lambda: Path(_env(
        "CHARGEGUARD_TPM_EMULATOR",
        str(THIRD_PARTY_TPM / "ibmswtpm2" / "src" / ("tpm_server.exe" if os.name == "nt" else "tpm_server")))))
    emulator_port: int = field(default_factory=lambda: int(_env("CHARGEGUARD_TPM_EMULATOR_PORT", "2321")))

    # Keylime verifier REST API
    keylime_verifier_url: str = field(default_factory=lambda: _env(
        "CHARGEGUARD_KEYLIME_VERIFIER", "https://127.0.0.1:8881"))
    keylime_api_version: str = field(default_factory=lambda: _env("CHARGEGUARD_KEYLIME_API", "2.3"))
    keylime_client_cert: str | None = field(default_factory=lambda: os.environ.get("CHARGEGUARD_KEYLIME_CERT"))
    keylime_client_key: str | None = field(default_factory=lambda: os.environ.get("CHARGEGUARD_KEYLIME_KEY"))
    keylime_ca_cert: str | None = field(default_factory=lambda: os.environ.get("CHARGEGUARD_KEYLIME_CA"))
    keylime_timeout_s: float = 3.0
