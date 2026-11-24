"""
ChargeGuard integrations: adapters around the third-party tools in third_party/.

    integrations.integrity      C2  MCUboot/wolfBoot, RAUC/SWUpdate, Cosign, TUF
    integrations.vulnerability  C3  unblob, Syft, Grype, cve-bin-tool, mithril, checksec,
                                    kernel-hardening-checker, EMBA/FACT (deep)
    integrations.behavior       C4  baseline + anomaly rules, iotaudit, tshark/MQTT, wolfSentry
    integrations.evidence       C7  SARIF 2.1.0, CycloneDX, hash manifest, Cosign signature
    integrations.attack_lab     C9  Renode, attack scenario catalogue

C1 (identity and attestation) lives in the sibling `attestation` package.
None of this is wired into the dashboard yet; see integrations/README.md.

    python -m integrations      # print which external tools are installed
"""
from . import attack_lab, behavior, evidence, integrity, vulnerability  # noqa: F401  (registers tools)
from .core import TOOLS, Finding, Severity, ToolFailed, ToolResult, ToolUnavailable, doctor

__all__ = ["TOOLS", "Finding", "Severity", "ToolFailed", "ToolResult", "ToolUnavailable", "doctor",
           "attack_lab", "behavior", "evidence", "integrity", "vulnerability"]
