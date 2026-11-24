"""
SARIF 2.1.0 writer for ChargeGuard findings.

Each tool becomes one SARIF `run`, so results from grype, mithril, checksec,
the behaviour baseline, etc. sit side by side in one standard file that
GitHub code scanning, DefectDojo and similar systems can ingest.
"""
from __future__ import annotations

from typing import Iterable

from ..core import Finding, Severity, ToolResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
          Severity.LOW: "note", Severity.INFO: "note", Severity.UNKNOWN: "warning"}
_SCORE = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
          Severity.LOW: "3.0", Severity.INFO: "0.0", Severity.UNKNOWN: "5.0"}


def _result(f: Finding) -> dict:
    r = {"ruleId": f.rule_id, "level": _LEVEL[f.severity], "message": {"text": f.title},
         "properties": {"severity": f.severity.value, **{k: v for k, v in f.details.items() if v is not None}}}
    if f.location:
        r["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": str(f.location)}}}]
    return r


def _run(tool: str, findings: list[Finding], version: str | None = None) -> dict:
    rules = {}
    for f in findings:
        rules.setdefault(f.rule_id, {"id": f.rule_id, "shortDescription": {"text": f.title[:120]},
                                     "properties": {"security-severity": _SCORE[f.severity]}})
    driver = {"name": tool, "rules": list(rules.values())}
    if version:
        driver["version"] = version
    return {"tool": {"driver": driver}, "results": [_result(f) for f in findings]}


def build_sarif(results: Iterable[ToolResult] = (), findings: Iterable[Finding] = ()) -> dict:
    by_tool: dict[str, list[Finding]] = {}
    for r in results:
        by_tool.setdefault(r.tool, []).extend(r.findings)
    for f in findings:
        by_tool.setdefault(f.tool, []).append(f)
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0",
            "runs": [_run(tool, fs) for tool, fs in sorted(by_tool.items())]}
