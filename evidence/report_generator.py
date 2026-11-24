"""
C7 – Evidence Bundle Generator
Produces a SARIF 2.1-compatible JSON report + signed verdict file,
annotated with compliance controls from the policy mapper.
"""
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import EVIDENCE_DIR
from policy.mapper import annotate, get_all_controls
from evidence.signer import sign_verdict


def generate(session_id: str, verdict: str, reason: str, score: int,
             results: dict, charger_mode: str) -> dict:
    """
    results: { check_name: CheckResult }
    Returns the full report dict (also saved to disk).
    """
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().isoformat() + "Z"
    all_controls = get_all_controls()

    # ── Build SARIF 2.1 structure ─────────────────────────────────────────
    sarif_runs = []
    for check_name, result in results.items():
        rd = result.to_dict()
        rd = annotate(check_name, rd)

        status_map = {"pass": "open", "fail": "open", "warning": "open"}
        level_map  = {"pass": "none", "fail": "error", "warning": "warning"}

        rules = []
        for ctrl in rd.get("compliance", []):
            rules.append({
                "id": ctrl["control_id"],
                "name": ctrl["title"],
                "shortDescription": {"text": ctrl["requirement"]},
                "properties": {"standard": ctrl["standard"]},
            })

        results_sarif = [{
            "ruleId":  rules[0]["id"] if rules else check_name,
            "level":   level_map.get(result.status, "note"),
            "message": {"text": result.detail},
            "properties": {
                "chargeGuard.check":    check_name,
                "chargeGuard.status":   result.status,
                "chargeGuard.evidence": result.evidence,
                "chargeGuard.timing_s": result.timing,
            },
        }]

        sarif_runs.append({
            "tool": {
                "driver": {
                    "name":    f"ChargeGuard/{check_name}",
                    "version": "1.0.0",
                    "rules":   rules,
                }
            },
            "results": results_sarif,
        })

    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs":    sarif_runs,
    }

    # ── Verdict block (to be signed) ──────────────────────────────────────
    verdict_payload = {
        "session_id":   session_id,
        "timestamp":    timestamp,
        "charger_mode": charger_mode,
        "verdict":      verdict,
        "score":        score,
        "reason":       reason,
        "check_summary": {
            name: res.status for name, res in results.items()
        },
    }

    signature = sign_verdict(verdict_payload)

    report = {
        "chargeGuard_version": "1.0.0",
        "session_id":          session_id,
        "generated_at":        timestamp,
        "charger_mode":        charger_mode,
        "verdict":             verdict,
        "score":               score,
        "reason":              reason,
        "signature":           signature,
        "signed_payload":      verdict_payload,
        "compliance_controls": all_controls,
        "sarif":               sarif,
        "check_details": {
            name: annotate(name, res.to_dict())
            for name, res in results.items()
        },
    }

    # Save to disk
    report_path = EVIDENCE_DIR / f"{session_id}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    return report
