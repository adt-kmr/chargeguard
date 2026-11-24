"""
C5 – Orchestrator
Runs C1-C4 sequentially with per-step timing that mirrors the spec:
  0.0s identity  → 1.0s
  1.0s integrity → 2.0s
  2.0s weakness  → 3.0s
  3.0s behavior  → 4.5s
  4.5s verdict   → 5.0s

Events are yielded as dicts so the FastAPI WebSocket layer can stream them.
"""
import asyncio
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from checks.identity.identity_check   import run as check_identity
from checks.integrity.integrity_check import run as check_integrity
from checks.weaknesses.weakness_check import run as check_weakness
from checks.behavior.behavior_check   import run as check_behavior
from orchestrator.trust_engine        import fuse


async def run_verification(simulator, session_id: str):
    """
    Async generator that yields event dicts for WebSocket streaming.

    Event shapes:
      {"event": "check_start",  "check": str, "t": float}
      {"event": "check_done",   "check": str, "status": str,
       "detail": str, "evidence": dict, "t": float}
      {"event": "verdict",      "verdict": str, "reason": str,
       "score": int, "t": float, "session_id": str}
    """
    t_start = time.monotonic()

    def elapsed():
        return round(time.monotonic() - t_start, 3)

    results = {}
    checks = [
        ("identity",   check_identity,  None),
        ("integrity",  check_integrity, None),
        ("weaknesses", check_weakness,  None),
        ("behavior",   check_behavior,  None),
    ]

    for name, fn, _ in checks:
        yield {"event": "check_start", "check": name, "t": elapsed()}
        try:
            result = await asyncio.wait_for(fn(simulator), timeout=2.0)
        except asyncio.TimeoutError:
            from checks.identity.identity_check import CheckResult
            result = CheckResult(name, "fail", f"Check timed out after 2 s.")

        results[name] = result

        yield {
            "event":    "check_done",
            "check":    name,
            "status":   result.status,
            "detail":   result.detail,
            "evidence": result.evidence,
            "t":        elapsed(),
        }

        # If a hard failure occurs on identity or integrity, skip remaining checks
        # but still run behavior for a compromised-mode detection
        if result.status == "fail" and name in ("identity",):
            break

    # Verdict
    verdict_dict = fuse(results)

    yield {
        "event":      "verdict",
        "verdict":    verdict_dict["verdict"],
        "reason":     verdict_dict["reason"],
        "score":      verdict_dict["score"],
        "t":          elapsed(),
        "session_id": session_id,
        "results":    {k: v.to_dict() for k, v in results.items()},
    }
