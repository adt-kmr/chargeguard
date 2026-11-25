"""
Benchmark the on-device Llama advisor on real advisor inputs and check its output is grounded.

    python advisor/bench_llama.py            # run inside the ExecuTorch environment (WSL or the Pi)

Writes benchmarks/results/llama_advisor_<arch>-<os>.json with, per case: prompt and generated
tokens, time to first token, prefill and decode rates, wall time, the explanation Llama wrote,
and whether it passed the grounding check (otherwise the grounded template is used).
"""
from __future__ import annotations

import json
import platform
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from advisor.engines import Advisor  # noqa: E402
from threatintel import analyse_message, analyse_url  # noqa: E402

CHECK = lambda s, d: {"status": s, "detail": d}  # noqa: E731
CASES = {
    "healthy": {"verdict": "green", "reason": "All checks passed",
                "checks": {"identity": CHECK("pass", "TPM quote verified for CG-CHARGER-001"),
                           "integrity": CHECK("pass", "Firmware v2.1.0 signed by vendor; PCR0 matches golden value"),
                           "weaknesses": CHECK("pass", "No known CVEs for this firmware"),
                           "behavior": CHECK("pass", "Traffic matches the charger baseline")}, "enforcement": None},
    "tampered": {"verdict": "red", "reason": "Firmware hash not in vendor registry",
                 "checks": {"identity": CHECK("pass", "TPM quote verified for CG-CHARGER-001"),
                            "integrity": CHECK("fail", "Firmware hash not in vendor registry; vendor signature invalid"),
                            "weaknesses": CHECK("skip", "Unaudited firmware"),
                            "behavior": CHECK("pass", "Traffic matches the charger baseline")},
                 "enforcement": {"action": "deny"}},
    "vulnerable": {"verdict": "amber", "reason": "Authentic firmware with known vulnerabilities",
                   "checks": {"identity": CHECK("pass", "TPM quote verified"),
                              "integrity": CHECK("pass", "Firmware v1.8.3 signed by vendor"),
                              "weaknesses": {"status": "warn", "detail": "5 known CVEs",
                                             "evidence": {"cves": [
                                                 {"id": "CVE-2021-3711", "component": "openssl 1.1.1k", "fixed_in": "1.1.1l", "severity": "critical"},
                                                 {"id": "CVE-2022-37434", "component": "zlib 1.2.11", "fixed_in": "1.2.12", "severity": "critical"}]}},
                              "behavior": CHECK("pass", "Traffic matches the charger baseline")}, "enforcement": None},
    "compromised": {"verdict": "red", "reason": "Port scan detected during charging",
                    "checks": {"identity": CHECK("pass", "TPM quote verified"), "integrity": CHECK("pass", "Firmware v2.1.0 signed"),
                               "weaknesses": CHECK("pass", "No known CVEs"),
                               "behavior": {"status": "fail", "detail": "port_scan: 6 unexpected ports to 192.168.1.20",
                                            "evidence": {"anomalies": [{"rule": "port_scan", "severity": "critical"}]}}},
                    "enforcement": {"action": "isolate"}},
}
THREATS = {
    "scam_sms": analyse_message("URGENT: Your EV charging account is suspended. Verify payment now at "
                                "chargepoint-billing.top/verify or lose your balance"),
    "phishing_link": analyse_url("https://chargepoint-pay.top/verify?station=CG-001"),
    "genuine_link": analyse_url("https://www.tatapower.com/ez-charge"),
}


def main():
    adv = Advisor()
    llama = adv.llama
    assert llama._local_available(), "model or runner missing (run advisor/export_llama.sh)"
    t0 = time.perf_counter()
    llama._generate_python(llama.chat_prompt("Reply OK.", {"ping": 1}))   # load + warm up
    load_s = time.perf_counter() - t0
    jobs = [(k, lambda c=c: adv.explain(c)) for k, c in CASES.items()] + \
           [(k, lambda t=t: adv.explain_threat(t)) for k, t in THREATS.items()]
    rows = []
    for name, run in jobs:
        t = time.perf_counter()
        a = run()
        wall = time.perf_counter() - t
        s = llama.last_stats
        pre_ms = max(s["prompt_eval_end_ms"] - s["inference_start_ms"], 1)
        # decode rate from wall time after the first token (the runner's own end stamp is unreliable
        # when generation stops early)
        dec_ms = max(wall * 1000 - (s["first_token_ms"] - s["inference_start_ms"]), 1)
        row = {"case": name, "prompt_tokens": s["num_prompt_tokens"], "generated_tokens": s["num_generated_tokens"],
               "ttft_ms": s["first_token_ms"] - s["inference_start_ms"],
               "prefill_tok_s": round(s["num_prompt_tokens"] / pre_ms * 1000, 1),
               "decode_tok_s": round(max(s["num_generated_tokens"] - 1, 1) / dec_ms * 1000, 1),
               "wall_s": round(wall, 2), "llama_text_used": a.fallback_reason is None,
               "rejected_because": a.fallback_reason, "engine": a.engine, "summary": a.summary, "steps": a.steps}
        rows.append(row)
        print(f"{name:14s} prompt {row['prompt_tokens']:4d}  gen {row['generated_tokens']:3d}  ttft {row['ttft_ms']:5.0f} ms  "
              f"prefill {row['prefill_tok_s']:6.1f}  decode {row['decode_tok_s']:5.1f} tok/s  wall {wall:4.1f} s  "
              f"used={row['llama_text_used']}\n    {a.summary}")
    med = lambda k: sorted(r[k] for r in rows)[len(rows) // 2]  # noqa: E731
    cpu = next((ln.split(":", 1)[1].strip() for ln in open("/proc/cpuinfo") if ln.startswith("model name")), platform.processor())
    result = {"model": "Llama-3.2-1B-Instruct SpinQuant INT4/EO8", "pte": "models/llama3_2_1b.pte",
              "pte_bytes": Path(llama.model).stat().st_size, "runtime": "ExecuTorch 1.6.0 TextLLMRunner, XNNPACK",
              "host": {"machine": platform.machine(), "system": platform.system(), "release": platform.release(), "cpu": cpu},
              "role": "Llama writes the explanation; risk and steps come from the grounded rules",
              "load_and_warmup_s": round(load_s, 2),
              "peak_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024),
              "median": {k: med(k) for k in ("ttft_ms", "prefill_tok_s", "decode_tok_s", "wall_s")},
              "llama_text_accepted": f"{sum(r['llama_text_used'] for r in rows)}/{len(rows)}",
              "cases": rows}
    out = ROOT / "benchmarks" / "results" / f"llama_advisor_{platform.machine().lower()}-{platform.system().lower()}.json"
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k != "cases"}, indent=2))


if __name__ == "__main__":
    main()
