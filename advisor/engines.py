"""
Advisor engines: turn a signed verdict and its findings into a plain-language
explanation and remediation steps for a non-expert operator.

  LlamaExecuTorchAdvisor   Llama 3.2 1B Instruct exported to an ExecuTorch .pte,
                           run on the Arm CPU by ExecuTorch's llama runner.
  GroundedTemplateAdvisor  Deterministic, rule-based. Uses only facts present in
                           the evidence. Used when no model is installed, and as
                           the fallback if generation fails or times out.

The engine that produced each advisory is always reported, so the dashboard
never presents template output as model output.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Advisory:
    engine: str
    summary: str
    steps: list[str] = field(default_factory=list)
    risk: str = ""
    latency_ms: float = 0.0
    fallback_reason: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _cves(ctx: dict) -> list[dict]:
    return ctx.get("checks", {}).get("weaknesses", {}).get("evidence", {}).get("cves", []) or []


def _anomalies(ctx: dict) -> list[dict]:
    return ctx.get("checks", {}).get("behavior", {}).get("evidence", {}).get("anomalies", []) or []


class GroundedTemplateAdvisor:
    name = "rule-based (grounded templates)"

    def explain(self, ctx: dict) -> Advisory:
        t0 = time.perf_counter()
        checks = ctx.get("checks", {})
        status = {k: v.get("status") for k, v in checks.items()}
        verdict = ctx.get("verdict")
        device = checks.get("identity", {}).get("evidence", {}).get("device_id", "the charger")
        steps: list[str] = []

        if status.get("identity") == "fail":
            summary = (f"ChargeGuard could not confirm that this device is the enrolled charger {device}. "
                       "It may be a counterfeit or cloned unit, so it was not allowed to charge.")
            risk = "A rogue device on the site network can steal sessions or attack other equipment."
            steps = ["Keep the charger disconnected from the site network.",
                     "Physically inspect the unit and compare its serial number with the asset register.",
                     "Contact the charger vendor before re-enrolling any device under this ID."]
        elif status.get("integrity") == "fail":
            fw = checks.get("integrity", {}).get("evidence", {})
            summary = (f"The charger is running firmware that the vendor never signed "
                       f"(reported version {fw.get('version', 'unknown')}). The software was modified after release.")
            risk = "Modified firmware can bypass safety limits or give an attacker control of the charger."
            steps = ["Do not authorise charging on this unit.",
                     "Reflash the latest vendor-signed firmware through the vendor's update tool.",
                     "Keep the evidence report: it records the measured firmware and why it failed."]
        elif status.get("behavior") == "fail":
            rules = sorted({a.get("rule") for a in _anomalies(ctx) if a.get("rule")})
            summary = ("The charger started communicating in ways a healthy charger never does "
                       f"({', '.join(rules) or 'abnormal traffic'}). It was isolated to protect the network.")
            risk = "A compromised charger can be used to reach other devices or leak data."
            steps = ["Leave the charger isolated; the session was stopped safely.",
                     "Collect the evidence report and network capture for your security team.",
                     "Reflash vendor firmware and rotate any credentials stored on the unit before reconnecting."]
        elif verdict == "amber":
            cves = _cves(ctx)
            worst = max(cves, key=lambda c: c.get("cvss", 0), default={})
            comps = sorted({c.get("component") for c in cves})
            summary = (f"The charger is genuine and its firmware is authentic, but it contains {len(cves)} "
                       f"known vulnerabilities in {', '.join(comps)}. The most serious is {worst.get('id')} "
                       f"(CVSS {worst.get('cvss')}).")
            risk = "Known vulnerabilities can be exploited remotely even though the firmware is genuine."
            fixed = sorted({c.get("fixed_in") for c in cves if c.get("fixed_in")})
            steps = ["Charging can continue, but schedule a firmware upgrade.",
                     f"Ask the vendor for a release that includes: {', '.join(fixed)}.",
                     "Re-verify the charger after the upgrade; it should then show green."]
        else:
            summary = ("This charger is the enrolled device, runs authentic vendor firmware with no known "
                       "vulnerabilities, and its network behaviour matches its baseline.")
            risk = "No action needed."
            steps = ["Charging is authorised.", "ChargeGuard keeps monitoring the session for changes in behaviour."]

        return Advisory(self.name, summary, steps, risk, round((time.perf_counter() - t0) * 1000, 3))


class LlamaExecuTorchAdvisor:
    """Runs ExecuTorch's llama runner (examples/models/llama, `llama_main`) on the CPU."""
    name = "Llama 3.2 1B Instruct · ExecuTorch (XNNPACK) · Arm CPU"

    def __init__(self, model: str | None = None, tokenizer: str | None = None,
                 runner: str | None = None, timeout_s: float = 25.0, max_tokens: int = 220):
        self.model = model or os.environ.get("CHARGEGUARD_LLAMA_PTE", str(ROOT / "models" / "llama3_2_1b.pte"))
        self.tokenizer = tokenizer or os.environ.get("CHARGEGUARD_LLAMA_TOKENIZER",
                                                     str(ROOT / "models" / "tokenizer.model"))
        self.runner = runner or os.environ.get("CHARGEGUARD_LLAMA_RUNNER", str(ROOT / "models" / "llama_main"))
        self.timeout_s, self.max_tokens = timeout_s, max_tokens

    def available(self) -> bool:
        return all(Path(p).exists() for p in (self.model, self.tokenizer, self.runner))

    def prompt(self, ctx: dict) -> str:
        facts = {"verdict": ctx.get("verdict"), "reason": ctx.get("reason"),
                 "checks": {k: {"status": v.get("status"), "detail": v.get("detail")}
                            for k, v in ctx.get("checks", {}).items()},
                 "cves": _cves(ctx), "anomalies": _anomalies(ctx),
                 "enforcement": ctx.get("enforcement")}
        system = ("You are ChargeGuard's on-device security advisor for EV charging site operators. "
                  "Explain the verdict in plain language for a non-expert, then give at most three "
                  "numbered remediation steps. Use only the facts provided. Do not invent CVEs, "
                  "versions or events. Reply as JSON: {\"summary\": str, \"risk\": str, \"steps\": [str]}.")
        return ("<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n" + system +
                "<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n" + json.dumps(facts) +
                "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n")

    def explain(self, ctx: dict) -> Advisory:
        t0 = time.perf_counter()
        proc = subprocess.run([self.runner, f"--model_path={self.model}", f"--tokenizer_path={self.tokenizer}",
                               f"--prompt={self.prompt(ctx)}", f"--seq_len={self.max_tokens + 900}",
                               "--temperature=0"],
                              capture_output=True, text=True, timeout=self.timeout_s)
        m = re.search(r"\{.*\}", proc.stdout, re.S)
        if proc.returncode != 0 or not m:
            raise RuntimeError(f"runner failed (code {proc.returncode})")
        out = json.loads(m.group(0))
        return Advisory(self.name, out["summary"], list(out.get("steps", []))[:3], out.get("risk", ""),
                        round((time.perf_counter() - t0) * 1000, 1))


class Advisor:
    """Chooses the best available engine and always falls back safely."""

    def __init__(self):
        self.llama = LlamaExecuTorchAdvisor()
        self.template = GroundedTemplateAdvisor()

    @property
    def engine_name(self) -> str:
        return self.llama.name if self.llama.available() else self.template.name

    def explain(self, ctx: dict) -> Advisory:
        if self.llama.available():
            try:
                return self.llama.explain(ctx)
            except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, OSError) as e:
                adv = self.template.explain(ctx)
                adv.fallback_reason = f"Llama advisor unavailable for this run: {e}"
                return adv
        adv = self.template.explain(ctx)
        adv.fallback_reason = "Llama model not installed on this node (models/llama3_2_1b.pte)"
        return adv
