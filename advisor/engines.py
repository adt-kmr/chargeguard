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
        elif status.get("behavior") == "fail" and any(a.get("rule") == "malicious-payment-qr" for a in _anomalies(ctx)):
            qr = next(a for a in _anomalies(ctx) if a.get("rule") == "malicious-payment-qr")
            summary = (f"The charger's screen is showing a payment QR code that leads to a fake payment site "
                       f"({qr.get('peer')}). Drivers who scan it could lose card details, so the charger was isolated.")
            risk = "QR-code payment fraud ('quishing') at public chargers steals card details and money."
            steps = ["Keep the charger out of service and inspect the screen and casing for stickers or tampering.",
                     "Restore the screen content and firmware from the vendor, then re-verify the charger.",
                     "Warn drivers on site to pay only through the operator's official app."]
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

    def explain_threat(self, threat: dict) -> Advisory:
        t0 = time.perf_counter()
        f = _threat_facts(threat)
        bad = f["verdict"] in ("malicious", "phishing")
        if f["type"] == "link":
            if bad:
                why = "; ".join(f["rules"]) or "its address looks like known phishing sites"
                summary = f"Do not open this link. {f['host']} is very likely a fake page ({why})."
                steps = ["Do not enter card details, passwords or one-time codes on this site.",
                         "Pay only through the charging operator's official app or the charger's own payment terminal.",
                         "If it came from a QR sticker on a charger, report the charger to the site operator."]
                risk = "Fake payment and login pages steal card details and account access."
            else:
                summary = (f"{f['host']} looks legitimate"
                           + (" and is on ChargeGuard's list of known official sites." if f.get("known_good_domain") else "."))
                steps = ["Still check the address bar before entering payment details."]
                risk = "Low."
        else:
            link = f.get("link")
            if bad:
                parts = []
                if f["message_score"] >= 0.5:
                    parts.append("its wording matches common scam messages ("
                                 + ", ".join(s for s in f["message_signals"][:3]) + ")")
                if link and link["verdict"] == "phishing":
                    parts.append(f"it links to {link['host']}, which looks like a fake site")
                summary = "This message is very likely a scam: " + " and ".join(parts or ["it matches known scam patterns"]) + "."
                steps = ["Do not reply, call back or open the link.",
                         "Check your account only in the official app or website you normally use.",
                         "Delete the message, or report it as spam to your mobile operator."]
                risk = "Scam messages pressure you into paying or sharing codes and card details."
            else:
                summary = "This message does not look like a scam."
                steps = ["Even so, never share one-time codes or card details by message."]
                risk = "Low."
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
        self._py_runner = None                 # ExecuTorch Python TextLLMRunner, created on first use
        self.last_stats: dict = {}

    @staticmethod
    def _python_runner_available() -> bool:
        import importlib.util
        try:
            return importlib.util.find_spec("executorch.extension.llm.runner") is not None
        except ModuleNotFoundError:
            return False

    def available(self) -> bool:
        if not (Path(self.model).exists() and Path(self.tokenizer).exists()):
            return False
        return self._python_runner_available() or Path(self.runner).exists()

    SYSTEM_CHARGER = ("You are ChargeGuard's on-device security advisor for EV charging site operators. "
                      "Explain the verdict in plain language for a non-expert, then give at most three "
                      "numbered remediation steps. Use only the facts provided. Do not invent CVEs, "
                      "versions or events. Reply as JSON: {\"summary\": str, \"risk\": str, \"steps\": [str]}.")
    SYSTEM_THREAT = ("You are ChargeGuard's on-device safety assistant for EV drivers and site staff. "
                     "A message or link was checked by local detectors. Explain in plain, calm language "
                     "whether it is safe and why, then give at most three numbered actions. Use only the "
                     "facts provided; never invent links, companies or amounts. Reply as JSON: "
                     "{\"summary\": str, \"risk\": str, \"steps\": [str]}.")

    @staticmethod
    def chat_prompt(system: str, facts: dict) -> str:
        return ("<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n" + system +
                "<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n" + json.dumps(facts) +
                "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n")

    def prompt(self, ctx: dict) -> str:
        facts = {"verdict": ctx.get("verdict"), "reason": ctx.get("reason"),
                 "checks": {k: {"status": v.get("status"), "detail": v.get("detail")}
                            for k, v in ctx.get("checks", {}).items()},
                 "cves": _cves(ctx), "anomalies": _anomalies(ctx),
                 "enforcement": ctx.get("enforcement")}
        return self.chat_prompt(self.SYSTEM_CHARGER, facts)

    def _generate_python(self, prompt: str) -> str:
        """ExecuTorch's in-process Python runner (executorch.extension.llm.runner)."""
        from executorch.extension.llm.runner import GenerationConfig, TextLLMRunner
        if self._py_runner is None:
            self._py_runner = TextLLMRunner(self.model, self.tokenizer)
        cfg = GenerationConfig()
        cfg.max_new_tokens = self.max_tokens
        cfg.temperature = 0.0
        cfg.echo = False
        cfg.num_bos = 0                         # the chat prompt already starts with <|begin_of_text|>
        pieces: list[str] = []
        stats: dict = {}

        def on_stats(s):
            for k in ("num_prompt_tokens", "num_generated_tokens", "inference_start_ms",
                      "prompt_eval_end_ms", "inference_end_ms", "first_token_ms"):
                if hasattr(s, k):
                    stats[k] = getattr(s, k)
        try:
            self._py_runner.generate(prompt, cfg, token_callback=pieces.append, stats_callback=on_stats)
        finally:
            self._py_runner.reset()
        self.last_stats = stats
        return "".join(pieces)

    def _generate_binary(self, prompt: str) -> str:
        """ExecuTorch's C++ llama_main runner, if built for this machine."""
        proc = subprocess.run([self.runner, f"--model_path={self.model}", f"--tokenizer_path={self.tokenizer}",
                               f"--prompt={prompt}", f"--seq_len={self.max_tokens + 900}", "--temperature=0"],
                              capture_output=True, text=True, timeout=self.timeout_s)
        if proc.returncode != 0:
            raise RuntimeError(f"runner failed (code {proc.returncode})")
        return proc.stdout

    def _generate(self, prompt: str) -> Advisory:
        t0 = time.perf_counter()
        text = self._generate_python(prompt) if self._python_runner_available() else self._generate_binary(prompt)
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise RuntimeError("model output contained no JSON object")
        out = json.loads(m.group(0))
        return Advisory(self.name, out["summary"], list(out.get("steps", []))[:3], out.get("risk", ""),
                        round((time.perf_counter() - t0) * 1000, 1))

    def explain(self, ctx: dict) -> Advisory:
        return self._generate(self.prompt(ctx))

    def explain_threat(self, threat: dict) -> Advisory:
        return self._generate(self.chat_prompt(self.SYSTEM_THREAT, _threat_facts(threat)))


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

    def explain_threat(self, threat: dict) -> Advisory:
        """Explain a threatintel result (analyse_message / analyse_url output)."""
        if self.llama.available():
            try:
                return self.llama.explain_threat(threat)
            except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, OSError) as e:
                adv = self.template.explain_threat(threat)
                adv.fallback_reason = f"Llama advisor unavailable for this run: {e}"
                return adv
        adv = self.template.explain_threat(threat)
        adv.fallback_reason = "Llama model not installed on this node (models/llama3_2_1b.pte)"
        return adv


def _threat_facts(t: dict) -> dict:
    """Compact, model-friendly facts from a threatintel result (message or URL)."""
    if "message" in t:
        m, link = t["message"], t.get("worst_link")
        return {"type": "message", "verdict": t["verdict"], "message_score": m["score"],
                "message_signals": [s["feature"] for s in m["signals"]],
                "link": None if not link else {"host": link["details"]["host"], "verdict": link["verdict"],
                                               "score": link["score"], "rules": link["rules"]}}
    return {"type": "link", "verdict": t["verdict"], "host": t["details"]["host"], "score": t["score"],
            "rules": t["rules"], "known_good_domain": t["details"].get("known_good_domain")}
