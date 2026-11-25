"""
Advisor engines: turn a signed verdict and its findings into a plain-language
explanation and remediation steps for a non-expert operator.

  LlamaExecuTorchAdvisor   Llama 3.2 1B Instruct exported to an ExecuTorch .pte,
                           run on the CPU by ExecuTorch's runner: in-process (Raspberry Pi),
                           or through the local Llama service (advisor/llama_service.py)
                           when the node runs on Windows and ExecuTorch lives in WSL.
  GroundedTemplateAdvisor  Deterministic, rule-based. Uses only facts present in
                           the evidence. Used when no model is installed, and as
                           the fallback if generation fails or times out.

The engine that produced each advisory is always reported, so the dashboard
never presents template output as model output.
"""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import time
import urllib.error
import urllib.request
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
    steps_source: str | None = None        # set when the steps come from another engine
    stats: dict = field(default_factory=dict)

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
            blocked = (ctx.get("enforcement") or {}).get("action") == "block"
            summary = ("The charger started communicating in ways a healthy charger never does "
                       f"({', '.join(rules) or 'abnormal traffic'}). "
                       + ("The offending traffic was blocked and the charger rate-limited." if blocked
                          else "It was isolated to protect the network."))
            risk = "A compromised charger can be used to reach other devices or leak data."
            steps = [("Keep the block in place and watch the charger's message rate; the session was stopped safely."
                      if blocked else "Leave the charger isolated; the session was stopped safely."),
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
    """Runs Llama 3.2 1B through ExecuTorch on the CPU.

    Backends, in order: the in-process Python runner (TextLLMRunner), the local Llama service
    over loopback HTTP, then ExecuTorch's C++ `llama_main` binary.
    """
    name = ("Llama 3.2 1B Instruct · ExecuTorch (XNNPACK) · "
            + ("Arm CPU" if platform.machine().lower() in ("aarch64", "arm64") else "CPU"))

    def __init__(self, model: str | None = None, tokenizer: str | None = None,
                 runner: str | None = None, timeout_s: float = 25.0, max_tokens: int = 110):
        self.model = model or os.environ.get("CHARGEGUARD_LLAMA_PTE", str(ROOT / "models" / "llama3_2_1b.pte"))
        self.tokenizer = tokenizer or os.environ.get("CHARGEGUARD_LLAMA_TOKENIZER",
                                                     str(ROOT / "models" / "tokenizer.model"))
        self.runner = runner or os.environ.get("CHARGEGUARD_LLAMA_RUNNER", str(ROOT / "models" / "llama_main"))
        self.timeout_s, self.max_tokens = timeout_s, max_tokens
        self._py_runner = None                 # ExecuTorch Python TextLLMRunner, created on first use
        self.last_stats: dict = {}
        self.service_url = os.environ.get("CHARGEGUARD_LLAMA_URL", "http://127.0.0.1:8765").rstrip("/")
        self._service_ok: tuple[float, bool] = (0.0, False)

    @staticmethod
    def _python_runner_available() -> bool:
        import importlib.util
        try:
            return importlib.util.find_spec("executorch.extension.llm.runner") is not None
        except ModuleNotFoundError:
            return False

    def _local_available(self) -> bool:
        if not (Path(self.model).exists() and Path(self.tokenizer).exists()):
            return False
        return self._python_runner_available() or Path(self.runner).exists()

    def _service_available(self) -> bool:
        """Health-check the local Llama service; the answer is cached for 15 s."""
        if not self.service_url or self.service_url.lower() == "off":
            return False
        t, ok = self._service_ok
        if time.monotonic() - t < 15:
            return ok
        try:
            with urllib.request.urlopen(self.service_url + "/health", timeout=0.5) as r:
                ok = bool(json.loads(r.read()).get("ok"))
        except (OSError, ValueError):
            ok = False
        self._service_ok = (time.monotonic(), ok)
        return ok

    def available(self) -> bool:
        return self._local_available() or self._service_available()

    # A 1B model is fluent but drifts when given many facts, and is unreliable at structured output
    # and advice. So Llama only rewrites the grounded finding in plain words, sees only the evidence
    # behind it, and its text is checked before use; risk and steps come from the grounded rules.
    SYSTEM_CHARGER = ("You explain an EV charger security result to a site operator who is not a security "
                      "expert. Rewrite the finding in two short, plain sentences: what happened and why it "
                      "matters. Use only the facts given. The checks listed as passed found no problem; never "
                      "describe them as problems. Do not give advice or steps.")
    # Stating the decision in words matters: given only a verdict label, the model called a
    # phishing link "safe" on every run; given the conclusion as a sentence, it explains it.
    SYSTEM_THREAT = ("You explain to an EV driver whether a message or link is safe. The on-device checks have "
                     "already decided; the decision is in 'conclusion'. Start with that conclusion, then give the "
                     "main reason, in two short, calm, plain sentences. Use only the facts given. Do not give "
                     "steps. Do not name any company, link or amount that is not in the facts.")

    @staticmethod
    def threat_prompt_facts(threat: dict, finding: str = "") -> dict:
        f = _threat_facts(threat)
        kind = "link" if f["type"] == "link" else "message"
        bad = threat["verdict"] != "legitimate"
        conclusion = (f"This {kind} is NOT safe: it is very likely a "
                      f"{'phishing (fake) page' if kind == 'link' else 'scam'}." if bad else f"This {kind} looks safe.")
        drop = {"verdict"} | (set() if bad else {"message_signals"})   # scam-leaning words confuse a "safe" story
        return {"conclusion": conclusion, **({"finding": finding} if finding else {}),
                **{k: v for k, v in f.items() if k not in drop}}

    CHECK_NAMES = {"identity": "identity", "integrity": "firmware integrity", "weaknesses": "known vulnerabilities",
                   "behavior": "network behaviour"}
    # words that, in the explanation, claim a problem in that check
    PROBLEM_WORDS = {"weaknesses": r"vulnerab|CVE|weakness|exploit",
                     "integrity": r"tamper|modif|unsigned|not signed|integrity (check )?fail",
                     "identity": r"spoof|clone|rogue|counterfeit|fake (charger|device)|identity (could not|failed)",
                     "behavior": r"scan|beacon|exfiltrat|flood|anomal|suspicious traffic"}

    @staticmethod
    def chat_prompt(system: str, facts: dict) -> str:
        return ("<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n" + system +
                "<|eot_id|><|start_header_id|>user<|end_header_id|>\n\nFacts: " + json.dumps(facts) +
                "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n")

    @classmethod
    def charger_facts(cls, ctx: dict, finding: str = "") -> dict:
        checks = ctx.get("checks", {})
        problems = {cls.CHECK_NAMES.get(k, k): v.get("detail") for k, v in checks.items()
                    if v.get("status") in ("fail", "warn")}
        facts = {"verdict": ctx.get("verdict"), "finding": finding or ctx.get("reason"),
                 "problems": problems,
                 "passed": [cls.CHECK_NAMES.get(k, k) for k, v in checks.items() if v.get("status") == "pass"]}
        if _cves(ctx):
            facts["cves"] = [f"{c.get('id')} in {c.get('component', '?')}" for c in _cves(ctx)][:5]
        if _anomalies(ctx):
            facts["anomalies"] = [x.get("rule") for x in _anomalies(ctx)][:5]
        action = (ctx.get("enforcement") or {}).get("action")
        if action:
            facts["action_taken"] = {"isolate": "charger isolated from the network", "deny": "charging refused",
                                     "block": "offending traffic blocked"}.get(action, action)
        return facts

    def prompt(self, ctx: dict, finding: str = "") -> str:
        return self.chat_prompt(self.SYSTEM_CHARGER, self.charger_facts(ctx, finding))

    @staticmethod
    def tidy(text: str) -> str:
        t = re.sub(r"[*#`]+", "", text)
        t = re.sub(r"^\s*(summary|explanation)\s*:\s*", "", t.strip(), flags=re.I)
        t = " ".join(t.split())
        t = re.sub(r"^(here (is|are)|below (is|are))[^:]{0,90}:\s*", "", t, flags=re.I)
        t = re.sub(r"^based on the (facts|checks)[^,]{0,40},\s*(the conclusion is that\s*)?", "", t, flags=re.I)
        t = t[:1].upper() + t[1:]   # "Here are two sentences:"
        sentences = [x for x in re.split(r"(?<=[.!?])\s+", t)
                     if not re.search(r"\b(this (version|rewrite|explanation)|the original|rewritten|in summary)\b", x, re.I)]
        return " ".join(sentences[:2]).strip()

    @classmethod
    def clean(cls, text: str, facts: dict, checks: dict | None = None) -> str:
        """Tidy the model's text and reject it if it cites, or claims, anything the evidence does not."""
        t = cls.tidy(text)
        if len(t) < 20:
            raise RuntimeError("explanation too short")
        known = json.dumps(facts)
        for pat in (r"CVE-\d{4}-\d{4,}", r"\b\d+\.\d+(?:\.\d+)+[a-z]?\b", r"\b\d{1,3}(?:\.\d{1,3}){3}\b"):
            for hit in re.findall(pat, t):
                if hit not in known:
                    raise RuntimeError(f"explanation cited '{hit}', which is not in the evidence")
        cls._check_verdict(t, str(facts.get("verdict", "")))
        for k, v in (checks or {}).items():
            if v.get("status") in ("pass", "skip") and k in cls.PROBLEM_WORDS:
                if cls._claims(cls.PROBLEM_WORDS[k], t) and not any(
                        re.search(cls.PROBLEM_WORDS[k], str(x.get("detail", "")), re.I)
                        for x in checks.values() if x.get("status") in ("fail", "warn")):
                    raise RuntimeError(f"explanation described the {cls.CHECK_NAMES[k]} check as a problem, "
                                       f"but it {'passed' if v.get('status') == 'pass' else 'was not run'}")
        return t

    NEGATED = r"\b(no|not|never|without|free of|zero|none|nothing)\b[^.]{0,40}$"

    @classmethod
    def _claims(cls, pattern: str, t: str) -> bool:
        """True if the text asserts the pattern somewhere without negating it."""
        return any(not re.search(cls.NEGATED, t[:m.start()], re.I) for m in re.finditer(pattern, t, re.I))

    @classmethod
    def _check_verdict(cls, t: str, verdict: str):
        """The explanation must agree with the verdict and must not play a risk down."""
        bad = verdict in ("red", "amber", "malicious", "scam", "phishing")
        if bad and cls._claims(r"\b(is|are|looks|seems|appears)( (completely|perfectly|totally))? (safe|legitimate|genuine|secure|trustworthy)\b", t):
            raise RuntimeError(f"explanation calls it safe, but the verdict is {verdict}")
        if bad and re.search(r"not (exploitable|dangerous|a (real )?(risk|threat|problem))|no (real )?(risk|threat|danger)|harmless", t, re.I):
            raise RuntimeError(f"explanation plays down a {verdict} verdict")
        if verdict in ("green", "legitimate") and cls._claims(r"\b(scam|phishing|malicious|fraud\w*|unsafe|compromised|attack\w*)\b", t):
            raise RuntimeError(f"explanation describes a threat, but the verdict is {verdict}")

    def _generate_python(self, prompt: str) -> str:
        """ExecuTorch's in-process Python runner (executorch.extension.llm.runner)."""
        # The SpinQuant program uses ExecuTorch's Llama kernels (custom_sdpa, fast_hadamard_transform)
        # and quantized ops; importing these modules registers them with the runtime.
        from executorch.extension.llm.custom_ops import custom_ops  # noqa: F401
        try:
            from executorch.kernels import quantized  # noqa: F401
        except ImportError:
            pass
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
        return "".join(pieces).replace("<|eot_id|>", "").replace("<|end_of_text|>", "")

    def _generate_binary(self, prompt: str) -> str:
        """ExecuTorch's C++ llama_main runner, if built for this machine."""
        proc = subprocess.run([self.runner, f"--model_path={self.model}", f"--tokenizer_path={self.tokenizer}",
                               f"--prompt={prompt}", f"--seq_len={self.max_tokens + 900}", "--temperature=0"],
                              capture_output=True, text=True, timeout=self.timeout_s)
        if proc.returncode != 0:
            raise RuntimeError(f"runner failed (code {proc.returncode})")
        return proc.stdout

    def _generate_service(self, prompt: str) -> str:
        req = urllib.request.Request(self.service_url + "/generate", method="POST",
                                     data=json.dumps({"prompt": prompt, "max_tokens": self.max_tokens}).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                out = json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Llama service error {e.code}") from e
        self.last_stats = out.get("stats", {})
        return out["text"]

    def _text(self, prompt: str) -> str:
        if self._local_available():
            return self._generate_python(prompt) if self._python_runner_available() else self._generate_binary(prompt)
        return self._generate_service(prompt)

    def explain_text(self, ctx: dict, finding: str = "") -> str:
        facts = self.charger_facts(ctx, finding)
        return self.clean(self._text(self.prompt(ctx, finding)), facts, ctx.get("checks", {}))

    def explain_threat_text(self, threat: dict, finding: str = "") -> str:
        facts = self.threat_prompt_facts(threat, finding)
        text = self._text(self.chat_prompt(self.SYSTEM_THREAT, facts))
        return self.clean(text, dict(facts, verdict=threat["verdict"]))


class Advisor:
    """Chooses the best available engine and always falls back safely."""

    def __init__(self):
        self.llama = LlamaExecuTorchAdvisor()
        self.template = GroundedTemplateAdvisor()

    @property
    def engine_name(self) -> str:
        return self.llama.name if self.llama.available() else self.template.name

    def _compose(self, base: Advisory, write) -> Advisory:
        """Llama's explanation + the grounded engine's risk and steps; the template on any failure."""
        if not self.llama.available():
            base.fallback_reason = "Llama model not installed on this node (models/llama3_2_1b.pte)"
            return base
        t0 = time.perf_counter()
        try:
            summary = write()
        except (RuntimeError, subprocess.TimeoutExpired, KeyError, OSError, ValueError) as e:
            base.fallback_reason = f"Llama explanation not used for this run: {e}"
            return base
        return Advisory(self.llama.name, summary, base.steps, base.risk,
                        round((time.perf_counter() - t0) * 1000, 1), steps_source="grounded rules",
                        stats={k: v for k, v in self.llama.last_stats.items() if isinstance(v, (int, float))})

    def explain(self, ctx: dict) -> Advisory:
        base = self.template.explain(ctx)
        return self._compose(base, lambda: self.llama.explain_text(ctx, base.summary))

    def explain_threat(self, threat: dict) -> Advisory:
        """Explain a threatintel result (analyse_message / analyse_url output)."""
        base = self.template.explain_threat(threat)
        return self._compose(base, lambda: self.llama.explain_threat_text(threat, base.summary))

    def explain_threat_fast(self, threat: dict) -> Advisory:
        """Grounded explanation only: returned instantly, Llama's text follows via explain_threat."""
        adv = self.template.explain_threat(threat)
        if self.llama.available():
            adv.fallback_reason = "Llama explanation pending"
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
