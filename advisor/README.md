# advisor — plain-language explanations on the device

Turns every signed charger verdict, and every message or link a driver checks,
into a short explanation and at most three remediation steps for a non-expert.

| Part | Produced by | Runtime |
|---|---|---|
| **Explanation** (two plain sentences) | Llama 3.2 1B Instruct, 4-bit SpinQuant, when the model is installed and its text passes the checks below | ExecuTorch 1.6, XNNPACK backend (KleidiAI kernels on Arm), CPU |
| **Risk and remediation steps** | Grounded rule engine, always | Python, deterministic |
| **Everything**, as fallback | Grounded rule engine, when Llama is absent, slow or its text is rejected | Python, deterministic |

**Why this split.** A 1B model writes fluent explanations but, in our runs, was
unreliable at structured output (4 of 6 JSON replies malformed) and invented
remediation ("report the incident to ChargePoint", "isolate the port"). Advice
that an operator acts on must not be invented, so it comes from rules; Llama
rewrites the grounded finding in plain words.

**Grounding.** The model sees only a compact set of facts already established by
the checks: the verdict, the grounded finding, the failed checks with their
detail, the names of the checks that passed, CVE identifiers, anomaly rules and
the action taken. Before its text is shown, `LlamaExecuTorchAdvisor.clean`
rejects it if it

- cites a CVE, version number or IP address that is not in the facts;
- describes a check that passed (or was not run) as a problem, unless negated ("no known vulnerabilities");
- calls a red, amber, scam or phishing result safe, or plays it down ("not exploitable", "no risk");
- describes a threat when the verdict is green or legitimate.

These rules are covered by `tests/test_advisor_grounding.py`. In our runs they
caught, among others, "The message is safe. The main reason is that the link
is a phishing attempt." and CVEs described as "not exploitable".

**Labelling.** The engine that produced each part is reported with the advisory,
in the dashboard and in the signed evidence report (`engine`, `steps_source`,
`fallback_reason`, token statistics).

**Timing.** The verdict and any enforcement are decided and applied before the
advisor runs, so generation never delays a decision. The signed report waits for
the explanation (a few seconds); the Driver Safety Check shows the verdict and
steps at once and fills in Llama's explanation when it is ready.

## Measured

`python advisor/bench_llama.py` (inside the ExecuTorch environment) runs seven
real advisor inputs and writes `benchmarks/results/llama_advisor_<arch>-<os>.json`.
Development host (Intel Core i9-14900HX, WSL2), not a Raspberry Pi:

| | Mains power | Battery |
|---|---|---|
| Decode | about 25 tok/s | about 12.5 tok/s |
| Prefill | 260–290 tok/s | about 140 tok/s |
| Time to first token | 0.6–0.8 s | about 1.2 s |
| One explanation (30–60 tokens) | 1.5–3.5 s | 2.5–6 s |
| Resident memory | 1.8 GB | 1.8 GB |
| Program size | 1.08 GB | |

The committed file is the battery run. The Pi 5 decode ceiling from memory
bandwidth is about 16 tok/s (17.1 GB/s ÷ 1.08 GB); `bench_llama.py` will
produce the Arm figures there.

## Enabling Llama (ExecuTorch)

1. Accept the Llama 3.2 licence on Hugging Face with your own account, for
   [`meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8`](https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8).
2. On a Linux machine (WSL on Windows, or the Raspberry Pi), create the ExecuTorch environment:
   ```bash
   uv venv ~/chargeguard-et --python 3.12 && source ~/chargeguard-et/bin/activate
   uv pip install --index-strategy unsafe-best-match \
     --extra-index-url https://download.pytorch.org/whl/cpu executorch==1.6.0 huggingface_hub
   ```
3. Log in with your own token, then export:
   ```bash
   hf auth login
   bash advisor/export_llama.sh        # writes models/llama3_2_1b.pte and models/tokenizer.model
   ```
4. On Linux (the Pi), run ChargeGuard from that environment: the advisor uses
   ExecuTorch's in-process Python runner (`executorch.extension.llm.runner.TextLLMRunner`),
   after registering the Llama custom kernels (`custom_sdpa`, `fast_hadamard_transform`)
   the SpinQuant program needs. If the Python runner is not available, a
   compiled `llama_main` at `models/llama_main`, or at `CHARGEGUARD_LLAMA_RUNNER`, is used instead.
5. On Windows, where the node's Python has no ExecuTorch, start the local Llama
   service inside WSL and run the node as usual; it is found on `127.0.0.1:8765`
   (or `CHARGEGUARD_LLAMA_URL`):
   ```bash
   source ~/chargeguard-et/bin/activate
   python advisor/llama_service.py --warm
   ```

`models/` is git-ignored: the weights are about 1 GB and are covered by Meta's licence.

## Why SpinQuant

Meta's measurements for Llama 3.2 1B on an Arm phone CPU with ExecuTorch and KleidiAI, against BF16:

| | Decode | Time to first token | Prefill | Model size | Peak memory |
|---|---|---|---|---|---|
| BF16 baseline | 19.2 tok/s | 1.0 s | 60.3 tok/s | 2,358 MB | 3,185 MB |
| SpinQuant 4-bit | 50.2 tok/s (2.6×) | 0.3 s (−76.9%) | 260.5 tok/s (4.3×) | 1,083 MB (−54.1%) | 1,921 MB (−39.7%) |

The figures are Meta's, from the ExecuTorch Llama README, for an Arm phone CPU.
Our own development-host figures are above; Raspberry Pi 5 figures come next.
