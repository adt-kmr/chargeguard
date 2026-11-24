# advisor — plain-language explanations on the device

Turns every signed charger verdict, and every message or link a driver checks,
into a short explanation and at most three remediation steps for a non-expert.

| Engine | When it runs | Runtime |
|---|---|---|
| **Llama 3.2 1B Instruct** (4-bit SpinQuant) | When `models/llama3_2_1b.pte`, `models/tokenizer.model` and the runner are present | ExecuTorch, XNNPACK backend (KleidiAI kernels on Arm), CPU |
| **Grounded templates** | Otherwise, and as the fallback if generation fails or times out | Python, deterministic |

**Grounding.** The engine never sees raw logs or free text from the charger.
It receives a compact JSON of facts already established by the checks:

- the verdict and each check's status
- CVE identifiers and fixed versions
- anomaly rules
- detector signals and rules
- enforcement steps

The system prompt forbids inventing CVEs, versions, links or amounts, and the
output must be JSON (`summary`, `risk`, `steps`).

**Labelling.** The engine that produced each advisory is reported with it, in the
dashboard and in the signed evidence report. If Llama is not installed, the UI
says "rule-based (grounded templates)" and records the reason in `fallback_reason`.

**Timing.** The advisor runs after the verdict is signed, so a slow generation
never delays the 5-second decision.

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
4. Run ChargeGuard from that environment. The advisor uses ExecuTorch's
   in-process Python runner (`executorch.extension.llm.runner.TextLLMRunner`),
   so no separate binary is needed. If the Python runner is not available, a
   compiled `llama_main` (from `examples/models/llama` in the ExecuTorch
   repository) at `models/llama_main`, or at `CHARGEGUARD_LLAMA_RUNNER`, is used instead.

`models/` is git-ignored: the weights are about 1 GB and are covered by Meta's licence.

## Why SpinQuant

Meta's measurements for Llama 3.2 1B on an Arm phone CPU with ExecuTorch and KleidiAI, against BF16:

| | Decode | Time to first token | Prefill | Model size | Peak memory |
|---|---|---|---|---|---|
| BF16 baseline | 19.2 tok/s | 1.0 s | 60.3 tok/s | 2,358 MB | 3,185 MB |
| SpinQuant 4-bit | 50.2 tok/s (2.6×) | 0.3 s (−76.9%) | 260.5 tok/s (4.3×) | 1,083 MB (−54.1%) | 1,921 MB (−39.7%) |

The figures are Meta's, from the ExecuTorch Llama README. ChargeGuard's own
tokens-per-second on the Raspberry Pi 5 will be measured and committed once
the model is exported.
