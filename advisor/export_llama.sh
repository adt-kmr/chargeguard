#!/usr/bin/env bash
# Export Llama 3.2 1B Instruct (4-bit SpinQuant) to an ExecuTorch program for the advisor.
#
# Runs on Linux (WSL on Windows, or the Raspberry Pi itself). Prerequisites:
#   1. Accept the Llama 3.2 licence for meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8
#      on Hugging Face with your own account.
#   2. Log in on this machine:  hf auth login
#   3. An environment with executorch==1.6.0 (see advisor/README.md).
#
# Output (git-ignored): models/llama3_2_1b.pte and models/tokenizer.model
#
#   bash advisor/export_llama.sh
set -euo pipefail

REPO="meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/models/src/llama3_2_1b_spinquant"
OUT="$ROOT/models"
mkdir -p "$SRC" "$OUT"

if ! hf auth whoami >/dev/null 2>&1; then
  echo "Not logged in to Hugging Face. Run 'hf auth login' with your own token, after accepting"
  echo "the Llama 3.2 licence at https://huggingface.co/$REPO" >&2
  exit 2
fi

echo ">> downloading $REPO (about 1.1 GB)"
hf download "$REPO" consolidated.00.pth params.json tokenizer.model --local-dir "$SRC"

echo ">> exporting to ExecuTorch (XNNPACK, SpinQuant 4-bit weights, 8-bit dynamic activations)"
CONFIG="$(python -c 'import os, executorch.examples.models.llama as m; print(os.path.join(os.path.dirname(m.__file__), "config", "llama_xnnpack_spinquant.yaml"))')"
[ -f "$CONFIG" ] || { echo "ExecuTorch SpinQuant config not found at $CONFIG" >&2; exit 3; }
python -m executorch.extension.llm.export.export_llm \
  --config "$CONFIG" \
  +base.model_class="llama3_2" \
  +base.checkpoint="$SRC/consolidated.00.pth" \
  +base.params="$SRC/params.json" \
  +export.output_name="$OUT/llama3_2_1b.pte"

cp "$SRC/tokenizer.model" "$OUT/tokenizer.model"
ls -lh "$OUT/llama3_2_1b.pte" "$OUT/tokenizer.model"
echo ">> done. The advisor picks these up automatically (advisor/engines.py)."
