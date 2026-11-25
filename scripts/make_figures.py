"""
Generate report and video figures from the committed result files.

    python scripts/make_figures.py --out media/figures
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "benchmarks" / "results"

INK, INK2, INK3 = "#1f1b16", "#5b5348", "#9a8f80"
CREAM, CREAM2, LINE = "#faf6ef", "#f3ece1", "#ebe3d6"
CLAY, CLAY_D, CLAY_L = "#c15f3c", "#a24c2d", "#f7e9e1"
GREEN, AMBER, RED, SLATE = "#2f6b4f", "#a86a16", "#b3261e", "#5f6f78"

plt.rcParams.update({
    "font.family": ["Palatino Linotype", "Book Antiqua", "Georgia", "serif"],
    "font.size": 11, "axes.edgecolor": LINE, "axes.labelcolor": INK2, "xtick.color": INK2,
    "ytick.color": INK2, "axes.titlecolor": INK, "axes.titleweight": "bold", "axes.titlesize": 13,
    "axes.spines.top": False, "axes.spines.right": False, "figure.facecolor": "white",
    "axes.facecolor": "white", "savefig.dpi": 200, "savefig.bbox": "tight",
})


def timeline(out):
    m = json.loads((RES / "scenario_matrix.json").read_text())
    healthy = next(r for r in m if r["scenario"] == "healthy")
    windows = [("Identity (TPM attestation)", 0.0, 1.0, CLAY), ("Firmware integrity", 1.0, 2.0, SLATE),
               ("Known weaknesses", 2.0, 3.0, AMBER), ("Live behaviour", 3.0, 4.5, GREEN), ("Verdict + signing", 4.5, 5.0, INK2)]
    keys = ["identity", "integrity", "weaknesses", "behavior", None]
    fig, ax = plt.subplots(figsize=(10, 3.4))
    for i, ((name, a, b, c), k) in enumerate(zip(windows, keys)):
        y = len(windows) - 1 - i
        ax.barh(y, b - a, left=a, height=0.55, color=c, alpha=0.18, edgecolor=c)
        if k:
            ms = healthy["checks"][k]["compute_ms"]
            ax.barh(y, ms / 1000, left=a, height=0.55, color=c)
            ax.text(b + 0.04, y, f"{ms:.1f} ms measured", va="center", fontsize=9.5, color=INK2, zorder=3, bbox=dict(fc="white", ec="none", pad=1))
    ax.set_yticks(range(len(windows)), [w[0] for w in windows][::-1], fontsize=10)
    ax.set_xlim(0, 6.1); ax.set_xlabel("seconds from plug-in")
    ax.axvline(5.0, color=CLAY, lw=1.2, ls="--"); ax.text(5.03, len(windows) - 0.6, "5 s budget", color=CLAY, fontsize=9.5)
    ax.set_title("Verification schedule (shaded) and measured compute per check (solid)", loc="left")
    fig.savefig(out / "verification_timeline.png"); plt.close(fig)


def detectors(out):
    m = json.loads((RES / "threatintel_metrics.json").read_text())
    metrics = ["precision", "recall", "f1", "roc_auc"]
    labels = ["Precision", "Recall", "F1", "ROC-AUC"]
    fig, ax = plt.subplots(figsize=(8.5, 3.6))
    w = 0.36
    for i, (k, name, c) in enumerate((("sms_scam", "Scam messages (776 held-out)", CLAY),
                                      ("phishing_url", "Phishing hostnames (30,093 held-out)", SLATE))):
        vals = [m[k]["test"][x] for x in metrics]
        xs = [j + (i - .5) * w for j in range(len(metrics))]
        ax.bar(xs, vals, width=w, color=c, label=name)
        for x, v in zip(xs, vals):
            ax.text(x, v + 0.015, f"{v:.3f}", ha="center", fontsize=8.5, color=INK2)
    ax.set_xticks(range(len(metrics)), labels); ax.set_ylim(0, 1.1)
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2, fontsize=9)
    ax.set_title("On-device threat detectors: held-out test results", loc="left")
    fig.savefig(out / "detector_metrics.png"); plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(8.5, 3.4))
    for ax, k, title in ((axes[0], "sms_scam", "Scam messages"), (axes[1], "phishing_url", "Phishing hostnames")):
        c = m[k]["test"]["confusion"]
        grid = [[c["tn"], c["fp"]], [c["fn"], c["tp"]]]
        ax.imshow([[0.15, 0.6], [0.6, 0.15]], cmap=matplotlib.colors.LinearSegmentedColormap.from_list("c", [CREAM, CLAY_L]))
        for r in range(2):
            for q in range(2):
                ax.text(q, r, f"{grid[r][q]:,}", ha="center", va="center", fontsize=13, color=INK, fontweight="bold")
        ax.set_xticks([0, 1], ["predicted safe", "predicted malicious"], fontsize=9)
        ax.set_yticks([0, 1], ["actually safe", "actually malicious"], fontsize=9)
        ax.set_title(title, fontsize=11)
        for s in ax.spines.values():
            s.set_visible(False)
    fig.suptitle("Confusion matrices on the held-out test splits", x=0.02, ha="left", fontweight="bold", color=INK)
    fig.tight_layout(); fig.savefig(out / "confusion.png"); plt.close(fig)


def executorch(out):
    m = json.loads((RES / "executorch_detectors_x86_64-linux.json").read_text())
    fig, ax = plt.subplots(figsize=(7.5, 2.8))
    names = [("sms_scam", "sms_scam.pte"), ("phishing_url", "phishing_url.pte")]
    for i, (k, label) in enumerate(names):
        l = m[k]["latency_ms"]
        ax.barh(i, l["p95"] * 1000, color=CLAY_L, height=0.5, label="p95" if i == 0 else None)
        ax.barh(i, l["p50"] * 1000, color=CLAY, height=0.5, label="p50" if i == 0 else None)
        ax.text(l["p95"] * 1000 + 0.3, i, f"p50 {l['p50']*1000:.1f} µs · p95 {l['p95']*1000:.1f} µs · "
                f"{m[k]['pte_bytes']/1e6:.2f} MB · 100% decision parity", va="center", fontsize=9, color=INK2)
    ax.set_yticks([0, 1], [n for _, n in names]); ax.set_xlim(0, 40); ax.set_xlabel("microseconds per inference")
    ax.legend(frameon=False, fontsize=9, loc="lower right")
    ax.set_title("ExecuTorch 1.6 (XNNPACK) detector programs, development host", loc="left")
    fig.savefig(out / "executorch_latency.png"); plt.close(fig)


def decode_bound(out):
    """Memory-bandwidth roofline for autoregressive decode on the Pi 5."""
    bw = 4267e6 * 4                                # LPDDR4X-4267, 32-bit bus: theoretical peak bytes/s
    sizes = {"BF16 (2.36 GB)": 2.358e9, "SpinQuant 4-bit (1.08 GB)": 1.083e9}
    fig, ax = plt.subplots(figsize=(7.5, 3.0))
    for i, (k, b) in enumerate(sizes.items()):
        tps = bw / b
        ax.barh(i, tps, color=[INK3, CLAY][i], height=0.5)
        ax.text(tps + 0.3, i, f"≤ {tps:.1f} tokens/s", va="center", fontsize=10, color=INK)
    ax.set_yticks(range(len(sizes)), list(sizes)); ax.set_xlim(0, 22)
    ax.set_xlabel("theoretical decode ceiling on Raspberry Pi 5 (tokens/s = memory bandwidth / model bytes)")
    ax.set_title("Why 4-bit weights: decode is memory-bandwidth bound", loc="left")
    fig.savefig(out / "decode_bound.png"); plt.close(fig)


def _box(ax, x, y, w, h, title, sub="", fc="white", ec=LINE, tc=INK, bold=True):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06", fc=fc, ec=ec, lw=1.2))
    ax.text(x + w / 2, y + h * (0.62 if sub else 0.5), title, ha="center", va="center", fontsize=10.5,
            color=tc, fontweight="bold" if bold else "normal")
    if sub:
        ax.text(x + w / 2, y + h * 0.3, sub, ha="center", va="center", fontsize=8.3, color=INK2)


def _arrow(ax, a, b, c=INK3, text="", ls="-"):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=12, color=c, lw=1.2, ls=ls))
    if text:
        ax.text((a[0] + b[0]) / 2, (a[1] + b[1]) / 2 + 0.12, text, ha="center", fontsize=8, color=INK2)


def architecture(out):
    fig, ax = plt.subplots(figsize=(12, 6.4)); ax.set_xlim(0, 12); ax.set_ylim(0, 6.4); ax.axis("off")
    ax.add_patch(FancyBboxPatch((2.9, 0.25), 6.6, 5.85, boxstyle="round,pad=0.02,rounding_size=0.1", fc=CREAM, ec=CLAY, lw=1.6))
    ax.text(3.1, 5.85, "Edge trust node · Raspberry Pi 5 (4× Arm Cortex-A76) + TPM 2.0", fontsize=11.5, color=CLAY_D, fontweight="bold")
    _box(ax, 0.2, 3.9, 2.3, 1.5, "EV charger", "OCPP 1.6-J client\nTPM · measured boot\npayment QR screen", CLAY_L, CLAY)
    _box(ax, 0.2, 1.4, 2.3, 1.3, "Site network", "flows exported by\nbridge / switch tap", "white")
    _box(ax, 3.2, 4.25, 2.5, 1.1, "Inline OCPP gateway", "transcript · attestation\nauthorisation gate")
    _box(ax, 3.2, 2.7, 2.5, 1.1, "Flow collector", "IPFIX-style records")
    _box(ax, 6.1, 4.55, 1.55, 0.8, "C1 Identity", "")
    _box(ax, 7.75, 4.55, 1.55, 0.8, "C2 Integrity", "")
    _box(ax, 6.1, 3.6, 1.55, 0.8, "C3 Weakness", "")
    _box(ax, 7.75, 3.6, 1.55, 0.8, "C4 Behaviour", "")
    _box(ax, 6.1, 2.45, 3.2, 0.9, "C5 Trust engine → verdict", "red / amber / green + reason", CLAY_L, CLAY)
    _box(ax, 3.2, 1.05, 2.0, 1.15, "Threat detectors", "scam SMS · phishing URL\nExecuTorch .pte")
    _box(ax, 5.4, 1.05, 1.9, 1.15, "Advisor", "Llama 3.2 1B\nExecuTorch · KleidiAI")
    _box(ax, 7.5, 1.05, 1.8, 1.15, "Evidence C6/C7", "signed report\n17 controls")
    _box(ax, 10.0, 3.9, 1.8, 1.5, "Dashboard", "live WebSocket\n3D scene")
    _box(ax, 10.0, 1.4, 1.8, 1.4, "Enforcement", "remote stop\nquarantine · nftables")
    _box(ax, 10.0, 0.25, 1.8, 0.85, "Audit (offline)", "SBOM · CVEs once per\nfirmware hash", "white")
    _arrow(ax, (2.5, 4.7), (3.2, 4.8), CLAY, "OCPP")
    _arrow(ax, (2.5, 2.0), (3.2, 3.1), INK3, "flows")
    _arrow(ax, (5.7, 4.8), (6.1, 4.95)); _arrow(ax, (5.7, 3.25), (7.75, 3.95))
    _arrow(ax, (7.7, 3.6), (7.7, 3.35))
    _arrow(ax, (9.3, 2.9), (10.0, 4.3), CLAY); _arrow(ax, (9.3, 2.75), (10.0, 2.2), RED)
    _arrow(ax, (8.4, 2.45), (8.4, 2.2)); _arrow(ax, (6.35, 2.45), (6.35, 2.2))
    fig.savefig(out / "architecture.png"); plt.close(fig)


def hardware(out):
    fig, ax = plt.subplots(figsize=(12, 4.6)); ax.set_xlim(0, 12); ax.set_ylim(0, 4.6); ax.axis("off")
    _box(ax, 0.2, 1.2, 2.8, 2.4, "Charger controller", "Raspberry Pi (or Cortex-M)\nSPI TPM 2.0 · MCUboot / wolfBoot\nOCPP agent · screen QR", CLAY_L, CLAY)
    _box(ax, 4.2, 0.7, 3.6, 3.4, "Edge trust node", "Raspberry Pi 5 · 4× Cortex-A76 @ 2.4 GHz\nSPI TPM 2.0 (tpm2-tss)\nLlama 3.2 1B · ExecuTorch + KleidiAI\nnetwork bridge + nftables\noptional AI HAT+ (Hailo NPU)", CREAM, CLAY)
    _box(ax, 9.0, 2.4, 2.8, 1.2, "Site switch / CSMS", "upstream OCPP backend")
    _box(ax, 9.0, 0.7, 2.8, 1.2, "Operator dashboard", "laptop or tablet")
    _arrow(ax, (3.0, 2.4), (4.2, 2.4), CLAY, "Ethernet (inline)")
    _arrow(ax, (7.8, 3.0), (9.0, 3.0), INK3, "forwarded OCPP")
    _arrow(ax, (7.8, 1.3), (9.0, 1.3), INK3, "WebSocket UI")
    ax.text(6.0, 4.3, "Inline placement: every packet and OCPP frame of the charger passes the node", ha="center", fontsize=10, color=INK2)
    fig.savefig(out / "hardware_deployment.png"); plt.close(fig)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="media/figures")
    out = Path(ap.parse_args().out); out.mkdir(parents=True, exist_ok=True)
    for f in (timeline, detectors, executorch, decode_bound, architecture, hardware):
        f(out); print("figure:", f.__name__)
