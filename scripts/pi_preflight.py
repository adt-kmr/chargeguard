"""
Readiness check for a Raspberry Pi running the ChargeGuard node or the demo charger.

    python scripts/pi_preflight.py --role node
    python scripts/pi_preflight.py --role charger

Each line is PASS, WARN (works, with a limitation) or FAIL (fix before going live).
Exit code 1 if anything failed. Safe to run anywhere; it only reads.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
RESULTS: list[tuple[str, str, str]] = []


def report(status: str, what: str, detail: str = ""):
    RESULTS.append((status, what, detail))


def has(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def mem_gb() -> float:
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemTotal"):
                return int(line.split()[1]) / 1024 / 1024
    except OSError:
        pass
    return 0.0


def check_platform():
    m = platform.machine()
    report("PASS" if m in ("aarch64", "arm64") else "WARN", "CPU architecture", m)
    try:
        model = Path("/proc/device-tree/model").read_text().strip("\0")
        report("PASS" if "Raspberry Pi 5" in model else "WARN", "board", model)
    except OSError:
        report("WARN", "board", "not a Raspberry Pi (no /proc/device-tree/model)")
    py = sys.version_info
    report("PASS" if py >= (3, 11) else "FAIL", "Python", platform.python_version())


def check_tpm(role: str):
    dev = Path("/dev/tpmrm0")
    report("PASS" if dev.exists() else "FAIL", "TPM device /dev/tpmrm0",
           "present" if dev.exists() else "missing: dtparam=spi=on and dtoverlay=tpm-slb9670 in /boot/firmware/config.txt, then reboot")
    if dev.exists() and not os.access(dev, os.R_OK | os.W_OK):
        report("FAIL", "TPM access", "add this user to group 'tss'")
    report("PASS" if has("tpm2_pytss") else ("FAIL" if role == "charger" else "WARN"), "tpm2-pytss",
           "installed" if has("tpm2_pytss") else "pip install tpm2-pytss (needs libtss2-dev)")
    if dev.exists() and has("tpm2_pytss") and role == "charger":
        try:
            os.environ.setdefault("CHARGEGUARD_TPM_TCTI", "device:/dev/tpmrm0")
            from attestation.backends.tss import TSSBackend
            from attestation.config import AttestationConfig
            t = TSSBackend(AttestationConfig(), startup=False)
            t.reset_pcr(23)
            t.extend_pcr(23, b"preflight")
            from attestation import PCRSelection
            t.quote(t.get_random(32), PCRSelection(indices=(23,)))
            t.reset_pcr(23)
            report("PASS", "TPM reset/extend/quote on PCR 23", "measured launch will work")
        except Exception as e:  # noqa: BLE001 - report anything the TPM stack raises
            report("FAIL", "TPM reset/extend/quote on PCR 23", f"{type(e).__name__}: {e}")


def check_node():
    report("PASS" if mem_gb() >= 7 else ("WARN" if mem_gb() >= 3.5 else "FAIL"), "memory",
           f"{mem_gb():.1f} GB (8 GB recommended with the Llama advisor, 4 GB without)")
    for mod in ("fastapi", "uvicorn", "ocpp", "websockets", "cryptography", "numpy", "sklearn", "yaml"):
        report("PASS" if has(mod) else "FAIL", f"python module {mod}", "" if has(mod) else "pip install -r requirements.txt")
    nft = shutil.which("nft")
    report("PASS" if nft else "FAIL", "nftables", nft or "apt install nftables")
    if nft and os.environ.get("CHARGEGUARD_FIREWALL") in ("check", "apply"):
        from integrations.behavior.firewall import Firewall
        cmds, _ = Firewall("check").commands(["10.20.0.15"], ["203.0.113.66"])
        p = subprocess.run([nft, "--check", "-f", "-"], input="\n".join(cmds) + "\n", capture_output=True, text=True)
        report("PASS" if p.returncode == 0 else "FAIL", "nftables ruleset (nft --check)", (p.stderr or "valid").strip()[:200])
    ifaces = {n for _, n in socket.if_nameindex()} if hasattr(socket, "if_nameindex") else set()
    port = os.environ.get("CHARGEGUARD_CHARGER_PORT", "eth1")
    for name, why in (("br0", "the bridge"), (port, "charger-facing port"), ("eth0", "site uplink")):
        report("PASS" if name in ifaces else "FAIL", f"interface {name}", why)
    can_raw = False
    if sys.platform.startswith("linux") and port in ifaces:
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.close()
            can_raw = True
        except PermissionError:
            pass
    report("PASS" if can_raw else "WARN", "raw packet capture", "allowed" if can_raw else
           "needs CAP_NET_RAW (the chargeguard-flows service grants it)")
    for f, what in (("trafficml/weights/flow_mlp.npz", "flow classifier"), ("trafficml/weights/behaviour_ae.npz", "learned baseline"),
                    ("threatintel/weights/sms_scam.npz", "scam detector"), ("dashboard/static/vendor/three@0.158.0/build/three.module.js", "offline dashboard")):
        report("PASS" if (ROOT / f).exists() else "FAIL", what, f)
    et = has("executorch")
    report("PASS" if et else "WARN", "ExecuTorch", "installed" if et else "not installed: detectors use NumPy; Llama advisor off")
    llama = (ROOT / "models" / "llama3_2_1b.pte").exists() and (ROOT / "models" / "tokenizer.model").exists()
    report("PASS" if llama else "WARN", "Llama 3.2 program", "models/llama3_2_1b.pte" if llama else
           "copy models/llama3_2_1b.pte and tokenizer.model from the development machine; grounded advisor used meanwhile")
    if et:
        try:
            from executorch.runtime import Runtime
            Runtime.get().load_program(ROOT / "trafficml" / "weights" / "flow_mlp.pte").load_method("forward")
            report("PASS", "ExecuTorch loads flow_mlp.pte", "")
        except Exception as e:  # noqa: BLE001
            report("FAIL", "ExecuTorch loads flow_mlp.pte", f"{type(e).__name__}: {e}")


def check_charger():
    for mod in ("ocpp", "websockets", "cryptography"):
        report("PASS" if has(mod) else "FAIL", f"python module {mod}", "")
    node = os.environ.get("CHARGEGUARD_NODE_IP", "10.20.0.1")
    try:
        socket.create_connection((node, 9000), timeout=2).close()
        report("PASS", f"node OCPP endpoint {node}:9000", "reachable")
    except OSError as e:
        report("FAIL", f"node OCPP endpoint {node}:9000", str(e))
    for f in ("firmware/images/good_v2.1.0.bin", "firmware/keys/CG-CHARGER-001_private.pem"):
        report("PASS" if (ROOT / f).exists() else "FAIL", f, "copy from the node (signed image, enrolled device key)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", choices=["node", "charger"], required=True)
    role = ap.parse_args().role
    check_platform()
    check_tpm(role)
    (check_node if role == "node" else check_charger)()
    width = max(len(w) for _, w, _ in RESULTS)
    for status, what, detail in RESULTS:
        print(f"  {status:4s}  {what:<{width}}  {detail}")
    failed = sum(s == "FAIL" for s, _, _ in RESULTS)
    print(f"\n{len(RESULTS)} checks, {failed} failed, {sum(s == 'WARN' for s, _, _ in RESULTS)} warnings")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
