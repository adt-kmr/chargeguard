"""
Renode: simulate a charger controller (MCU) without hardware.

Boots a firmware ELF on an emulated board, captures UART output, and lets
tests apply the same verification as a physical charger (e.g. feed it a
tampered image and confirm ChargeGuard flags it).

Install Renode from a release package (the vendored source in
vendor/attack-lab/renode needs its submodules to build; see
vendor/submodules.lock).
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from ..core import VENDOR_DIR, Tool, ToolResult, register_tool, run, timed

RENODE = register_tool(Tool(
    "renode", ("renode", "Renode"), "C9", vendored="attack-lab/renode",
    install_hint="Install a Renode release (renode.io) or build vendor/attack-lab/renode."))

PLATFORMS = VENDOR_DIR / "attack-lab" / "renode" / "platforms" / "boards"
DEFAULT_BOARD = "stm32f4_discovery-kit.repl"          # Cortex-M4, typical charger-controller class


def charger_script(firmware_elf: str | Path, board: str = DEFAULT_BOARD,
                   uart: str = "sysbus.usart2", run_for: str = "5") -> str:
    """Renode .resc that boots the firmware and logs UART to the console."""
    board_path = Path(board) if Path(board).is_absolute() else PLATFORMS / board
    return "\n".join([
        'mach create "chargeguard-controller"',
        f"machine LoadPlatformDescription @{board_path.as_posix()}",
        f"sysbus LoadELF @{Path(firmware_elf).as_posix()}",
        f"showAnalyzer {uart} Antmicro.Renode.Analyzers.LoggingUartAnalyzer",
        f'emulation RunFor "{run_for}"',
        "quit",
    ])


def boot_firmware(firmware_elf: str | Path, board: str = DEFAULT_BOARD,
                  run_for_s: int = 5, timeout: float = 120) -> ToolResult:
    """Boot firmware for `run_for_s` seconds of virtual time; raw output holds the UART log."""
    result = ToolResult(tool="renode", ok=False)
    with timed(result):
        with tempfile.TemporaryDirectory(prefix="cg-renode-") as tmp:
            script = Path(tmp) / "charger.resc"
            script.write_text(charger_script(firmware_elf, board, run_for=str(run_for_s)))
            proc = run(RENODE, ["--disable-gui", "--console", "-p", script],
                       timeout=timeout, check=False)
        result.ok = proc.returncode == 0
        result.raw = proc.stdout[-20000:]
        result.error = None if result.ok else proc.stderr[-1000:]
    return result
