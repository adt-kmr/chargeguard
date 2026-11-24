"""
Launch and stop the IBM software TPM emulator (third_party/tpm/ibmswtpm2).

Build it first (Linux/macOS/WSL):
    cd third_party/tpm/ibmswtpm2/src && make
Then:
    with TPMEmulator() as emu:
        with get_backend("tpm2-tss", tcti=emu.tcti) as tpm: ...

The emulator listens on <port> (commands) and <port+1> (platform).
"""
from __future__ import annotations

import socket
import subprocess
import tempfile
import time
from pathlib import Path

from .base import BackendUnavailable
from .config import AttestationConfig


class TPMEmulator:
    def __init__(self, config: AttestationConfig | None = None, binary: str | Path | None = None,
                 port: int | None = None, state_dir: str | Path | None = None):
        cfg = config or AttestationConfig()
        self.binary = Path(binary or cfg.emulator_binary)
        self.port = port or cfg.emulator_port
        self.state_dir = Path(state_dir) if state_dir else None
        self._proc: subprocess.Popen | None = None
        self._tmp: tempfile.TemporaryDirectory | None = None

    @property
    def tcti(self) -> str:
        return f"mssim:host=127.0.0.1,port={self.port}"

    def _wait_ready(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise BackendUnavailable(f"TPM emulator exited with code {self._proc.returncode}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.1)
        raise BackendUnavailable(f"TPM emulator did not open port {self.port} within {timeout}s")

    def start(self, timeout: float = 5.0) -> "TPMEmulator":
        if self._proc is not None:
            return self
        if not self.binary.exists():
            raise BackendUnavailable(f"TPM emulator binary not found: {self.binary} (build ibmswtpm2 first)")
        if self.state_dir is None:                       # NVChip lives in the working dir
            self._tmp = tempfile.TemporaryDirectory(prefix="cg-tpm-")
            self.state_dir = Path(self._tmp.name)
        self._proc = subprocess.Popen(
            [str(self.binary), "-port", str(self.port), "-rm"],
            cwd=self.state_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._wait_ready(timeout)
        return self

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp, self.state_dir = None, None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False
