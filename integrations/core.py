"""
Shared plumbing for wrapping external security tools.

Every adapter in this package describes its tool with a `Tool` entry and
runs it through `run()`. That gives one consistent way to:
  * locate a binary (env override -> PATH -> build output under vendor/)
  * enforce a timeout (the orchestrator works to a 5-second budget)
  * capture stdout/stderr and parse JSON
  * report missing tools as `ToolUnavailable` instead of crashing
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VENDOR_DIR = PROJECT_ROOT / "vendor"


class ToolUnavailable(RuntimeError):
    """The tool's binary or Python module could not be found."""


class ToolFailed(RuntimeError):
    def __init__(self, tool: str, returncode: int, stderr: str):
        super().__init__(f"{tool} exited with {returncode}: {stderr.strip()[:500]}")
        self.tool, self.returncode, self.stderr = tool, returncode, stderr


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: str | None) -> "Severity":
        try:
            return cls((value or "unknown").strip().lower())
        except ValueError:
            return {"negligible": cls.LOW, "moderate": cls.MEDIUM,
                    "important": cls.HIGH, "error": cls.HIGH,
                    "warning": cls.MEDIUM, "note": cls.LOW}.get((value or "").lower(), cls.UNKNOWN)


@dataclass
class Finding:
    """One normalised issue from any tool (CVE, leaked key, missing hardening flag, ...)."""
    tool: str
    rule_id: str                    # e.g. "CVE-2022-0778", "weak-rsa-key", "no-pie"
    title: str
    severity: Severity = Severity.UNKNOWN
    location: str | None = None     # file path, component, peer address
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ToolResult:
    tool: str
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)   # name -> file path
    raw: Any = None
    duration_s: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "ok": self.ok, "duration_s": round(self.duration_s, 3),
                "error": self.error, "artifacts": self.artifacts,
                "findings": [f.to_dict() for f in self.findings]}


@dataclass(frozen=True)
class Tool:
    """How to find one external tool."""
    name: str
    executables: tuple[str, ...]                 # names to search on PATH
    feature: str                                 # C2, C3, ...
    vendored: str | None = None                  # path under vendor/
    # candidate built binaries/scripts, relative to vendor/. Prefix with
    # "python:" or "bash:" to run through an interpreter (bash ones are skipped on Windows).
    build_outputs: tuple[str, ...] = ()
    python_module: str | None = None             # run as `python -m module` if importable
    requires_modules: tuple[str, ...] = ()       # Python deps a vendored script needs
    install_hint: str = ""

    @property
    def env_var(self) -> str:
        return "CHARGEGUARD_TOOL_" + self.name.upper().replace("-", "_")

    def resolve(self) -> list[str]:
        """Return the argv prefix to invoke the tool, or raise ToolUnavailable."""
        override = os.environ.get(self.env_var)
        if override:
            return override.split()
        for exe in self.executables:
            found = shutil.which(exe)
            if found:
                return [found]
        import importlib.util
        deps_ok = all(importlib.util.find_spec(m) is not None for m in self.requires_modules)
        for entry in self.build_outputs:
            interp, _, rel = entry.rpartition(":")
            p = VENDOR_DIR / rel
            if not p.exists():
                continue
            if interp == "python" and deps_ok:
                return [sys.executable, str(p)]
            if interp == "bash" and os.name != "nt" and shutil.which("bash"):
                return ["bash", str(p)]
            if not interp and os.access(p, os.X_OK) and os.name != "nt":
                return [str(p)]
        if self.python_module and deps_ok:
            if importlib.util.find_spec(self.python_module.split(".")[0]) is not None:
                return [sys.executable, "-m", self.python_module]
        raise ToolUnavailable(f"{self.name} not found. {self.install_hint} "
                              f"(or set {self.env_var})".strip())

    def available(self) -> bool:
        try:
            self.resolve()
            return True
        except ToolUnavailable:
            return False


TOOLS: dict[str, Tool] = {}


def register_tool(tool: Tool) -> Tool:
    TOOLS[tool.name] = tool
    return tool


def run(tool: Tool, args: Iterable[str], timeout: float = 60.0, check: bool = True,
        cwd: str | Path | None = None, ok_codes: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess:
    argv = tool.resolve() + [str(a) for a in args]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd,
                              encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired as e:
        raise ToolFailed(tool.name, -1, f"timed out after {timeout}s") from e
    if check and proc.returncode not in ok_codes:
        raise ToolFailed(tool.name, proc.returncode, proc.stderr)
    return proc


def run_json(tool: Tool, args: Iterable[str], timeout: float = 60.0,
             ok_codes: tuple[int, ...] = (0,)) -> Any:
    proc = run(tool, args, timeout=timeout, ok_codes=ok_codes)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ToolFailed(tool.name, proc.returncode, f"invalid JSON output: {e}") from e


class timed:
    """Context manager that fills ToolResult.duration_s."""
    def __init__(self, result: ToolResult):
        self.result = result

    def __enter__(self):
        self._t = time.perf_counter()
        return self.result

    def __exit__(self, exc_type, exc, tb):
        self.result.duration_s = time.perf_counter() - self._t
        if exc is not None and isinstance(exc, (ToolUnavailable, ToolFailed)):
            self.result.ok, self.result.error = False, str(exc)
            return True                                   # swallow: reported in result
        return False


def doctor() -> dict[str, dict[str, Any]]:
    """Availability report for every registered tool (for setup scripts / health checks)."""
    out = {}
    for name, t in sorted(TOOLS.items()):
        try:
            argv = t.resolve()
            out[name] = {"feature": t.feature, "available": True, "command": " ".join(argv)}
        except ToolUnavailable as e:
            out[name] = {"feature": t.feature, "available": False, "hint": str(e)}
    return out
