"""
nftables enforcement on the node's bridge.

The node is a two-port Ethernet bridge between the charger and the site network, so
traffic it forwards is filtered in the `bridge` family; traffic addressed to the node
itself (OCPP, DNS, NTP) passes the `inet` input hook. One table each:

  bridge chargeguard   forward: drop anything from or to a quarantined charger, and
                       anything to a blocked peer (blocks expire after BLOCK_TIMEOUT)
  inet chargeguard     input:   drop anything from a quarantined charger to the node

Modes (CHARGEGUARD_FIREWALL):
  render   default: build the commands and record them as evidence (any OS)
  check    also validate them with `nft --check` (Linux, nft installed)
  apply    run them (Linux with CAP_NET_ADMIN; the node service on the Raspberry Pi)

Every address is validated with `ipaddress` before it is written into a command, and
commands are passed to nft on stdin (never through a shell).
"""
from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from dataclasses import dataclass, field

BLOCK_TIMEOUT = "1h"
TABLES = f"""table bridge chargeguard {{
  set quarantine {{ type ipv4_addr; }}
  set blocked {{ type ipv4_addr; flags timeout; timeout {BLOCK_TIMEOUT}; }}
  chain forward {{
    type filter hook forward priority filter; policy accept;
    ip saddr @quarantine counter drop
    ip daddr @quarantine counter drop
    ip daddr @blocked counter drop
    ip saddr @blocked counter drop
  }}
}}
table inet chargeguard {{
  set quarantine {{ type ipv4_addr; }}
  chain input {{
    type filter hook input priority filter; policy accept;
    ip saddr @quarantine counter drop
  }}
}}"""


def _ipv4(addr: str) -> str | None:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    return str(ip) if ip.version == 4 and not ip.is_unspecified and not ip.is_multicast else None


@dataclass
class FirewallResult:
    mode: str
    commands: list[str]
    applied: bool = False
    error: str | None = None
    skipped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"mode": self.mode, "commands": self.commands, "applied": self.applied,
                "error": self.error, "skipped_invalid_addresses": self.skipped}


class Firewall:
    def __init__(self, mode: str | None = None, protect: tuple[str, ...] = ()):
        self.mode = (mode or os.environ.get("CHARGEGUARD_FIREWALL", "render")).lower()
        self.protect = {a for a in (_ipv4(p) for p in protect) if a}     # never block the node itself
        self._installed = False

    def commands(self, quarantine: list[str], block: list[str]) -> tuple[list[str], list[str]]:
        q, b, skipped = [], [], []
        for addr in quarantine:
            (q if (v := _ipv4(addr)) and v not in self.protect else skipped).append(v or addr)
        for addr in block:
            (b if (v := _ipv4(addr)) and v not in self.protect else skipped).append(v or addr)
        cmds = [] if self._installed else [TABLES]
        if q:
            ips = ", ".join(sorted(set(q)))
            cmds += [f"add element bridge chargeguard quarantine {{ {ips} }}",
                     f"add element inet chargeguard quarantine {{ {ips} }}"]
        if b:
            cmds.append(f"add element bridge chargeguard blocked {{ {', '.join(sorted(set(b)))} }}")
        return cmds, skipped

    def enforce(self, quarantine: list[str] = (), block: list[str] = ()) -> FirewallResult:
        cmds, skipped = self.commands(list(quarantine), list(block))
        res = FirewallResult(self.mode, cmds, skipped=skipped)
        if self.mode not in ("check", "apply") or not cmds:
            return res
        nft = shutil.which("nft")
        if nft is None:
            res.error = "nft not found (install nftables)"
            return res
        args = [nft, "--check", "-f", "-"] if self.mode == "check" else [nft, "-f", "-"]
        proc = subprocess.run(args, input="\n".join(cmds) + "\n", capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            res.error = (proc.stderr or proc.stdout).strip()[:500]
            return res
        res.applied = self.mode == "apply"
        if res.applied:
            self._installed = True
        return res

    def release(self, addr: str) -> FirewallResult:
        """Lift a quarantine (an operator decision after the charger is fixed and re-verified)."""
        v = _ipv4(addr)
        if v is None:
            return FirewallResult(self.mode, [], error=f"invalid address {addr!r}")
        cmds = [f"delete element bridge chargeguard quarantine {{ {v} }}",
                f"delete element inet chargeguard quarantine {{ {v} }}"]
        res = FirewallResult(self.mode, cmds)
        if self.mode == "apply" and (nft := shutil.which("nft")):
            proc = subprocess.run([nft, "-f", "-"], input="\n".join(cmds) + "\n", capture_output=True, text=True, timeout=10)
            res.applied, res.error = proc.returncode == 0, (proc.stderr.strip()[:500] or None)
        return res
