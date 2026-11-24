"""
Charger behaviour baseline and anomaly rules (C4 custom piece).

Input: flow/message records from any source (simulator, tshark/MQTT,
iotaudit, a router export), normalised to dicts:

    {"dst": "10.0.0.5", "port": 8080, "proto": "OCPP", "rate": 1.0,
     "encrypted": True, "message": "Heartbeat"}          # only dst is required

Output: BehaviorReport with normal/suspicious, the anomalies found and an
enforcement decision (none / block <peers> / isolate) that can be rendered
into a wolfSentry policy.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

import yaml

DEFAULT_BASELINE = Path(__file__).with_name("charger_baseline.yaml")

_SCAN_PORT_THRESHOLD = 3            # distinct unexpected ports to one host => scan
_C2_PORTS = {4444, 1337, 6667, 31337}
_EXFIL_PORTS = {53}


class Action(str, Enum):
    NONE = "none"
    BLOCK = "block"
    ISOLATE = "isolate"


@dataclass
class Anomaly:
    rule: str
    message: str
    peer: str | None = None
    severity: str = "medium"
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviorReport:
    status: str                                       # "normal" | "suspicious"
    anomalies: list[Anomaly] = field(default_factory=list)
    action: Action = Action.NONE
    blocked_peers: list[str] = field(default_factory=list)
    rate_limited: list[str] = field(default_factory=list)    # protocols to throttle
    flows_checked: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "action": self.action.value,
                "blocked_peers": self.blocked_peers, "rate_limited": self.rate_limited,
                "flows_checked": self.flows_checked,
                "anomalies": [a.__dict__ for a in self.anomalies]}


@dataclass
class Baseline:
    peers: list[dict]
    listening_ports: set[int]
    rates: dict[str, float]
    require_encryption: set[int]
    phases: list[dict]
    isolate_on: set[str]
    block_on: set[str]
    device: str = ""

    @classmethod
    def load(cls, path: str | Path = DEFAULT_BASELINE) -> "Baseline":
        d = yaml.safe_load(Path(path).read_text())
        enf = d.get("enforcement", {})
        return cls(peers=d.get("peers", []), listening_ports=set(d.get("listening_ports", [])),
                   rates={str(k): float(v) for k, v in d.get("rates", {}).items()},
                   require_encryption=set(d.get("require_encryption", [])),
                   phases=d.get("phases", []), isolate_on=set(enf.get("isolate_on", [])),
                   block_on=set(enf.get("block_on", [])), device=d.get("device", ""))

    # ── matching helpers ──────────────────────────────────────────────────

    @staticmethod
    def _host_match(host: str, pattern: str) -> bool:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return host.lower() == pattern.lower()

    def peer_for(self, host: str) -> dict | None:
        return next((p for p in self.peers if any(self._host_match(host, h) for h in p.get("hosts", []))),
                    None)

    def rate_limit(self, proto: str) -> float:
        return self.rates.get(proto, self.rates.get("default", float("inf")))

    def phase_index(self, message: str) -> int | None:
        for i, ph in enumerate(self.phases):
            if message in ph.get("messages", []):
                return i
        return None

    # ── evaluation ────────────────────────────────────────────────────────

    def evaluate(self, flows: Iterable[dict], listening: Iterable[int] = ()) -> BehaviorReport:
        flows = list(flows)
        anomalies: list[Anomaly] = []
        rate_by_proto: dict[str, float] = {}
        odd_ports_by_host: dict[str, set[int]] = {}
        reached_phase = -1

        for f in flows:
            dst, port, proto = str(f.get("dst", "")), f.get("port"), str(f.get("proto", ""))
            peer = self.peer_for(dst)
            if peer is None:
                anomalies.append(Anomaly("unexpected-peer", f"Outbound connection to unknown peer {dst}",
                                         dst, "high"))
            else:
                if port is not None and port not in peer.get("ports", []):
                    anomalies.append(Anomaly("unexpected-port",
                                             f"Port {port} not expected for peer '{peer['name']}'", dst))
                if proto and peer.get("protocols") and proto not in peer["protocols"]:
                    anomalies.append(Anomaly("unexpected-protocol",
                                             f"Protocol {proto} not expected for '{peer['name']}'", dst))
            if port is not None and (peer is None or port not in peer.get("ports", [])):
                odd_ports_by_host.setdefault(dst, set()).add(int(port))
            if port in self.require_encryption and f.get("encrypted") is False:
                anomalies.append(Anomaly("plaintext", f"Plaintext traffic on port {port}", dst, "high"))
            if proto:
                rate_by_proto[proto] = rate_by_proto.get(proto, 0.0) + float(f.get("rate", 0) or 0)
            if msg := f.get("message"):
                idx = self.phase_index(msg)
                if idx is None:
                    anomalies.append(Anomaly("unknown-message", f"Message {msg} not in any protocol phase", dst))
                elif idx > reached_phase + 1:
                    anomalies.append(Anomaly("phase-violation",
                                             f"{msg} seen before phase '{self.phases[idx - 1]['name']}'", dst))
                else:
                    reached_phase = max(reached_phase, idx)

        for proto, rate in rate_by_proto.items():
            if rate > self.rate_limit(proto):
                anomalies.append(Anomaly("rate-exceeded",
                                         f"{proto} at {rate:g} msg/s exceeds {self.rate_limit(proto):g}",
                                         None, details={"proto": proto}))
        for port in set(listening) - self.listening_ports:
            anomalies.append(Anomaly("unexpected-listener", f"Charger is listening on port {port}", None, "high"))

        # pattern rules (aggregate)
        for host, ports in odd_ports_by_host.items():
            if len(ports) >= _SCAN_PORT_THRESHOLD:
                anomalies.append(Anomaly("port-scan", f"{len(ports)} unexpected ports towards {host}", host, "critical"))
            if ports & _C2_PORTS:
                anomalies.append(Anomaly("c2-pattern", f"Known C2 port {sorted(ports & _C2_PORTS)} to {host}",
                                         host, "critical"))
            if ports & _EXFIL_PORTS and self.peer_for(host) is None:
                anomalies.append(Anomaly("exfiltration", f"DNS to non-baseline resolver {host}", host, "critical"))

        return self._decide(anomalies, len(flows))

    def _decide(self, anomalies: list[Anomaly], n: int) -> BehaviorReport:
        rules = {a.rule for a in anomalies}
        if not anomalies:
            return BehaviorReport("normal", flows_checked=n)
        if rules & self.isolate_on:
            action = Action.ISOLATE
        elif rules & self.block_on:
            action = Action.BLOCK
        else:
            action = Action.NONE
        blocked = sorted({a.peer for a in anomalies if a.peer and a.rule in self.block_on | self.isolate_on})
        throttled = sorted({a.details["proto"] for a in anomalies if a.rule == "rate-exceeded"})
        return BehaviorReport("suspicious", anomalies, action, blocked, throttled, n)
