"""
Per-session state for the live gateway: event fan-out to dashboards, the OCPP
transcript observed inline, and network flows received from the tap.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from config import SITE


class EventBus:
    """Fan-out of session events to any number of dashboard subscribers (with replay)."""

    def __init__(self):
        self.history: list[dict] = []
        self.subscribers: set[asyncio.Queue] = set()
        self.closed = False

    def publish(self, event: dict) -> None:
        self.history.append(event)
        for q in list(self.subscribers):
            q.put_nowait(event)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        for e in self.history:
            q.put_nowait(e)
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subscribers.discard(q)

    def close(self) -> None:
        self.closed = True
        self.publish({"event": "session_end"})


@dataclass
class OcppFrame:
    t: float                      # monotonic seconds
    direction: str                # "in" (charger -> node) or "out" (node -> charger)
    kind: str                     # CALL / CALLRESULT / CALLERROR
    unique_id: str
    action: str | None
    payload: Any


@dataclass
class Session:
    session_id: str
    scenario: dict
    bus: EventBus = field(default_factory=EventBus)
    t0: float = field(default_factory=time.monotonic)
    device_id: str | None = None
    transcript: list[OcppFrame] = field(default_factory=list)
    flows: deque = field(default_factory=lambda: deque(maxlen=5000))
    verdict: dict | None = None
    verdict_ready: asyncio.Event = field(default_factory=asyncio.Event)
    results: dict = field(default_factory=dict)
    transaction_id: int | None = None
    charging: dict = field(default_factory=lambda: {"state": "offline", "power_kw": 0.0, "energy_kwh": 0.0})
    enforcement: dict | None = None
    advisory: dict | None = None
    report_path: str | None = None
    verify_t0: float = 0.0
    responding: bool = False
    payment_qr: dict | None = None          # threatintel result for the QR the charger displays

    def qr_anomalies(self) -> list[dict]:
        q = self.payment_qr
        if not q or q.get("verdict") != "phishing":
            return []
        return [{"rule": "malicious-payment-qr", "peer": q["details"]["host"], "severity": "critical",
                 "message": f"Charger screen shows a payment QR pointing to a phishing site ({q['details']['host']})"}]
    attestation: dict | None = None
    _pending: dict = field(default_factory=dict)   # unique_id -> action, to name CALLRESULTs

    def elapsed(self) -> float:
        return round(time.monotonic() - self.t0, 3)

    def emit(self, event: str, **data) -> None:
        self.bus.publish({"event": event, "t": self.elapsed(), **data})

    # ── OCPP transcript ──────────────────────────────────────────────────

    def record_frame(self, raw: str, direction: str) -> OcppFrame | None:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return None
        kind = {2: "CALL", 3: "CALLRESULT", 4: "CALLERROR"}.get(msg[0], "?")
        uid = msg[1]
        if kind == "CALL":
            action, payload = msg[2], msg[3]
            self._pending[uid] = action
        else:
            action, payload = self._pending.pop(uid, None), msg[2] if len(msg) > 2 else None
        frame = OcppFrame(time.monotonic(), direction, kind, uid, action, payload)
        self.transcript.append(frame)
        self.emit("ocpp", dir=direction, kind=kind, action=action, summary=_summarise(action, kind, payload))
        return frame

    def charger_calls(self, window_s: float | None = None) -> list[OcppFrame]:
        now = time.monotonic()
        return [f for f in self.transcript if f.direction == "in" and f.kind == "CALL"
                and (window_s is None or now - f.t <= window_s)]

    # ── behaviour inputs ─────────────────────────────────────────────────

    def prior_messages(self, window_s: float) -> list[str]:
        """Charger OCPP actions that arrived before the current window, in order."""
        now = time.monotonic()
        return [f.action for f in self.transcript
                if f.direction == "in" and f.kind == "CALL" and now - f.t > window_s]

    def window_flows(self, window_s: float = 10.0) -> tuple[list[dict], float]:
        """The charger's raw NetFlow records from the last `window_s` seconds, and how many seconds
        of traffic have been observed so far (the learned baseline needs a full window)."""
        now = time.monotonic()
        mine = [f for f in self.flows if f.get("src") == SITE["charger_ip"] and isinstance(f.get("nf"), dict)]
        span = min(window_s, now - mine[0]["rx"]) if mine else 0.0
        return [f for f in mine if now - f["rx"] <= window_s], span

    def behaviour_records(self, window_s: float = 10.0) -> list[dict]:
        """OCPP calls and tap flows from the last `window_s` seconds, as baseline flow records."""
        now = time.monotonic()
        calls = self.charger_calls(window_s)
        span = max(1.0, min(window_s, now - self.t0))
        records = [{"dst": SITE["node_ip"], "port": 9000, "proto": "OCPP", "message": f.action,
                    "vendor_id": (f.payload or {}).get("vendorId") if isinstance(f.payload, dict) else None,
                    "rate": 1.0 / span}
                   for f in calls]
        flows = [f for f in self.flows if now - f["rx"] <= window_s and f.get("src") == SITE["charger_ip"]]
        per_peer: dict[tuple, int] = {}
        for f in flows:
            if f.get("app") == "OCPP":
                continue                       # already represented by the OCPP transcript
            key = (f["dst"], f["dport"], f.get("app") or f.get("proto"))
            per_peer[key] = per_peer.get(key, 0) + 1
        for (dst, port, proto), n in per_peer.items():
            records.append({"dst": dst, "port": port, "proto": proto, "rate": n / span})
        return records


def _summarise(action: str | None, kind: str, p: Any) -> str:
    if not isinstance(p, dict):
        return ""
    if kind == "CALLERROR":
        return "error"
    if action == "BootNotification" and kind == "CALL":
        return f"{p.get('chargePointVendor')} {p.get('chargePointModel')} fw {p.get('firmwareVersion')}"
    if action == "StatusNotification":
        return p.get("status", "")
    if action == "MeterValues" and kind == "CALL":
        for mv in p.get("meterValue", []):
            for sv in mv.get("sampledValue", []):
                if sv.get("measurand") == "Power.Active.Import":
                    return f"{float(sv['value']) / 1000:.2f} kW"
    if action == "DataTransfer":
        if kind == "CALL":
            return f"{p.get('vendorId')} / {p.get('messageId')}"
        return p.get("status", "")
    if action in ("Authorize", "StartTransaction") and kind == "CALLRESULT":
        return (p.get("idTagInfo") or {}).get("status", "") + (f" tx {p['transactionId']}" if "transactionId" in p else "")
    if action == "Authorize" and kind == "CALL":
        return p.get("idTag", "")
    if action == "RemoteStopTransaction":
        return f"tx {p.get('transactionId')}" if kind == "CALL" else p.get("status", "")
    if action == "StopTransaction" and kind == "CALL":
        return f"tx {p.get('transactionId')} reason {p.get('reason', '')}"
    if action == "BootNotification":
        return p.get("status", "")
    return ""


class TappedConnection:
    """Wraps the charger's WebSocket so every OCPP frame is recorded inline."""

    def __init__(self, ws, session: Session):
        self.ws, self.session = ws, session

    async def recv(self):
        raw = await self.ws.recv()
        self.session.record_frame(raw, "in")
        return raw

    async def send(self, raw):
        self.session.record_frame(raw, "out")
        await self.ws.send(raw)

    async def close(self, code: int = 1000, reason: str = ""):
        await self.ws.close(code, reason)
