"""
ChargeGuard gateway: the OCPP 1.6-J endpoint that chargers connect to.

Sitting inline, it:
  1. accepts the charger's BootNotification,
  2. challenges it over OCPP DataTransfer (nonce -> signature + TPM quote + firmware),
  3. runs C1–C4 on the real responses and traffic, fuses a verdict (C5) and signs the report (C7),
  4. gates Authorize / StartTransaction on that verdict,
  5. keeps evaluating behaviour during the session and enforces: remote stop,
     disconnect and quarantine when the charger turns hostile.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone

import websockets
from ocpp.routing import on
from ocpp.v16 import ChargePoint, call, call_result
from ocpp.v16.datatypes import IdTagInfo
from ocpp.v16.enums import (
    Action, AuthorizationStatus, DataTransferStatus, RegistrationStatus,
)

from advisor import Advisor
from config import (
    VENDOR, ATTESTATION_VENDOR_ID, CHECK_TIMINGS, EVIDENCE_DIR, FLOW_SENSOR_HOST, FLOW_SENSOR_PORT,
    HEARTBEAT_INTERVAL_S, OCPP_HOST, OCPP_PATH, OCPP_PORT, PRESENTATION_PACING, SITE,
)
from db.database import save_run
from evidence.report_generator import generate as generate_report
from gateway import checks
from gateway.sensor import start_collector
from gateway.session import Session, TappedConnection
from integrations.behavior import Action as EnfAction, render_wolfsentry_config
from orchestrator.trust_engine import fuse
from threatintel import analyse_url

log = logging.getLogger("gateway")
BEHAVIOUR_WINDOW_S = 10.0


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class GatewayChargePoint(ChargePoint):
    def __init__(self, cp_id, conn, gw: "Gateway", session: Session):
        super().__init__(cp_id, conn, response_timeout=10)
        self.gw, self.session = gw, session
        self.next_tx = 41_000

    @on(Action.boot_notification)
    async def on_boot(self, charge_point_vendor, charge_point_model, **kw):
        self.session.charging.update(state="booted", model=charge_point_model,
                                     firmware=kw.get("firmware_version"))
        self.session.emit("session", **self.session.charging)
        self.gw.spawn(self.gw.verify(self))
        return call_result.BootNotification(current_time=utcnow(), interval=HEARTBEAT_INTERVAL_S,
                                            status=RegistrationStatus.accepted)

    @on(Action.heartbeat)
    async def on_heartbeat(self, **_):
        return call_result.Heartbeat(current_time=utcnow())

    @on(Action.status_notification)
    async def on_status(self, status, **_):
        self.session.charging["state"] = str(status).lower()
        if self.session.charging["state"] != "charging":
            self.session.charging["power_kw"] = 0.0
        self.session.emit("session", **self.session.charging)
        return call_result.StatusNotification()

    async def _gate(self) -> AuthorizationStatus:
        try:
            await asyncio.wait_for(self.session.verdict_ready.wait(), timeout=8)
        except asyncio.TimeoutError:
            return AuthorizationStatus.blocked
        if self.session.verdict["verdict"] == "red" or self.session.enforcement:
            return AuthorizationStatus.blocked
        return AuthorizationStatus.accepted

    @on(Action.authorize)
    async def on_authorize(self, id_tag, **_):
        status = await self._gate()
        if status != AuthorizationStatus.accepted:
            self.session.emit("alert", level="crit",
                              message=f"Authorization for {id_tag} refused: charger is not trusted.")
        return call_result.Authorize(id_tag_info=IdTagInfo(status=status))

    @on(Action.start_transaction)
    async def on_start(self, connector_id, id_tag, meter_start, timestamp, **_):
        status = await self._gate()
        self.next_tx += 1
        tx = self.next_tx
        if status == AuthorizationStatus.accepted:
            self.session.transaction_id = tx
            self.session.charging.update(transaction_id=tx, meter_start_wh=meter_start,
                                         energy_kwh=0.0, state="charging")
            self.session.emit("session", **self.session.charging)
        return call_result.StartTransaction(transaction_id=tx, id_tag_info=IdTagInfo(status=status))

    @on(Action.meter_values)
    async def on_meter(self, connector_id, meter_value, transaction_id=None, **_):
        for mv in meter_value:
            for sv in mv.get("sampled_value", mv.get("sampledValue", [])):
                m, v = sv.get("measurand"), float(sv["value"])
                if m == "Power.Active.Import":
                    self.session.charging["power_kw"] = round(v / 1000, 2)
                elif m == "Energy.Active.Import.Register":
                    start = self.session.charging.get("meter_start_wh", v)
                    self.session.charging["energy_kwh"] = round((v - start) / 1000, 3)
        self.session.emit("session", **self.session.charging)
        return call_result.MeterValues()

    @on(Action.stop_transaction)
    async def on_stop(self, meter_stop, timestamp, transaction_id, reason=None, **_):
        self.session.transaction_id = None
        self.session.charging.update(state="finishing", power_kw=0.0, stop_reason=str(reason or ""))
        self.session.emit("session", **self.session.charging)
        return call_result.StopTransaction()

    @on(Action.data_transfer)
    async def on_data_transfer(self, vendor_id, message_id=None, data=None, **_):
        # Charger-initiated extensions are recorded in the transcript and judged by C4.
        if vendor_id == ATTESTATION_VENDOR_ID:
            return call_result.DataTransfer(status=DataTransferStatus.accepted)
        if vendor_id == VENDOR and message_id == "DisplayPaymentQR":
            url = (json.loads(data or "{}") or {}).get("url", "")
            result = await asyncio.to_thread(analyse_url, url)
            self.session.payment_qr = {**result, "url": url}
            self.session.emit("payment_qr", url=url, verdict=result["verdict"], score=result["score"],
                              rules=result["rules"], host=result["details"]["host"])
            if result["verdict"] == "phishing":
                self.session.emit("alert", level="crit",
                                  message=f"Payment QR on the charger screen points to a phishing site: {url}")
            return call_result.DataTransfer(status=DataTransferStatus.accepted)
        return call_result.DataTransfer(status=DataTransferStatus.unknown_vendor_id)


class Gateway:
    def __init__(self):
        self.sessions: dict[str, Session] = {}
        self.active: Session | None = None
        self.quarantine: set[str] = set()
        self.advisor = Advisor()
        self._server = None
        self._collector = None
        self.connections: dict[str, tuple] = {}     # device_id -> (ws, cp)
        self._tasks: set[asyncio.Task] = set()      # keep response tasks referenced until done

    def spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def start(self):
        self._server = await websockets.serve(self._handle, OCPP_HOST, OCPP_PORT, subprotocols=["ocpp1.6"])
        self._collector, _ = await start_collector(FLOW_SENSOR_HOST, FLOW_SENSOR_PORT, lambda: self.active)
        log.info("OCPP gateway on ws://%s:%d%s, flow collector on udp/%d", OCPP_HOST, OCPP_PORT, OCPP_PATH,
                 FLOW_SENSOR_PORT)

    async def stop(self):
        if self._server:
            self._server.close()
        if self._collector:
            self._collector.close()

    def open_session(self, session_id: str, scenario: dict) -> Session:
        if self.active and not self.active.bus.closed:
            self.active.bus.close()
        s = Session(session_id, scenario)
        self.sessions[session_id] = s
        self.active = s
        self.quarantine.clear()                  # each demo run starts from a clean site
        return s

    async def _handle(self, ws):
        path = ws.request.path
        device_id = path.rstrip("/").split("/")[-1]
        session = self.active
        if session is None or not path.startswith(OCPP_PATH):
            await ws.close(1008, "no active verification session")
            return
        if device_id in self.quarantine:
            session.emit("alert", level="crit", message=f"Quarantined charger {device_id} tried to reconnect: refused.")
            await ws.close(1008, "quarantined")
            return
        session.device_id = device_id
        session.emit("connected", device_id=device_id, remote=f"{ws.remote_address[0]}:{ws.remote_address[1]}",
                     subprotocol=ws.subprotocol)
        cp = GatewayChargePoint(device_id, TappedConnection(ws, session), self, session)
        self.connections[device_id] = (ws, cp)
        monitor = asyncio.create_task(self._monitor(session, cp, ws))
        try:
            await cp.start()
        except websockets.ConnectionClosed:
            pass
        finally:
            monitor.cancel()
            self.connections.pop(device_id, None)
            session.charging.update(state="offline", power_kw=0.0)
            session.emit("session", **session.charging)
            session.emit("disconnected", device_id=device_id)

    # ── C5: verification under the 5-second schedule ──────────────────────

    async def _paced(self, session: Session, name: str, coro_fn):
        start_off, end_off = CHECK_TIMINGS[name]
        session.emit("check_start", check=name)
        t0 = time.perf_counter()
        result = await coro_fn()
        result.timing = time.perf_counter() - t0
        if PRESENTATION_PACING:
            wait = end_off - (time.monotonic() - session.verify_t0)
            if wait > 0:
                await asyncio.sleep(wait)
        session.results[name] = result
        session.emit("check_done", check=name, status=result.status, detail=result.detail,
                     evidence=result.evidence, compute_ms=round(result.timing * 1000, 3))
        return result

    async def verify(self, cp: GatewayChargePoint):
        session = cp.session
        session.verify_t0 = time.monotonic()
        session.emit("verify_start", device_id=cp.id, pacing=PRESENTATION_PACING)
        nonce = os.urandom(32)
        state: dict = {}

        async def identity():
            t = time.perf_counter()
            try:
                res = await cp.call(call.DataTransfer(
                    vendor_id=ATTESTATION_VENDOR_ID, message_id="AttestationRequest",
                    data=json.dumps({"nonce": nonce.hex(), "pcrs": [0]})))
                state["resp"] = json.loads(res.data) if res.status == DataTransferStatus.accepted and res.data else None
            except (asyncio.TimeoutError, json.JSONDecodeError):
                state["resp"] = None
            state["rtt"] = round((time.perf_counter() - t) * 1000, 2)
            return checks.check_identity(cp.id, nonce, state["resp"], state["rtt"])

        async def integrity():
            return checks.check_integrity(state.get("resp"), session.results.get("identity"))

        async def weaknesses():
            return checks.check_weaknesses(state.get("resp"))

        async def behaviour():
            flows, span = session.window_flows(BEHAVIOUR_WINDOW_S)
            return checks.check_behaviour(session.behaviour_records(BEHAVIOUR_WINDOW_S), BEHAVIOUR_WINDOW_S,
                                          session.prior_messages(BEHAVIOUR_WINDOW_S), session.qr_anomalies(),
                                          flows=flows, span_s=span)

        r_id = await self._paced(session, "identity", identity)
        for name, fn in (("integrity", integrity), ("weaknesses", weaknesses), ("behavior", behaviour)):
            if r_id.status == "fail" and name in ("integrity", "weaknesses") and state.get("resp") is None:
                continue
            await self._paced(session, name, fn)

        verdict = fuse(session.results)
        if PRESENTATION_PACING:
            wait = CHECK_TIMINGS["verdict"][1] - (time.monotonic() - session.verify_t0)
            if wait > 0:
                await asyncio.sleep(wait)
        session.verdict = verdict
        session.attestation = state.get("resp")
        session.emit("verdict", verdict=verdict["verdict"], reason=verdict["reason"], score=verdict["score"],
                     results={k: v.to_dict() for k, v in session.results.items()},
                     verify_s=round(time.monotonic() - session.verify_t0, 3))
        session.verdict_ready.set()

        if session.results.get("behavior") and session.results["behavior"].status == "fail":
            await self.enforce(session, cp, "plug-in")
        elif verdict["verdict"] == "red":
            session.emit("enforcement", action="deny", detail="Charging authorization blocked for this charger.",
                         artifacts={})
        await self.finalise(session)

    # ── continuous monitoring (C4 during the session) ─────────────────────

    async def _monitor(self, session: Session, cp: GatewayChargePoint, ws):
        try:
            while True:
                await asyncio.sleep(1.0)
                session.emit("traffic", rows=_traffic_rows(session))
                if not session.verdict_ready.is_set():
                    continue
                records = session.behaviour_records(BEHAVIOUR_WINDOW_S)
                flows, span = session.window_flows(BEHAVIOUR_WINDOW_S)
                result = checks.check_behaviour(records, BEHAVIOUR_WINDOW_S, session.prior_messages(BEHAVIOUR_WINDOW_S),
                                                session.qr_anomalies(), flows=flows, span_s=span)
                session.emit("monitor", status="suspicious" if result.status == "fail" else "normal",
                             anomalies=result.evidence["anomalies"][:6], records=len(records),
                             window_s=BEHAVIOUR_WINDOW_S, compute_ms=result.evidence.get("compute_ms"))
                if result.status == "fail" and not session.enforcement and not session.responding:
                    session.responding = True
                    session.results["behavior"] = result
                    verdict = fuse(session.results)
                    session.verdict = verdict
                    session.emit("verdict", verdict=verdict["verdict"], reason=verdict["reason"],
                                 score=verdict["score"], mid_session=True,
                                 results={k: v.to_dict() for k, v in session.results.items()})
                    # Independent task: isolating the charger closes its connection, which
                    # cancels this monitor; the response and the signed report must still finish.
                    self.spawn(self._respond(session, cp))
                    return
        except asyncio.CancelledError:
            pass

    async def _respond(self, session: Session, cp: GatewayChargePoint):
        try:
            await self.enforce(session, cp, "mid-session")
        finally:
            await self.finalise(session)

    # ── enforcement ───────────────────────────────────────────────────────

    async def enforce(self, session: Session, cp: GatewayChargePoint, when: str):
        b = session.results["behavior"].evidence
        report = checks.baseline().evaluate(
            session.behaviour_records(BEHAVIOUR_WINDOW_S),
            start_phase=checks.baseline().phase_reached(session.prior_messages(BEHAVIOUR_WINDOW_S)))
        action = "isolate" if report.action in (EnfAction.ISOLATE,) or session.qr_anomalies() else "block"
        steps = []
        if session.transaction_id is not None:
            try:
                res = await cp.call(call.RemoteStopTransaction(transaction_id=session.transaction_id))
                steps.append(f"RemoteStopTransaction tx {session.transaction_id}: {res.status}")
                await asyncio.sleep(1.5)                     # let the charger send StopTransaction
            except asyncio.TimeoutError:
                steps.append("RemoteStopTransaction: no response")
        if action == "isolate":
            self.quarantine.add(cp.id)
            steps.append(f"Charger {cp.id} quarantined; OCPP connection closed (1008).")
        peers = b.get("blocked_peers", [])
        nft = ["table inet chargeguard { set quarantine { type ipv4_addr; } set blocked { type ipv4_addr; }",
               "  chain forward { type filter hook forward priority 0; policy accept;",
               "    ip saddr @quarantine drop; ip daddr @quarantine drop; ip daddr @blocked drop; } }"]
        if action == "isolate":
            nft.append(f"add element inet chargeguard quarantine {{ {SITE['charger_ip']} }}")
        ips = [p for p in peers if p and p[0].isdigit()]
        if ips:
            nft.append(f"add element inet chargeguard blocked {{ {', '.join(ips)} }}")
        session.enforcement = {
            "action": action, "when": when, "steps": steps, "blocked_peers": peers,
            "artifacts": {"nftables": nft, "nftables_mode": "rendered (applied by the node service on the Raspberry Pi)",
                          "wolfsentry": render_wolfsentry_config(report, checks.baseline())},
        }
        session.emit("enforcement", **session.enforcement,
                     detail=("Charger isolated: session stopped, connection closed, device quarantined."
                             if action == "isolate" else "Offending peers blocked; charger rate-limited."))
        if action == "isolate":
            conn = self.connections.get(cp.id)
            if conn:
                await conn[0].close(1008, "isolated by ChargeGuard")

    # ── C6/C7: advisory + signed evidence ─────────────────────────────────

    async def finalise(self, session: Session):
        checks_dict = {k: v.to_dict() for k, v in session.results.items()}
        ctx = {"verdict": session.verdict["verdict"], "reason": session.verdict["reason"],
               "checks": checks_dict, "enforcement": session.enforcement}
        advisory = await asyncio.to_thread(self.advisor.explain, ctx)
        session.advisory = advisory.to_dict()
        session.emit("advisory", **session.advisory)

        transcript = [{"t": round(f.t - session.t0, 3), "dir": f.direction, "kind": f.kind, "action": f.action}
                      for f in session.transcript]
        extras = {
            "device_id": session.device_id,
            "attestation_response": session.attestation,
            "ocpp_transcript": {"frames": len(transcript), "messages": transcript[-200:]},
            "network_flows_observed": len(session.flows),
            "charging_session": session.charging,
            "payment_qr": session.payment_qr,
            "enforcement": session.enforcement,
            "advisory": session.advisory,
            "timing": {"presentation_pacing": PRESENTATION_PACING,
                       "check_compute_ms": {k: round(v.timing * 1000, 3) for k, v in session.results.items()}},
        }
        report = await asyncio.to_thread(
            generate_report, session.session_id, session.verdict["verdict"], session.verdict["reason"],
            session.verdict["score"], session.results, session.scenario.get("name", "custom"), extras)
        session.report_path = str(EVIDENCE_DIR / f"{session.session_id}.json")
        save_run(session_id=session.session_id, charger_mode=session.scenario.get("name", "custom"),
                 device_id=session.device_id or "",
                 firmware_hash=(session.attestation or {}).get("firmware", {}).get("payload_sha256", ""),
                 verdict=session.verdict["verdict"], results=checks_dict, report_path=session.report_path)
        session.emit("report_ready", session_id=session.session_id, download=f"/api/report/{session.session_id}",
                     signature=report["signature"][:24])


def _traffic_rows(session: Session) -> list[dict]:
    now = time.monotonic()
    rows: dict[tuple, dict] = {}
    for f in session.charger_calls(5.0):
        key = ("OCPP", f.action)
        rows.setdefault(key, {"proto": "OCPP", "dst": f"{SITE['node_ip']}:9000 · {f.action}", "count": 0,
                              "attack": f.action == "DataTransfer"})["count"] += 1
    for f in session.flows:
        if now - f["rx"] > 5.0 or f.get("app") == "OCPP":
            continue
        key = (f.get("app"), f["dst"], f["dport"])
        baseline_peer = checks.baseline().peer_for(f["dst"]) is not None
        rows.setdefault(key, {"proto": f.get("app") or f.get("proto"), "dst": f"{f['dst']}:{f['dport']}",
                              "count": 0, "attack": not baseline_peer})["count"] += 1
    out = sorted(rows.values(), key=lambda r: (not r["attack"], -r["count"]))[:12]
    for r in out:
        r["rate"] = f"{r.pop('count') / 5:.1f}/s"
    return out
