"""
C8 – Dashboard backend.

Serves the web UI and bridges it to the live ChargeGuard gateway:

  POST /api/verify        stage a scenario: launch the charger process (OCPP 1.6)
                          and the network tap; the gateway verifies it live
  WS   /ws/{session_id}   stream every gateway event (OCPP frames, checks,
                          verdicts, charging session, monitoring, enforcement)
  GET  /api/report/{id}   signed evidence report
"""
import asyncio
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import EVIDENCE_DIR, OCPP_HOST, OCPP_PATH, OCPP_PORT, STATIC_DIR  # noqa: E402
from evidence.report_generator import verify_report  # noqa: E402
from gateway.csms import Gateway  # noqa: E402
from simlab.scenarios import PRESETS, Scenario, ScenarioRunner  # noqa: E402

log = logging.getLogger("dashboard")
app = FastAPI(title="ChargeGuard", version="1.1.0")
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

gateway = Gateway()
runner = ScenarioRunner()


class VerifyRequest(BaseModel):
    mode: Optional[str] = None                  # preset name
    identity_attack: str = "legitimate"         # legitimate | clone | unknown
    firmware_mode: str = "good"                 # good | tampered | vulnerable
    behavior_attack: str = "normal"             # normal | port_scan | c2 | dns_exfil | burst
    attack_timing: str = "plugin"               # plugin | mid_session
    behavior_target: str = "192.168.1.254"
    behavior_rate: int = 50
    session_seconds: float = 30.0


@app.on_event("startup")
async def _startup():
    await gateway.start()


@app.on_event("shutdown")
async def _shutdown():
    await runner.stop()
    await gateway.stop()


@app.get("/")
async def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/api/scenarios")
async def scenarios():
    return {name: sc.to_dict() for name, sc in PRESETS.items()}


@app.get("/api/status")
async def status():
    return {"gateway": f"ws://{OCPP_HOST}:{OCPP_PORT}{OCPP_PATH}/<charge_point_id>",
            "advisor_engine": gateway.advisor.engine_name,
            "active_session": gateway.active.session_id if gateway.active else None,
            "quarantined": sorted(gateway.quarantine)}


@app.post("/api/verify")
async def start_verify(req: VerifyRequest):
    if req.mode and req.mode in PRESETS:
        base = PRESETS[req.mode]
        sc = Scenario(**{**base.to_dict(), "target": req.behavior_target, "rate": req.behavior_rate})
    else:
        sc = Scenario(name="custom", identity=req.identity_attack, firmware=req.firmware_mode,
                      behaviour=req.behavior_attack, attack_timing=req.attack_timing,
                      target=req.behavior_target, rate=req.behavior_rate)
    sc.session_seconds = req.session_seconds
    session_id = str(uuid.uuid4())
    session = gateway.open_session(session_id, sc.to_dict())
    session.emit("scenario", **sc.to_dict())
    await runner.start(sc, on_log=lambda line: session.emit("charger_log", line=line[-220:]))
    return {"session_id": session_id, "scenario": sc.to_dict()}


@app.websocket("/ws/{session_id}")
async def ws_session(websocket: WebSocket, session_id: str):
    await websocket.accept()
    session = gateway.sessions.get(session_id)
    if session is None:
        await websocket.send_json({"event": "error", "detail": "Unknown session."})
        await websocket.close()
        return
    q = session.bus.subscribe()
    try:
        while True:
            event = await q.get()
            await websocket.send_text(json.dumps(event, default=str))
            if event["event"] == "session_end":
                break
    except WebSocketDisconnect:
        pass
    finally:
        session.bus.unsubscribe(q)
        try:
            await websocket.close()
        except RuntimeError:
            pass


@app.get("/api/report/{session_id}")
async def download_report(session_id: str):
    path = EVIDENCE_DIR / f"{session_id}.json"
    if not path.exists():
        raise HTTPException(404, "Report not found.")
    return FileResponse(str(path), media_type="application/json",
                        filename=f"chargeguard_report_{session_id[:8]}.json")


@app.get("/api/report/{session_id}/verify")
async def check_report(session_id: str):
    path = EVIDENCE_DIR / f"{session_id}.json"
    if not path.exists():
        raise HTTPException(404, "Report not found.")
    ok, detail = verify_report(json.loads(path.read_text(encoding="utf-8")))
    return {"valid": ok, "detail": detail}


@app.get("/api/session/{session_id}")
async def get_session(session_id: str):
    s = gateway.sessions.get(session_id)
    if s is None:
        raise HTTPException(404, "Session not found.")
    return {"session_id": s.session_id, "scenario": s.scenario, "device_id": s.device_id,
            "verdict": s.verdict, "charging": s.charging, "enforcement": s.enforcement,
            "ocpp_frames": len(s.transcript), "flows": len(s.flows), "report": s.report_path}
