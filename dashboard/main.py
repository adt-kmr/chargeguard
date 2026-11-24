"""
C8 – Dashboard Backend
FastAPI app: serves the web UI, handles WebSocket verification streams,
returns evidence reports for download.
"""
import asyncio
import json
import sys
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    STATIC_DIR, EVIDENCE_DIR,
    MODE_HEALTHY, MODE_TAMPERED, MODE_VULNERABLE, MODE_COMPROMISED,
)
from simulator.charger    import ChargerSimulator, AttackConfig
from orchestrator.orchestrator import run_verification
from evidence.report_generator import generate as generate_report
from db.database import save_run
from simulator.attacker import get_all_scenarios

app = FastAPI(title="ChargeGuard", version="1.0.0")

# Mount static files
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Global simulator instance (mode is set per-request)
_simulator = ChargerSimulator()

# In-memory session store: session_id → {mode, status, report_path}
_sessions: dict = {}


class VerifyRequest(BaseModel):
    # Legacy preset (optional)
    mode: Optional[str] = None
    # Granular attack config
    identity_attack:  str       = "legitimate"      # legitimate | unknown | clone
    firmware_mode:    str       = "good"             # good | tampered | vulnerable
    inject_cves:      list      = []                 # ["CVE-2022-0778", ...]
    behavior_attack:  str       = "normal"           # normal | port_scan | c2 | dns_exfil | burst
    behavior_target:  str       = "192.168.1.254"
    behavior_rate:    int       = 50

