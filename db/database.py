import sqlite3
import json
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import DB_PATH


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    conn = get_conn()
    cur = conn.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS firmware_registry (
        hash          TEXT PRIMARY KEY,
        device_id     TEXT NOT NULL,
        version       TEXT NOT NULL,
        vendor        TEXT NOT NULL,
        build_date    TEXT NOT NULL,
        is_signed     INTEGER DEFAULT 1,
        is_authentic  INTEGER DEFAULT 1,
        pub_key_hex   TEXT,
        sig_hex       TEXT
    );

    CREATE TABLE IF NOT EXISTS cve_entries (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        firmware_hash TEXT NOT NULL,
        cve_id        TEXT NOT NULL UNIQUE,
        severity      TEXT NOT NULL,
        cvss_score    REAL,
        component     TEXT,
        description   TEXT,
        fixed_in      TEXT
    );

    CREATE TABLE IF NOT EXISTS identity_registry (
        device_id     TEXT PRIMARY KEY,
        pub_key_hex   TEXT NOT NULL,
        enrolled_at   TEXT NOT NULL,
        charger_model TEXT,
        vendor        TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_runs (
        session_id    TEXT PRIMARY KEY,
        timestamp     TEXT NOT NULL,
        charger_mode  TEXT NOT NULL,
        device_id     TEXT,
        firmware_hash TEXT,
        verdict       TEXT NOT NULL,
        results_json  TEXT NOT NULL,
        report_path   TEXT
    );
    """)

    conn.commit()
    conn.close()


# ── Seed helpers ─────────────────────────────────────────────────────────────

