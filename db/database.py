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

def seed_firmware(entries: list) -> None:
    conn = get_conn()
    cur = conn.cursor()
    for e in entries:
        cur.execute("""
            INSERT OR IGNORE INTO firmware_registry
            (hash, device_id, version, vendor, build_date, is_signed, is_authentic, pub_key_hex, sig_hex)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (e["hash"], e["device_id"], e["version"], e["vendor"],
              e["build_date"], e["is_signed"], e["is_authentic"],
              e.get("pub_key_hex"), e.get("sig_hex")))
    conn.commit()
    conn.close()


def seed_cves(entries: list) -> None:
    conn = get_conn()
    cur = conn.cursor()
    for e in entries:
        cur.execute("""
            INSERT OR IGNORE INTO cve_entries
            (firmware_hash, cve_id, severity, cvss_score, component, description, fixed_in)
            VALUES (?,?,?,?,?,?,?)
        """, (e["firmware_hash"], e["cve_id"], e["severity"], e["cvss_score"],
              e["component"], e["description"], e["fixed_in"]))
    conn.commit()
    conn.close()


def seed_identity(entries: list) -> None:
    conn = get_conn()
    cur = conn.cursor()
    for e in entries:
        cur.execute("""
            INSERT OR IGNORE INTO identity_registry
            (device_id, pub_key_hex, enrolled_at, charger_model, vendor)
            VALUES (?,?,?,?,?)
        """, (e["device_id"], e["pub_key_hex"], e["enrolled_at"],
              e.get("charger_model"), e.get("vendor")))
    conn.commit()
    conn.close()


# ── Query helpers ─────────────────────────────────────────────────────────────

def lookup_firmware(hash_hex: str) -> dict | None:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM firmware_registry WHERE hash = ?", (hash_hex,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def lookup_cves(hash_hex: str) -> list:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM cve_entries WHERE firmware_hash = ?", (hash_hex,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def lookup_identity(device_id: str) -> dict | None:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM identity_registry WHERE device_id = ?", (device_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def save_run(session_id: str, charger_mode: str, device_id: str,
             firmware_hash: str, verdict: str, results: list,
             report_path: str = None) -> None:
    conn = get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO audit_runs
        (session_id, timestamp, charger_mode, device_id, firmware_hash, verdict, results_json, report_path)
        VALUES (?,?,?,?,?,?,?,?)
    """, (session_id, datetime.utcnow().isoformat(), charger_mode, device_id,
          firmware_hash, verdict, json.dumps(results), report_path))
    conn.commit()
    conn.close()


def get_run(session_id: str) -> dict | None:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM audit_runs WHERE session_id = ?", (session_id,)
    ).fetchone()
    conn.close()
    if row:
        d = dict(row)
        d["results"] = json.loads(d["results_json"])
        return d
    return None
