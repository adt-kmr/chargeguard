"""
Provision the node: build the vendor firmware images, audit them, enrol the
charger's identity and attestation key, and seed every registry.

Used by main.py at start-up, by the benchmark and by the tests.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db.database import (  # noqa: E402
    get_conn, init_db, reset_registries, seed_attestation, seed_cves, seed_firmware, seed_identity,
)
from firmware.generator import KEYS_DIR, generate_all, generate_attestation_enrollment  # noqa: E402

ENROLLED_DIR = KEYS_DIR / "enrolled"          # git-ignored; public keys of chargers with hardware TPMs


@dataclass
class ProvisionSummary:
    firmware: int
    cves: int
    identities: int
    attestation_keys: int
    measurements: int


def provision() -> ProvisionSummary:
    init_db()
    reset_registries()
    fw_rows, cve_rows, id_rows = generate_all()
    seed_firmware(fw_rows)
    seed_cves(cve_rows)
    seed_identity(id_rows)
    ak_rows, measurement_rows = generate_attestation_enrollment()
    seed_attestation(ak_rows, measurement_rows)
    enrolled = apply_enrolments()
    return ProvisionSummary(len(fw_rows), len(cve_rows), len(id_rows), len(ak_rows) + enrolled, len(measurement_rows))


def apply_enrolments() -> int:
    """Chargers enrolled from a hardware TPM (charger/enroll.py) replace the simulated keys for their ID."""
    n = 0
    for path in sorted(ENROLLED_DIR.glob("*.json")) if ENROLLED_DIR.exists() else []:
        e = json.loads(path.read_text())
        bytes.fromhex(e["ak_pub_der_hex"]), bytes.fromhex(e["device_pub_hex"])        # validate before use
        conn = get_conn()
        conn.execute("INSERT OR REPLACE INTO attestation_registry VALUES (?,?,?)",
                     (e["device_id"], e["ak_pub_der_hex"], e.get("ak_algorithm", "ecc-p256")))
        conn.execute("UPDATE identity_registry SET pub_key_hex = ? WHERE device_id = ?", (e["device_pub_hex"], e["device_id"]))
        conn.commit()
        conn.close()
        n += 1
    return n


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--enrol", help="enrolment JSON from `python -m charger.enroll` on the charger")
    a = ap.parse_args()
    if a.enrol:
        data = json.loads(Path(a.enrol).read_text())
        ENROLLED_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy(a.enrol, ENROLLED_DIR / f"{data['device_id']}.json")
        print(f"enrolled {data['device_id']} ({data.get('tpm_backend', '?')} TPM)")
    print(provision())
