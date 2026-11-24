"""
Provision the node: build the vendor firmware images, audit them, enrol the
charger's identity and attestation key, and seed every registry.

Used by main.py at start-up, by the benchmark and by the tests.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db.database import (  # noqa: E402
    init_db, reset_registries, seed_attestation, seed_cves, seed_firmware, seed_identity,
)
from firmware.generator import generate_all, generate_attestation_enrollment  # noqa: E402


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
    return ProvisionSummary(len(fw_rows), len(cve_rows), len(id_rows), len(ak_rows), len(measurement_rows))


if __name__ == "__main__":
    print(provision())
