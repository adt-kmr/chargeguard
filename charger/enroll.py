"""
Enrol a charger with a hardware TPM: export what the node must trust.

On the charger (Raspberry Pi with an SPI TPM, tpm2-tss and tpm2-pytss installed):

    CHARGEGUARD_TPM_TCTI=device:/dev/tpmrm0 python -m charger.enroll --tpm tpm2-tss > enrol.json

then copy enrol.json to the node and import it:

    python -m firmware.provision --enrol enrol.json

The file holds only public material: the device ID, the device's Ed25519 public key
and the TPM attestation key's public part. The attestation key is a primary key under
the endorsement hierarchy, so the TPM derives the same key on every start and the
private part never leaves the chip.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization  # noqa: E402

from charger.agent import open_tpm  # noqa: E402
from firmware.generator import DEVICE_ID, get_device_key  # noqa: E402


def enrolment(backend: str) -> dict:
    tpm = open_tpm(backend)
    ak = tpm.get_endorsement_key()
    device_pub = get_device_key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"device_id": DEVICE_ID, "device_pub_hex": device_pub.hex(), "ak_pub_der_hex": ak.public_der.hex(),
            "ak_algorithm": ak.algorithm, "tpm_backend": backend}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tpm", choices=["software", "tpm2-tss"], default="tpm2-tss")
    print(json.dumps(enrolment(ap.parse_args().tpm), indent=2))


if __name__ == "__main__":
    main()
