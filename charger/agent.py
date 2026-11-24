"""
C10 – Charger agent: an OCPP 1.6-J charge point process.

Runs as its own process, exactly as a charger's controller would: it boots a
firmware image (measured into PCR0 of its TPM), connects to its central
system over WebSocket, and runs the OCPP lifecycle:

    BootNotification -> StatusNotification -> Heartbeat ... ->
    Authorize -> StartTransaction -> MeterValues ... -> StopTransaction

It answers ChargeGuard's attestation request (OCPP DataTransfer, vendorId
org.chargeguard) with a nonce signature from its device key, a TPM quote over
PCR0 and its firmware metadata.

Identity modes emulate the C1 attacks: `clone` claims the genuine device ID
but lacks its keys; `unknown` presents an unenrolled device. OCPP-level
attack modes (`burst`, `c2`) emulate a compromised controller.

    python -m charger.agent --firmware firmware/images/good_v2.1.0.bin
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

import websockets
from ocpp.routing import on
from ocpp.v16 import ChargePoint, call, call_result
from ocpp.v16.enums import (
    Action, AuthorizationStatus, ChargePointErrorCode, ChargePointStatus, DataTransferStatus,
    Reason, RegistrationStatus, RemoteStartStopStatus,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from attestation import PCRSelection  # noqa: E402
from attestation.backends.software import SoftwareTPM  # noqa: E402
from config import (  # noqa: E402
    ATTESTATION_VENDOR_ID, CHARGER_MODEL, DEVICE_ID, OCPP_HOST, OCPP_PATH, OCPP_PORT, VENDOR,
)
from firmware.generator import SIG_OFFSET, attestation_key_path, get_device_key  # noqa: E402

log = logging.getLogger("charger")

C2_VENDOR_ID = "net.updatesvc-cdn"           # attacker-controlled vendor extension
LEGIT_PAYMENT_QR = "https://chargepoint.com/pay/CG-CHARGER-001"
MALICIOUS_PAYMENT_QR = "https://chargepoint-pay.top/verify?station=CG-001"   # quishing: look-alike payment page


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class FirmwareImage:
    """Parses the CGFW header of an image the controller boots."""

    def __init__(self, path: Path):
        self.path = path
        self.raw = path.read_bytes()
        hdr = self.raw[:256]
        self.version = hdr[4:20].rstrip(b"\x00").decode()
        self.vendor = hdr[52:68].rstrip(b"\x00").decode()
        self.payload_hash = hdr[68:100].hex()
        self.vendor_sig = hdr[SIG_OFFSET:SIG_OFFSET + 64].hex()


class ChargerIdentity:
    def __init__(self, mode: str):
        self.mode = mode
        if mode == "legitimate":
            self.device_id = DEVICE_ID
            self.device_key = get_device_key()
            self.tpm = SoftwareTPM(key_path=attestation_key_path(DEVICE_ID))
        elif mode == "clone":                 # copies the ID, cannot copy the keys
            self.device_id = DEVICE_ID
            self.device_key = Ed25519PrivateKey.generate()
            self.tpm = SoftwareTPM()
        else:                                 # unknown / rogue device
            self.device_id = "ROGUE-999"
            self.device_key = Ed25519PrivateKey.generate()
            self.tpm = SoftwareTPM()


class ChargerAgent(ChargePoint):
    def __init__(self, cp_id, connection, args, identity: ChargerIdentity, firmware: FirmwareImage):
        super().__init__(cp_id, connection, response_timeout=15)
        self.args = args
        self.identity = identity
        self.firmware = firmware
        self.attested = asyncio.Event()
        self.remote_stop = asyncio.Event()
        self.transaction_id: int | None = None
        self.energy_wh = 12_480.0             # meter register at plug-in
        self.heartbeat_interval = 5

    # ── CSMS -> charger ──────────────────────────────────────────────────

    @on(Action.data_transfer)
    async def on_data_transfer(self, vendor_id, message_id=None, data=None, **_):
        if vendor_id != ATTESTATION_VENDOR_ID or message_id != "AttestationRequest":
            return call_result.DataTransfer(status=DataTransferStatus.unknown_vendor_id)
        req = json.loads(data or "{}")
        nonce = bytes.fromhex(req["nonce"])
        sel = PCRSelection(indices=tuple(req.get("pcrs", [0])))
        evidence = self.identity.tpm.collect_evidence(self.identity.device_id, nonce, sel)
        body = {
            "device_id": self.identity.device_id,
            "nonce_signature": self.identity.device_key.sign(nonce).hex(),
            "quote": evidence.quote.to_dict(),
            "pcrs": evidence.pcrs.to_dict(),
            "firmware": {"version": self.firmware.version, "vendor": self.firmware.vendor,
                         "payload_sha256": self.firmware.payload_hash,
                         "vendor_signature": self.firmware.vendor_sig},
        }
        self.attested.set()
        return call_result.DataTransfer(status=DataTransferStatus.accepted, data=json.dumps(body))

    @on(Action.remote_stop_transaction)
    async def on_remote_stop(self, transaction_id, **_):
        if self.transaction_id is not None and transaction_id == self.transaction_id:
            self.remote_stop.set()
            return call_result.RemoteStopTransaction(status=RemoteStartStopStatus.accepted)
        return call_result.RemoteStopTransaction(status=RemoteStartStopStatus.rejected)

    # ── charger -> CSMS ──────────────────────────────────────────────────

    async def status(self, status: ChargePointStatus, info: str | None = None):
        await self.call(call.StatusNotification(connector_id=1, error_code=ChargePointErrorCode.no_error,
                                                status=status, timestamp=now(), info=info))

    async def heartbeat_loop(self):
        while True:
            await asyncio.sleep(self.heartbeat_interval)
            await self.call(call.Heartbeat())

    def meter_sample(self, interval_s: float) -> list:
        power_w = 7_200 + random.gauss(0, 60)                   # 7.2 kW single-phase AC
        self.energy_wh += power_w * interval_s / 3600
        current_a = power_w / 230
        return [{"timestamp": now(), "sampledValue": [
            {"value": f"{self.energy_wh:.1f}", "measurand": "Energy.Active.Import.Register", "unit": "Wh"},
            {"value": f"{power_w:.0f}", "measurand": "Power.Active.Import", "unit": "W"},
            {"value": f"{current_a:.2f}", "measurand": "Current.Import", "unit": "A", "phase": "L1"},
            {"value": f"{229 + random.gauss(0, 0.8):.1f}", "measurand": "Voltage", "unit": "V", "phase": "L1"},
        ]}]

    async def run_attack(self):
        kind = self.args.attack
        log.warning("attack starting: %s", kind)
        if kind == "burst":                    # flood the CSMS with meter values
            for _ in range(int(self.args.attack_rate * 3)):
                await self.call(call.MeterValues(connector_id=1, transaction_id=self.transaction_id,
                                                 meter_value=self.meter_sample(0.0)))
                await asyncio.sleep(1 / self.args.attack_rate)
        elif kind == "c2":                     # beacon to an attacker vendor extension
            for i in range(12):
                await self.call(call.DataTransfer(vendor_id=C2_VENDOR_ID, message_id="beacon",
                                                  data=json.dumps({"seq": i, "host": self.identity.device_id})))
                await asyncio.sleep(1.5 + random.uniform(-0.3, 0.3))

    async def lifecycle(self):
        boot = await self.call(call.BootNotification(
            charge_point_model=CHARGER_MODEL, charge_point_vendor=VENDOR,
            firmware_version=self.firmware.version,
            charge_point_serial_number=f"SN-{self.identity.device_id}"))
        if boot.status != RegistrationStatus.accepted:
            log.error("boot rejected")
            return
        self.heartbeat_interval = boot.interval or 5
        await self.status(ChargePointStatus.available)
        asyncio.create_task(self.heartbeat_loop())
        # The idle screen shows a payment QR code; report it to the central system
        await self.call(call.DataTransfer(vendor_id=VENDOR, message_id="DisplayPaymentQR",
                                          data=json.dumps({"url": self.args.payment_qr, "screen": "idle"})))

        try:
            await asyncio.wait_for(self.attested.wait(), timeout=10)
        except asyncio.TimeoutError:
            log.warning("no attestation request received")

        if self.args.attack != "none" and self.args.attack_at == "plugin":
            asyncio.create_task(self.run_attack())

        # Driver plugs in the vehicle
        await asyncio.sleep(self.args.plug_delay)
        await self.status(ChargePointStatus.preparing)
        auth = await self.call(call.Authorize(id_tag=self.args.id_tag))
        if auth.id_tag_info["status"] != AuthorizationStatus.accepted:
            log.warning("authorization %s - charging refused", auth.id_tag_info["status"])
            await self.status(ChargePointStatus.available, info="Authorization refused")
            await asyncio.sleep(self.args.session_seconds)
            return

        start = await self.call(call.StartTransaction(connector_id=1, id_tag=self.args.id_tag,
                                                      meter_start=int(self.energy_wh), timestamp=now()))
        self.transaction_id = start.transaction_id
        await self.status(ChargePointStatus.charging)

        if self.args.attack != "none" and self.args.attack_at == "mid_session":
            async def delayed():
                await asyncio.sleep(self.args.attack_delay)
                await self.run_attack()
            asyncio.create_task(delayed())

        reason, elapsed, interval = Reason.local, 0.0, 2.0
        while elapsed < self.args.session_seconds:
            try:
                await asyncio.wait_for(self.remote_stop.wait(), timeout=interval)
                reason = Reason.remote
                break
            except asyncio.TimeoutError:
                elapsed += interval
                await self.call(call.MeterValues(connector_id=1, transaction_id=self.transaction_id,
                                                 meter_value=self.meter_sample(interval)))

        await self.status(ChargePointStatus.finishing)
        await self.call(call.StopTransaction(meter_stop=int(self.energy_wh), timestamp=now(),
                                             transaction_id=self.transaction_id, reason=reason))
        self.transaction_id = None
        await self.status(ChargePointStatus.available)
        await asyncio.sleep(2)


async def main(args) -> int:
    identity = ChargerIdentity(args.identity)
    firmware = FirmwareImage(Path(args.firmware))
    identity.tpm.extend_pcr(0, firmware.raw)      # measured boot: boot ROM measures the image
    url = f"ws://{args.host}:{args.port}{OCPP_PATH}/{identity.device_id}"
    log.info("booted firmware %s (payload %s...), connecting to %s",
             firmware.version, firmware.payload_hash[:12], url)
    try:
        async with websockets.connect(url, subprotocols=["ocpp1.6"], open_timeout=10) as ws:
            agent = ChargerAgent(identity.device_id, ws, args, identity, firmware)
            receiver = asyncio.create_task(agent.start())
            try:
                await agent.lifecycle()
            finally:
                receiver.cancel()
    except websockets.ConnectionClosed as e:
        log.warning("connection closed by central system: code=%s reason=%s", e.code, e.reason)
        return 3
    except OSError as e:
        log.error("cannot reach central system: %s", e)
        return 2
    return 0


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="OCPP 1.6 charger agent")
    ap.add_argument("--firmware", default=str(ROOT / "firmware" / "images" / "good_v2.1.0.bin"))
    ap.add_argument("--identity", choices=["legitimate", "clone", "unknown"], default="legitimate")
    ap.add_argument("--host", default=OCPP_HOST)
    ap.add_argument("--port", type=int, default=OCPP_PORT)
    ap.add_argument("--id-tag", default="RFID-04A2C1F9")
    ap.add_argument("--attack", choices=["none", "burst", "c2"], default="none")
    ap.add_argument("--attack-at", choices=["plugin", "mid_session"], default="plugin")
    ap.add_argument("--attack-delay", type=float, default=6.0, help="seconds into the session (mid_session)")
    ap.add_argument("--attack-rate", type=float, default=40.0, help="messages per second (burst)")
    ap.add_argument("--plug-delay", type=float, default=0.5)
    ap.add_argument("--session-seconds", type=float, default=40.0)
    ap.add_argument("--payment-qr", default=LEGIT_PAYMENT_QR, help="URL encoded in the screen's payment QR code")
    return ap.parse_args(argv)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s charger %(levelname)s %(message)s")
    sys.exit(asyncio.run(main(parse_args())))
