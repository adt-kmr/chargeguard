import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "db" / "chargeguard.db"
FIRMWARE_DIR = BASE_DIR / "firmware" / "images"
KEYS_DIR = BASE_DIR / "firmware" / "keys"
EVIDENCE_DIR = BASE_DIR / "evidence" / "reports"
POLICY_PATH = BASE_DIR / "policy" / "compliance_map.yaml"
STATIC_DIR = BASE_DIR / "dashboard" / "static"

# 5-second budget: (start_offset, end_offset) from plug-in event
CHECK_TIMINGS = {
    "identity":   (0.0, 1.0),
    "integrity":  (1.0, 2.0),
    "weaknesses": (2.0, 3.0),
    "behavior":   (3.0, 4.5),
    "verdict":    (4.5, 5.0),
}
TOTAL_BUDGET = 5.0

VERDICT_GREEN = "green"
VERDICT_AMBER = "amber"
VERDICT_RED   = "red"

# Charger simulator modes
MODE_HEALTHY      = "healthy"
MODE_TAMPERED     = "tampered"
MODE_VULNERABLE   = "vulnerable"
MODE_COMPROMISED  = "compromised"

DEVICE_ID = "CG-CHARGER-001"
VENDOR    = "ChargeCo"
CHARGER_MODEL = "ChargeCo AC-7 Pro"

# ── Live gateway (OCPP 1.6-J) ───────────────────────────────────────────────
# The ChargeGuard node terminates the charger's OCPP connection, so it sits
# inline and sees every message. In production it forwards to the upstream CSMS.
# demo: sessions start from the dashboard, which launches a simulated charger.
# node: the Raspberry Pi deployment; a session opens whenever a real charger connects,
#       quarantines persist across sessions and the dashboard follows each one.
NODE_MODE = os.environ.get("CHARGEGUARD_NODE_MODE", "demo")
OCPP_HOST = os.environ.get("CHARGEGUARD_OCPP_HOST", "127.0.0.1")   # 0.0.0.0 on the node
OCPP_PORT = 9000
OCPP_PATH = "/ocpp"
HEARTBEAT_INTERVAL_S = 5
ATTESTATION_VENDOR_ID = "org.chargeguard"      # OCPP DataTransfer vendorId

# PCR that holds the charger's firmware measurement. 0 in software mode (a fresh
# software TPM per boot). On a hardware TPM, PCR 0 resets only at power-on, so the
# charger agent measures its launch into the resettable application PCR 23 instead:
# reset, then extend, giving the same value SHA-256(0^32 || SHA-256(image)).
MEASURED_PCR = int(os.environ.get("CHARGEGUARD_MEASURED_PCR", "0"))

# Flow collector: receives IPFIX-style flow records exported by the site
# switch / bridge (simulated by simlab.tap in software mode).
FLOW_SENSOR_HOST = os.environ.get("CHARGEGUARD_FLOW_HOST", "127.0.0.1")
FLOW_SENSOR_PORT = 9100

# Logical site addressing used by the tap simulator and the baseline
SITE = {
    "charger_ip": os.environ.get("CHARGEGUARD_CHARGER_IP", "10.20.0.15"),
    "node_ip":    os.environ.get("CHARGEGUARD_NODE_IP", "10.20.0.1"),   # node: OCPP endpoint, NTP, DNS resolver
}

# Presentation pacing: the real checks take milliseconds. The dashboard holds
# each step until its schedule window ends so the audience can follow it.
# Measured compute time is always reported separately in the evidence.
PRESENTATION_PACING = True

AUDIT_FEED_PATH = BASE_DIR / "audit" / "cve_feed.json"
