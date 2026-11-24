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
