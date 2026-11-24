from pathlib import Path

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "db" / "chargeguard.db"
FIRMWARE_DIR = BASE_DIR / "firmware" / "images"
KEYS_DIR = BASE_DIR / "firmware" / "keys"
EVIDENCE_DIR = BASE_DIR / "evidence" / "reports"
POLICY_PATH = BASE_DIR / "policy" / "compliance_map.yaml"
STATIC_DIR = BASE_DIR / "dashboard" / "static"
