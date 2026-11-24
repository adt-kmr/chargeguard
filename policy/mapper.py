"""
C6 – Compliance Mapper
Loads the YAML compliance map and annotates each check result
with the standards controls it covers.
"""
import sys
from pathlib import Path
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import POLICY_PATH

_MAP = None


def _load() -> dict:
    global _MAP
    if _MAP is None:
        with open(POLICY_PATH, "r", encoding="utf-8") as f:
            _MAP = yaml.safe_load(f)
    return _MAP


def annotate(check_name: str, result_dict: dict) -> dict:
    """Add a 'compliance' key to the result dict listing applicable controls."""
    policy = _load()
    checks = policy.get("checks", {})
    check_policy = checks.get(check_name, {})
    result_dict["compliance"] = check_policy.get("controls", [])
    return result_dict


def get_all_controls() -> dict:
    """Return the full mapping {check_name: [controls]}."""
    policy = _load()
    return {
        name: info.get("controls", [])
        for name, info in policy.get("checks", {}).items()
    }
