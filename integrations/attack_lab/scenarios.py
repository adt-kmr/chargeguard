"""
C9 attack catalogue: repeatable attacks, the tool behind each, and the
ChargeGuard check expected to catch it.

For authorised testing on lab equipment you own only. Wireless and USB tools
(Bruce on ESP32, Facedancer) run on separate hardware; their source is
vendored under third_party/attack-lab/ for building and auditing, and is
never invoked automatically by ChargeGuard.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class AttackScenario:
    id: str
    title: str
    tool: str                    # what produces the attack
    vendored: str | None         # path under third_party/, if any
    target_check: str            # C1..C4 check expected to fire
    expected_verdict: str        # green / amber / red
    automated: bool              # can run unattended in CI
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


SCENARIOS: dict[str, AttackScenario] = {s.id: s for s in [
    AttackScenario("tampered-firmware", "Bit-flipped firmware with original signature",
                   "firmware/generator.py (in-house)", None, "C2", "red", True),
    AttackScenario("rogue-identity", "Unknown or cloned device key",
                   "simulator AttackConfig", None, "C1", "red", True),
    AttackScenario("vulnerable-target", "Realistic vulnerable firmware (OpenWrt-based)",
                   "IoTGoat", "attack-lab/iotgoat", "C3", "amber", True,
                   "Build the image from source or use a release image; feed it to FirmwareAudit."),
    AttackScenario("emulated-controller", "Charger MCU running tampered firmware in emulation",
                   "Renode", "attack-lab/renode", "C2", "red", True,
                   "integrations.attack_lab.renode.boot_firmware"),
    AttackScenario("wireless-attack", "Wi-Fi/BLE deauth, rogue AP, or spoofing near the charger",
                   "Bruce (ESP32)", "attack-lab/bruce", "C4", "red", False,
                   "Flash to an ESP32 board; run only in a shielded lab or on your own network."),
    AttackScenario("usb-attack", "Malicious USB device on the charger service port",
                   "Facedancer", "attack-lab/facedancer", "C4", "red", False,
                   "Requires GreatFET/Cynthion hardware."),
    AttackScenario("c2-beacon", "Outbound command-and-control beacon",
                   "simulator behavior_attack=c2", None, "C4", "red", True),
    AttackScenario("dns-exfil", "Data exfiltration over DNS",
                   "simulator behavior_attack=dns_exfil", None, "C4", "red", True),
]}


def automated() -> list[AttackScenario]:
    return [s for s in SCENARIOS.values() if s.automated]
