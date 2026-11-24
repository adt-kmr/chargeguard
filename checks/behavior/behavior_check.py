"""
C4 – Live Behavior Monitor
Compares the charger's live traffic sample against the expected baseline.
Anomalies: unexpected destinations, excessive rates, unexpected protocols.
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Expected behavior baseline for a healthy charger
BASELINE = {
    "allowed_peers": {"127.0.0.1", "localhost", "::1"},
    "allowed_ports": {8080, 8000, 443},
    "allowed_protos": {"OCPP", "HEARTBEAT", "STATUS", "METER"},
    "max_msg_rate_per_sec": 5,
    "allowed_outbound_hosts": set(),   # no outbound internet expected
}


async def run(simulator) -> object:
    import time
    from checks.identity.identity_check import CheckResult
    t0 = time.monotonic()

    # Collect traffic sample (1-second window)
    await asyncio.sleep(0.5)
    traffic = simulator.get_traffic_sample()
    await asyncio.sleep(0.5)

    anomalies = []

    for pkt in traffic:
        dst   = pkt.get("dst", "")
        port  = pkt.get("port", 0)
        proto = pkt.get("proto", "")
        rate  = pkt.get("rate", 0)

        if dst and dst not in BASELINE["allowed_peers"] and dst != "":
            anomalies.append(
                f"Unexpected outbound connection to '{dst}' (not in baseline peer set)"
            )

        if port and port not in BASELINE["allowed_ports"]:
            anomalies.append(
                f"Unexpected port {port} — baseline allows {sorted(BASELINE['allowed_ports'])}"
            )

        if proto and proto not in BASELINE["allowed_protos"]:
            anomalies.append(
                f"Unknown protocol '{proto}' — not part of OCPP/HEARTBEAT baseline"
            )

        if rate > BASELINE["max_msg_rate_per_sec"]:
            anomalies.append(
                f"Message burst detected: {rate} msg/s (threshold {BASELINE['max_msg_rate_per_sec']})"
            )

    # Deduplicate
    anomalies = list(dict.fromkeys(anomalies))

    if anomalies:
        return CheckResult(
            "behavior", "fail",
            f"Anomalous traffic detected: {anomalies[0]}",
            evidence={
                "anomalies":     anomalies,
                "sample_events": len(traffic),
                "baseline":      {
                    "allowed_peers": list(BASELINE["allowed_peers"]),
                    "max_rate":      BASELINE["max_msg_rate_per_sec"],
                },
            },
            timing=time.monotonic() - t0,
        )

    return CheckResult(
        "behavior", "pass",
        f"Traffic nominal — {len(traffic)} events match OCPP heartbeat baseline.",
        evidence={
            "sample_events": len(traffic),
            "protos_seen":   list({p.get("proto") for p in traffic if p.get("proto")}),
        },
        timing=time.monotonic() - t0,
    )
