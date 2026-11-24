"""
Traffic sources that feed the baseline engine.

iotaudit – analyses a pcap for plaintext traffic, open ports and outbound
           destinations. Only run against devices and networks you own.
tshark   – Wireshark's CLI; used for MQTT dissection when the charger speaks
           MQTT. Wireshark itself is not vendored (1.5 GB); install it from
           the OS package manager.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..core import Tool, ToolResult, register_tool, run, run_json, timed

IOTAUDIT = register_tool(Tool(
    "iotaudit", ("iotaudit",), "C4", vendored="network-monitor/iotaudit", python_module="iotaudit",
    install_hint="pip install -e third_party/network-monitor/iotaudit"))
TSHARK = register_tool(Tool(
    "tshark", ("tshark",), "C4",
    install_hint="Install Wireshark/tshark (apt install tshark, or the Wireshark installer on Windows)."))


def iotaudit_pcap(pcap: str | Path, out_dir: str | Path, timeout: float = 300) -> ToolResult:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    html, js = out_dir / "iotaudit.html", out_dir / "iotaudit.json"
    result = ToolResult(tool="iotaudit", ok=True)
    with timed(result):
        run(IOTAUDIT, ["analyze", pcap, "--out", html, "--json", js], timeout=timeout)
        result.artifacts.update(html=str(html), json=str(js))
        result.raw = json.loads(js.read_text())
    return result


def mqtt_messages(pcap: str | Path, timeout: float = 60) -> ToolResult:
    """Extract MQTT packets as flow records (dst, port, proto, message, topic)."""
    result = ToolResult(tool="tshark", ok=True)
    with timed(result):
        pkts = run_json(TSHARK, ["-r", pcap, "-Y", "mqtt", "-T", "json",
                                 "-e", "ip.dst", "-e", "tcp.dstport", "-e", "mqtt.msgtype",
                                 "-e", "mqtt.topic", "-e", "tls.record.content_type"], timeout=timeout)
        flows = []
        for p in pkts:
            f = p.get("_source", {}).get("layers", {})
            first = lambda k: (f.get(k) or [None])[0]  # noqa: E731
            flows.append({"dst": first("ip.dst"), "port": int(first("tcp.dstport") or 0),
                          "proto": "MQTT", "message": first("mqtt.msgtype"),
                          "topic": first("mqtt.topic"),
                          "encrypted": first("tls.record.content_type") is not None})
        result.raw = flows
    return result


def flows_from_pcap_summary(iotaudit_json: dict) -> list[dict]:
    """Best-effort conversion of an iotaudit result into baseline flow records."""
    flows = []
    for dev in iotaudit_json.get("devices", []) or [iotaudit_json]:
        for d in dev.get("destinations", []) or []:
            flows.append({"dst": d.get("ip") or d.get("domain"), "port": d.get("port"),
                          "proto": (d.get("protocol") or "").upper() or None,
                          "encrypted": d.get("encrypted")})
    return flows
