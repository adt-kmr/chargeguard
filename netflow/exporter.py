"""
Flow exporter: packets from the bridge (or a pcap) -> NetFlow records -> the node's
flow collector (UDP JSON, gateway/sensor.py).

    sudo python -m netflow.exporter --iface eth1              # on the Raspberry Pi node
    python -m netflow.exporter --pcap capture.pcap            # replay a capture

Each datagram carries the node's flow-record fields (src, dst, sport, dport, proto,
app, bytes, pkts, qname) for the behaviour rules, plus the full NetFlow record under
"nf" for the traffic classifier.
"""
from __future__ import annotations

import argparse
import json
import socket
import time

from .flowtable import FlowTable
from .packets import ICMP, TCP, UDP
from .sources import live, read_pcap

PROTO_NAMES = {TCP: "TCP", UDP: "UDP", ICMP: "ICMP"}
APP_PORTS = {53: "DNS", 123: "NTP", 9000: "OCPP", 8080: "OCPP", 443: "TLS", 80: "HTTP"}


def to_node_record(nf: dict, charger_ip: str | None = None) -> dict:
    """Map a NetFlow record onto the node's flow schema, oriented from the charger."""
    src, dst = nf["IPV4_SRC_ADDR"], nf["IPV4_DST_ADDR"]
    sport, dport = nf["L4_SRC_PORT"], nf["L4_DST_PORT"]
    if charger_ip and dst == charger_ip and src != charger_ip:   # inbound connection to the charger
        src, dst, sport, dport = dst, src, dport, sport
    proto = PROTO_NAMES.get(nf["PROTOCOL"], str(nf["PROTOCOL"]))
    app = APP_PORTS.get(nf["L4_DST_PORT"]) or APP_PORTS.get(nf["L4_SRC_PORT"]) or proto
    rec = {"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto, "app": app,
           "bytes": nf["IN_BYTES"] + nf["OUT_BYTES"], "pkts": nf["IN_PKTS"] + nf["OUT_PKTS"], "nf": nf}
    if nf.get("DNS_QUERY_NAME"):
        rec["qname"] = nf["DNS_QUERY_NAME"]
    if proto == "TCP" and nf["CLIENT_TCP_FLAGS"] == 0x02 and nf["SERVER_TCP_FLAGS"] in (0, 0x14):
        rec["flags"] = "S"                                          # unanswered or refused SYN
    return rec


class Exporter:
    def __init__(self, host: str, port: int, charger_ip: str | None = None, **table_kw):
        self.addr, self.charger_ip = (host, port), charger_ip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.table = FlowTable(**table_kw)
        self.sent = 0

    def emit(self, records: list[dict]):
        for nf in records:
            self.sock.sendto(json.dumps(to_node_record(nf, self.charger_ip)).encode(), self.addr)
            self.sent += 1

    def run(self, packets, realtime: bool = True):
        for p in packets:
            if p is None:                                   # idle tick from a live source
                self.emit(self.table.expire(time.time()))
                continue
            self.emit(self.table.add(p))
        self.emit(self.table.flush())


def main():
    from config import FLOW_SENSOR_HOST, FLOW_SENSOR_PORT, SITE
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="bridge port facing the charger, e.g. eth1")
    src.add_argument("--pcap", help="classic pcap file to replay")
    ap.add_argument("--collector", default=f"{FLOW_SENSOR_HOST}:{FLOW_SENSOR_PORT}")
    ap.add_argument("--charger-ip", default=SITE["charger_ip"])
    ap.add_argument("--idle", type=float, default=15.0)
    ap.add_argument("--active", type=float, default=60.0)
    a = ap.parse_args()
    host, port = a.collector.rsplit(":", 1)
    ex = Exporter(host, int(port), a.charger_ip, idle_timeout=a.idle, active_timeout=a.active)
    ex.run(live(a.iface) if a.iface else read_pcap(a.pcap))
    print(f"exported {ex.sent} flow records")


if __name__ == "__main__":
    main()
