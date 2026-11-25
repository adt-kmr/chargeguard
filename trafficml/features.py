"""
Flow features for the traffic classifier. One function, used for training (NF-UNSW-NB15
rows) and on the node (records from netflow.FlowTable), so both see identical inputs.

Only fields a NetFlow exporter on the node's bridge measures reliably are used:
bytes and packets each way, duration, TCP flags, protocol class and destination-port
class. Deliberately excluded, because in the training data they identify the testbed
rather than the behaviour:

  IP addresses     every attack in NF-UNSW-NB15 comes from 175.45.176.0/24
  source port      ephemeral, testbed-specific
  TTL, TCP window  operating-system fingerprints of the attack hosts (v2)
  L7_PROTO         needs nDPI on the node; the port class carries most of it
  exotic protocols attacks use all 256 protocol numbers; folded into "other"
"""
from __future__ import annotations

import math

import numpy as np

FLAG_BITS = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
PROTOS = {6: "tcp", 17: "udp", 1: "icmp"}
PORT_CLASSES = [
    ("port0", {0}), ("dns", {53}), ("http", {80, 8080, 8000}), ("https", {443, 8443}), ("ssh", {22}),
    ("telnet", {23}), ("ftp", {20, 21}), ("smtp", {25, 587, 465}), ("ntp", {123}), ("smb_rpc", {111, 135, 137, 138, 139, 445}),
    ("mail_read", {110, 143, 993, 995}), ("rdp_vnc", {3389, 5900}), ("ics_iot", {502, 1883, 8883, 20000, 47808}),
]
MAX_DURATION_MS = 3_600_000          # longer values are exporter wrap-arounds (2^32 - small)

NAMES = (["log_in_bytes", "log_out_bytes", "log_in_pkts", "log_out_pkts", "log_duration_ms",
          "log_in_bytes_per_pkt", "log_out_bytes_per_pkt", "log_out_in_byte_ratio", "log_out_in_pkt_ratio",
          "no_reply", "log_pkt_rate"]
         + [f"flag_{f}" for f in FLAG_BITS]
         + [f"proto_{p}" for p in ("tcp", "udp", "icmp", "other")]
         + [f"dport_{n}" for n, _ in PORT_CLASSES] + ["dport_other_wellknown", "dport_registered", "dport_dynamic"])
DIM = len(NAMES)


def port_class(port: int) -> str:
    for name, ports in PORT_CLASSES:
        if port in ports:
            return name
    if port < 1024:
        return "other_wellknown"
    return "registered" if port < 49152 else "dynamic"


_INDEX = {n: i for i, n in enumerate(NAMES)}


def vector(nf: dict) -> np.ndarray:
    """Feature vector for one NetFlow record (dict with NF-UNSW-NB15 v1 field names)."""
    x = np.zeros(DIM, dtype=np.float32)
    ib, ob = float(nf["IN_BYTES"]), float(nf["OUT_BYTES"])
    ip, op = float(nf["IN_PKTS"]), float(nf["OUT_PKTS"])
    dur = min(float(nf["FLOW_DURATION_MILLISECONDS"]), MAX_DURATION_MS)
    x[0], x[1], x[2], x[3] = math.log1p(ib), math.log1p(ob), math.log1p(ip), math.log1p(op)
    x[4] = math.log1p(dur)
    x[5] = math.log1p(ib / ip) if ip else 0.0
    x[6] = math.log1p(ob / op) if op else 0.0
    x[7] = math.log((ob + 1) / (ib + 1))
    x[8] = math.log((op + 1) / (ip + 1))
    x[9] = 1.0 if op == 0 else 0.0
    x[10] = math.log1p((ip + op) / (dur / 1000 + 0.001))
    flags = int(nf.get("TCP_FLAGS", 0))
    for i in range(8):
        x[11 + i] = (flags >> i) & 1
    x[_INDEX["proto_" + PROTOS.get(int(nf["PROTOCOL"]), "other")]] = 1.0
    x[_INDEX["dport_" + port_class(int(nf["L4_DST_PORT"]))]] = 1.0
    return x


def matrix(df) -> np.ndarray:
    """Vectorised `vector` for a pandas DataFrame of NetFlow rows (training)."""
    ib, ob = df.IN_BYTES.to_numpy(float), df.OUT_BYTES.to_numpy(float)
    ip, op = df.IN_PKTS.to_numpy(float), df.OUT_PKTS.to_numpy(float)
    dur = np.minimum(df.FLOW_DURATION_MILLISECONDS.to_numpy(float), MAX_DURATION_MS)
    X = np.zeros((len(df), DIM), dtype=np.float32)
    X[:, 0], X[:, 1], X[:, 2], X[:, 3] = np.log1p(ib), np.log1p(ob), np.log1p(ip), np.log1p(op)
    X[:, 4] = np.log1p(dur)
    with np.errstate(divide="ignore", invalid="ignore"):
        X[:, 5] = np.where(ip > 0, np.log1p(ib / np.maximum(ip, 1)), 0)
        X[:, 6] = np.where(op > 0, np.log1p(ob / np.maximum(op, 1)), 0)
    X[:, 7] = np.log((ob + 1) / (ib + 1))
    X[:, 8] = np.log((op + 1) / (ip + 1))
    X[:, 9] = (op == 0)
    X[:, 10] = np.log1p((ip + op) / (dur / 1000 + 0.001))
    flags = df.TCP_FLAGS.to_numpy(int)
    for i in range(8):
        X[:, 11 + i] = (flags >> i) & 1
    proto = df.PROTOCOL.to_numpy(int)
    X[:, _INDEX["proto_tcp"]] = proto == 6
    X[:, _INDEX["proto_udp"]] = proto == 17
    X[:, _INDEX["proto_icmp"]] = proto == 1
    X[:, _INDEX["proto_other"]] = ~np.isin(proto, [6, 17, 1])
    classes = np.array([_INDEX["dport_" + port_class(p)] for p in range(65536)])
    X[np.arange(len(df)), classes[df.L4_DST_PORT.to_numpy(int)]] = 1.0
    return X
