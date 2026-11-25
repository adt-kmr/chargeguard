"""
Minimal, dependency-free packet parsing for the node's bridge: Ethernet (with 802.1Q),
IPv4, TCP, UDP, ICMP, and the query type of DNS questions. Enough to build NetFlow
records; anything else is counted as "other" and skipped.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

ETH_IPV4, ETH_VLAN = 0x0800, 0x8100
TCP, UDP, ICMP = 6, 17, 1


@dataclass(slots=True)
class Packet:
    ts: float              # seconds
    src: str
    dst: str
    proto: int             # IP protocol number
    sport: int
    dport: int
    length: int            # IP total length (layer-3 bytes, as NetFlow counts them)
    tcp_flags: int = 0
    ttl: int = 0
    icmp_type: int = 0     # type * 256 + code, as nProbe reports ICMP_TYPE
    dns_qtype: int = 0     # first question's QTYPE for DNS (port 53)
    dns_qname: str = ""


def _ip(b: bytes) -> str:
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"


def _dns_question(payload: bytes) -> tuple[int, str]:
    """QTYPE and QNAME of the first question in a DNS message (0, '' if malformed)."""
    if len(payload) < 12 or struct.unpack("!H", payload[4:6])[0] == 0:
        return 0, ""
    i, labels = 12, []
    while i < len(payload):
        n = payload[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 or i + 1 + n > len(payload) or len(labels) > 64:
            return 0, ""
        labels.append(payload[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    if i + 2 > len(payload):
        return 0, ""
    return struct.unpack("!H", payload[i:i + 2])[0], ".".join(labels)


def parse_ipv4(ts: float, ip: bytes) -> Packet | None:
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    proto, ttl = ip[9], ip[8]
    src, dst = _ip(ip[12:16]), _ip(ip[16:20])
    frag_offset = struct.unpack("!H", ip[6:8])[0] & 0x1FFF
    l4 = ip[ihl:]
    pkt = Packet(ts, src, dst, proto, 0, 0, total or len(ip), ttl=ttl)
    if frag_offset:                          # non-first fragment: no L4 header
        return pkt
    if proto == TCP and len(l4) >= 14:
        pkt.sport, pkt.dport = struct.unpack("!HH", l4[0:4])
        pkt.tcp_flags = l4[13]
    elif proto == UDP and len(l4) >= 8:
        pkt.sport, pkt.dport = struct.unpack("!HH", l4[0:4])
        if 53 in (pkt.sport, pkt.dport):
            pkt.dns_qtype, pkt.dns_qname = _dns_question(l4[8:])
    elif proto == ICMP and len(l4) >= 2:
        pkt.icmp_type = l4[0] * 256 + l4[1]
    return pkt


def parse_ethernet(ts: float, frame: bytes) -> Packet | None:
    if len(frame) < 14:
        return None
    etype, off = struct.unpack("!H", frame[12:14])[0], 14
    if etype == ETH_VLAN and len(frame) >= 18:
        etype, off = struct.unpack("!H", frame[16:18])[0], 18
    if etype != ETH_IPV4:
        return None
    return parse_ipv4(ts, frame[off:])


# ── building packets (tests, simulator, pcap writer) ───────────────────────

def _csum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _aton(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


def build_frame(src: str, dst: str, proto: int, sport: int = 0, dport: int = 0, payload: bytes = b"",
                flags: int = 0, ttl: int = 64, icmp: tuple[int, int] = (8, 0)) -> bytes:
    """An Ethernet/IPv4 frame with a TCP, UDP or ICMP header and payload."""
    if proto == TCP:
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 64240, 0, 0) + payload
    elif proto == UDP:
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    elif proto == ICMP:
        l4 = struct.pack("!BBHI", icmp[0], icmp[1], 0, 0) + payload
    else:
        l4 = payload
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0x4000, ttl, proto, 0, _aton(src), _aton(dst))
    hdr = hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + struct.pack("!H", ETH_IPV4) + hdr + l4


def dns_query(qname: str, qtype: int = 1, qid: int = 0x1234) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".") if p) + b"\0"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)
