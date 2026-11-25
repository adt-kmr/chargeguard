"""
Synthetic packet sequences for a charger's traffic, healthy and hostile.

The simulator (simlab/tap.py) builds these packets and runs them through the same
FlowTable that aggregates real packets on the node's bridge, so software mode exercises
the real capture-to-record path. Frames are genuine Ethernet/IPv4/TCP/UDP bytes, so they
can also be written to a pcap and replayed with `python -m netflow.exporter --pcap`.
"""
from __future__ import annotations

import random

from .packets import TCP, UDP, build_frame, dns_query

SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04
Frames = list[tuple[float, bytes]]


def _payload(n: int) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(max(0, n)))


def tcp_session(c: str, s: str, sport: int, dport: int, t: float, exchanges: list[tuple[int, int]],
                rtt: float = 0.002, close: bool = True, handshake: bool = True) -> Frames:
    """A TCP conversation: optional handshake, request/response exchanges (bytes each way), FIN."""
    out: Frames = []
    if handshake:
        out += [(t, build_frame(c, s, TCP, sport, dport, flags=SYN)),
                (t + rtt, build_frame(s, c, TCP, dport, sport, flags=SYN | ACK)),
                (t + 1.5 * rtt, build_frame(c, s, TCP, sport, dport, flags=ACK))]
        t += 2 * rtt
    for req, resp in exchanges:
        for chunk in _split(req):
            out.append((t, build_frame(c, s, TCP, sport, dport, _payload(chunk), flags=PSH | ACK)))
            t += 0.0002
        t += rtt
        for chunk in _split(resp):
            out.append((t, build_frame(s, c, TCP, dport, sport, _payload(chunk), flags=PSH | ACK)))
            t += 0.0002
        out.append((t + rtt / 2, build_frame(c, s, TCP, sport, dport, flags=ACK)))
        t += rtt
    if close:
        out += [(t, build_frame(c, s, TCP, sport, dport, flags=FIN | ACK)),
                (t + rtt, build_frame(s, c, TCP, dport, sport, flags=FIN | ACK)),
                (t + 1.5 * rtt, build_frame(c, s, TCP, sport, dport, flags=ACK))]
    return out


def _split(n: int, mss: int = 1448) -> list[int]:
    return [mss] * (n // mss) + ([n % mss] if n % mss else []) if n > 0 else []


def syn_probe(c: str, s: str, sport: int, dport: int, t: float, state: str = "closed", rtt: float = 0.001) -> Frames:
    """One port-scan probe: SYN, then RST|ACK (closed), SYN|ACK + RST (open) or nothing (filtered)."""
    out = [(t, build_frame(c, s, TCP, sport, dport, flags=SYN))]
    if state == "closed":
        out.append((t + rtt, build_frame(s, c, TCP, dport, sport, flags=RST | ACK)))
    elif state == "open":
        out += [(t + rtt, build_frame(s, c, TCP, dport, sport, flags=SYN | ACK)),
                (t + 1.5 * rtt, build_frame(c, s, TCP, sport, dport, flags=RST))]
    return out


def udp_exchange(c: str, s: str, sport: int, dport: int, t: float, req: bytes, resp: bytes | None,
                 rtt: float = 0.002) -> Frames:
    out = [(t, build_frame(c, s, UDP, sport, dport, req))]
    if resp is not None:
        out.append((t + rtt, build_frame(s, c, UDP, dport, sport, resp)))
    return out


def dns_lookup(c: str, resolver: str, sport: int, qname: str, t: float, qtype: int = 1, answered: bool = True) -> Frames:
    q = dns_query(qname, qtype, random.getrandbits(16))
    return udp_exchange(c, resolver, sport, 53, t, q, q + _payload(16 if qtype == 1 else 60) if answered else None)


def ntp_sync(c: str, server: str, sport: int, t: float) -> Frames:
    return udp_exchange(c, server, sport, 123, t, _payload(48), _payload(48))


def ocpp_slice(charger: str, node: str, sport: int, t: float, messages: int, avg: int = 120) -> Frames:
    """One second of an established OCPP WebSocket: small frames each way, no handshake."""
    out: Frames = []
    for i in range(messages):
        req = max(40, int(random.gauss(avg, avg * 0.25)))
        out += tcp_session(charger, node, sport, 9000, t + i * (1.0 / max(messages, 1)),
                           [(req, max(30, int(req * 0.4)))], rtt=0.003, close=False, handshake=False)
    return out


def c2_beacon(charger: str, c2: str, sport: int, t: float, port: int = 4444) -> Frames:
    return tcp_session(charger, c2, sport, port, t, [(random.randint(150, 320), random.randint(60, 400))], rtt=0.08)


def flows_of(frames: Frames, **table_kw) -> list[dict]:
    """Aggregate frames (in time order) into NetFlow records with a private flow table."""
    from .flowtable import FlowTable
    from .packets import parse_ethernet
    table = FlowTable(**table_kw)
    out: list[dict] = []
    for ts, fr in sorted(frames, key=lambda x: x[0]):
        p = parse_ethernet(ts, fr)
        if p:
            out += table.add(p)
    return out + table.flush()
