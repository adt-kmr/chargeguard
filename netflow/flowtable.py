"""
Bidirectional flow table that turns packets into NetFlow-style records.

Field names follow the NetFlow v1 feature set of the NF-UNSW-NB15 datasets (nProbe),
which the traffic classifier is trained on, plus a few extended fields the node uses
for rules and explanations:

  IN_BYTES / IN_PKTS      client -> server (the side that sent the first packet)
  OUT_BYTES / OUT_PKTS    server -> client
  TCP_FLAGS               OR of all TCP flags in both directions
  CLIENT_TCP_FLAGS, SERVER_TCP_FLAGS   per direction
  FLOW_DURATION_MILLISECONDS           last packet - first packet
  LONGEST_FLOW_PKT, SHORTEST_FLOW_PKT  IP packet lengths
  DNS_QUERY_TYPE, ICMP_TYPE

A flow is exported when it has been idle for `idle_timeout`, has been active for
`active_timeout`, or (TCP) after FIN/RST plus a short linger.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .packets import TCP, Packet

FIN, SYN, RST = 0x01, 0x02, 0x04


@dataclass
class Flow:
    client: tuple[str, int]
    server: tuple[str, int]
    proto: int
    first: float
    last: float
    in_bytes: int = 0
    out_bytes: int = 0
    in_pkts: int = 0
    out_pkts: int = 0
    client_flags: int = 0
    server_flags: int = 0
    longest: int = 0
    shortest: int = 1 << 30
    icmp_type: int = 0
    dns_qtype: int = 0
    dns_qname: str = ""
    closed_at: float | None = None
    extra: dict = field(default_factory=dict)

    def add(self, p: Packet, from_client: bool):
        self.last = p.ts
        if from_client:
            self.in_bytes += p.length
            self.in_pkts += 1
            self.client_flags |= p.tcp_flags
        else:
            self.out_bytes += p.length
            self.out_pkts += 1
            self.server_flags |= p.tcp_flags
        self.longest = max(self.longest, p.length)
        self.shortest = min(self.shortest, p.length)
        if p.icmp_type and not self.icmp_type:
            self.icmp_type = p.icmp_type
        if p.dns_qtype and not self.dns_qtype:
            self.dns_qtype, self.dns_qname = p.dns_qtype, p.dns_qname
        if self.proto == TCP and p.tcp_flags & (FIN | RST) and self.closed_at is None:
            self.closed_at = p.ts

    def record(self) -> dict:
        return {
            "IPV4_SRC_ADDR": self.client[0], "L4_SRC_PORT": self.client[1],
            "IPV4_DST_ADDR": self.server[0], "L4_DST_PORT": self.server[1],
            "PROTOCOL": self.proto,
            "IN_BYTES": self.in_bytes, "OUT_BYTES": self.out_bytes,
            "IN_PKTS": self.in_pkts, "OUT_PKTS": self.out_pkts,
            "TCP_FLAGS": self.client_flags | self.server_flags,
            "CLIENT_TCP_FLAGS": self.client_flags, "SERVER_TCP_FLAGS": self.server_flags,
            "FLOW_DURATION_MILLISECONDS": int(round((self.last - self.first) * 1000)),
            "LONGEST_FLOW_PKT": self.longest, "SHORTEST_FLOW_PKT": 0 if self.shortest == 1 << 30 else self.shortest,
            "ICMP_TYPE": self.icmp_type, "DNS_QUERY_TYPE": self.dns_qtype,
            "FIRST_SWITCHED": self.first, "LAST_SWITCHED": self.last,
            **({"DNS_QUERY_NAME": self.dns_qname} if self.dns_qname else {}),
        }


class FlowTable:
    def __init__(self, idle_timeout: float = 15.0, active_timeout: float = 60.0, tcp_linger: float = 1.0,
                 max_flows: int = 65536):
        self.idle, self.active, self.linger, self.max_flows = idle_timeout, active_timeout, tcp_linger, max_flows
        self.flows: dict[tuple, Flow] = {}
        self.evicted = 0

    @staticmethod
    def _key(p: Packet) -> tuple:
        a, b = (p.src, p.sport), (p.dst, p.dport)
        return (p.proto,) + ((a, b) if a <= b else (b, a))

    def add(self, p: Packet) -> list[dict]:
        """Account one packet; returns records of flows that expired as a result."""
        out = self.expire(p.ts)
        k = self._key(p)
        f = self.flows.get(k)
        if f is None:
            if len(self.flows) >= self.max_flows:          # bounded memory: export the oldest
                oldest = min(self.flows, key=lambda x: self.flows[x].last)
                out.append(self.flows.pop(oldest).record())
                self.evicted += 1
            f = self.flows[k] = Flow((p.src, p.sport), (p.dst, p.dport), p.proto, p.ts, p.ts)
        f.add(p, from_client=(p.src, p.sport) == f.client)
        return out

    def expire(self, now: float) -> list[dict]:
        done = [k for k, f in self.flows.items()
                if now - f.last >= self.idle or now - f.first >= self.active
                or (f.closed_at is not None and now - f.closed_at >= self.linger)]
        return [self.flows.pop(k).record() for k in done]

    def flush(self) -> list[dict]:
        out = [f.record() for f in self.flows.values()]
        self.flows.clear()
        return out
