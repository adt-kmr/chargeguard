"""
Flow collector (UDP, JSON flow records).

On the Raspberry Pi node, flow records come from the inline bridge (or the
site switch's IPFIX export). In software mode, simlab.tap produces the same
records. Each record:

    {"src": "10.20.0.15", "dst": "203.0.113.66", "sport": 51234, "dport": 4444,
     "proto": "TCP", "app": "TCP", "bytes": 312, "pkts": 4, "qname": null}
"""
from __future__ import annotations

import asyncio
import json
import time


class FlowCollector(asyncio.DatagramProtocol):
    def __init__(self, get_session):
        self.get_session = get_session
        self.received = 0

    def datagram_received(self, data: bytes, addr):
        session = self.get_session()
        if session is None:
            return
        try:
            rec = json.loads(data.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        rec["rx"] = time.monotonic()
        session.flows.append(rec)
        self.received += 1


async def start_collector(host: str, port: int, get_session):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(lambda: FlowCollector(get_session),
                                                              local_addr=(host, port))
    return transport, protocol
