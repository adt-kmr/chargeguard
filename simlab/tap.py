"""
Network tap simulator: exports flow records for the charger's port, the way
the inline bridge (or a switch's IPFIX exporter) does on the real site.

Background traffic models a healthy charger: its persistent OCPP WebSocket to
the node, periodic NTP and occasional DNS to the site resolver. Attack
profiles add the traffic a compromised controller produces:

  port_scan  TCP SYN sweep of a LAN host (one short flow per port)
  c2         periodic beacon to an external host on 4444/tcp with jitter
  dns_exfil  high-rate DNS to a public resolver with long encoded labels

External addresses use the documentation ranges (RFC 5737) unless the
operator sets a target.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import socket

from config import FLOW_SENSOR_HOST, FLOW_SENSOR_PORT, SITE

C2_HOST = "203.0.113.66"
PUBLIC_RESOLVER = "8.8.8.8"
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 502, 1883, 3389, 5900, 8080, 8443, 9100]


class Tap:
    def __init__(self, attack: str = "none", target: str = "192.168.1.254", rate: int = 50,
                 start_delay: float = 0.0):
        self.attack, self.target, self.rate, self.start_delay = attack, target, max(1, rate), start_delay
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sent = 0
        self._sport = random.randint(40000, 60000)

    def _emit(self, dst: str, dport: int, proto: str, app: str, nbytes: int, pkts: int, **extra):
        self._sport = 40000 + (self._sport + 1) % 20000
        rec = {"src": SITE["charger_ip"], "dst": dst, "sport": self._sport, "dport": dport, "proto": proto,
               "app": app, "bytes": nbytes, "pkts": pkts, **extra}
        self.sock.sendto(json.dumps(rec).encode(), (FLOW_SENSOR_HOST, FLOW_SENSOR_PORT))
        self.sent += 1

    async def background(self):
        node = SITE["node_ip"]
        self._emit(node, 53, "UDP", "DNS", 92, 2, qname="csms.site.local")
        self._emit(node, 123, "UDP", "NTP", 152, 2)
        while True:
            self._emit(node, 9000, "TCP", "OCPP", random.randint(380, 900), random.randint(4, 9))
            if random.random() < 0.05:
                self._emit(node, 53, "UDP", "DNS", 90, 2, qname="time.site.local")
            await asyncio.sleep(1.0)

    async def attack_traffic(self):
        await asyncio.sleep(self.start_delay)
        if self.attack == "port_scan":
            ports = SCAN_PORTS + random.sample(range(1024, 65535), 40)
            interval = 1 / self.rate
            for port in ports:
                self._emit(self.target, port, "TCP", "TCP", 60, 1, flags="S")
                await asyncio.sleep(interval)
        elif self.attack == "c2":
            for _ in range(40):
                self._emit(C2_HOST, 4444, "TCP", "TCP", random.randint(220, 420), random.randint(3, 6))
                await asyncio.sleep(max(0.4, 2.0 + random.uniform(-0.6, 0.6)) * 50 / self.rate)
        elif self.attack == "dns_exfil":
            for i in range(self.rate * 6):
                chunk = base64.b32encode(os.urandom(30)).decode().rstrip("=").lower()
                self._emit(PUBLIC_RESOLVER, 53, "UDP", "DNS", 140, 2, qname=f"{chunk}.{i:04x}.x7k2.example")
                await asyncio.sleep(1 / self.rate)

    async def run(self, duration_s: float):
        tasks = [asyncio.create_task(self.background())]
        if self.attack in ("port_scan", "c2", "dns_exfil"):
            tasks.append(asyncio.create_task(self.attack_traffic()))
        try:
            await asyncio.sleep(duration_s)
        finally:
            for t in tasks:
                t.cancel()
            self.sock.close()
