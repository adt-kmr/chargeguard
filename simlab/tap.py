"""
Network tap simulator: the charger's traffic as real packets, aggregated by the same
flow table the node runs on its bridge (netflow.FlowTable), exported as the same
records (netflow.exporter) to the node's flow collector.

Healthy traffic: the persistent OCPP WebSocket to the node (exported as one-second
slices, the node's active timeout), NTP and occasional DNS to the node. Attack
profiles add what a compromised controller sends:

  port_scan  TCP SYN sweep of a LAN host (one short flow per port, most refused)
  c2         periodic beacon to an external host on 4444/tcp with jitter
  dns_exfil  high-rate TXT queries with long encoded labels to a public resolver
  burst      OCPP message flood on the WebSocket (network view of the OCPP flood)

External addresses use the documentation ranges (RFC 5737) unless the operator sets
a target. On the Raspberry Pi, `python -m netflow.exporter --iface eth1` replaces this.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import socket
import time

from config import FLOW_SENSOR_HOST, FLOW_SENSOR_PORT, SITE
from netflow import synth
from netflow.exporter import to_node_record
from netflow.flowtable import FlowTable
from netflow.packets import parse_ethernet

C2_HOST = "203.0.113.66"
PUBLIC_RESOLVER = "8.8.8.8"
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 502, 1883, 3389, 5900, 8080, 8443, 9100]
ACTIVE_TIMEOUT_S = 1.0        # the node exports long-lived flows every second for live monitoring


class Tap:
    def __init__(self, attack: str = "none", target: str = "192.168.1.254", rate: int = 50,
                 start_delay: float = 0.0):
        self.attack, self.target, self.rate, self.start_delay = attack, target, max(1, rate), start_delay
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.table = FlowTable(idle_timeout=2.0, active_timeout=ACTIVE_TIMEOUT_S, tcp_linger=0.3)
        self.charger, self.node = SITE["charger_ip"], SITE["node_ip"]
        self.sent = 0
        self._port = random.randint(40000, 50000)
        self._ws_port = self._next_port()

    def _next_port(self) -> int:
        self._port = 40000 + (self._port + 1 - 40000) % 20000
        return self._port

    def _inject(self, frames: synth.Frames):
        for ts, fr in sorted(frames, key=lambda x: x[0]):
            p = parse_ethernet(ts, fr)
            if p:
                self._send(self.table.add(p))

    def _send(self, records: list[dict]):
        for nf in records:
            self.sock.sendto(json.dumps(to_node_record(nf, self.charger)).encode(), (FLOW_SENSOR_HOST, FLOW_SENSOR_PORT))
            self.sent += 1

    async def _ticker(self):
        while True:
            await asyncio.sleep(0.25)
            self._send(self.table.expire(time.time()))

    async def background(self):
        now = time.time()
        self._inject(synth.dns_lookup(self.charger, self.node, self._next_port(), "csms.site.local", now)
                     + synth.ntp_sync(self.charger, self.node, self._next_port(), now + 0.05))
        while True:
            now = time.time()
            frames = synth.ocpp_slice(self.charger, self.node, self._ws_port, now, random.choice([1, 1, 2, 3]))
            if random.random() < 0.05:
                frames += synth.dns_lookup(self.charger, self.node, self._next_port(), "time.site.local", now + 0.4)
            self._inject(frames)
            await asyncio.sleep(1.0)

    async def attack_traffic(self):
        await asyncio.sleep(self.start_delay)
        if self.attack == "port_scan":
            ports = SCAN_PORTS + random.sample(range(1024, 65535), 40)
            for port in ports:
                state = "open" if port in (22, 80, 502) else random.choice(["closed"] * 6 + ["filtered"])
                self._inject(synth.syn_probe(self.charger, self.target, self._next_port(), port, time.time(), state))
                await asyncio.sleep(1 / self.rate)
        elif self.attack == "c2":
            for _ in range(40):
                self._inject(synth.c2_beacon(self.charger, C2_HOST, self._next_port(), time.time()))
                await asyncio.sleep(max(0.4, 2.0 + random.uniform(-0.6, 0.6)) * 50 / self.rate)
        elif self.attack == "dns_exfil":
            for i in range(self.rate * 6):
                chunk = base64.b32encode(os.urandom(30)).decode().rstrip("=").lower()
                self._inject(synth.dns_lookup(self.charger, PUBLIC_RESOLVER, self._next_port(),
                                              f"{chunk}.{i:04x}.x7k2.example", time.time(), qtype=16))
                await asyncio.sleep(1 / self.rate)
        elif self.attack == "burst":
            for _ in range(20):
                self._inject(synth.ocpp_slice(self.charger, self.node, self._ws_port, time.time(), self.rate, avg=180))
                await asyncio.sleep(1.0)

    async def run(self, duration_s: float):
        tasks = [asyncio.create_task(self.background()), asyncio.create_task(self._ticker())]
        if self.attack in ("port_scan", "c2", "dns_exfil", "burst"):
            tasks.append(asyncio.create_task(self.attack_traffic()))
        try:
            await asyncio.sleep(duration_s)
        finally:
            for t in tasks:
                t.cancel()
            self._send(self.table.flush())
            self.sock.close()
