"""
Packet sources: a live interface (Linux AF_PACKET, used on the node's bridge) and
classic pcap files (offline replay and tests). Both yield Packet objects.
"""
from __future__ import annotations

import socket
import struct
import sys
import time
from collections.abc import Iterator
from pathlib import Path

from .packets import Packet, parse_ethernet, parse_ipv4

LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL = 1, 101, 113
ETH_P_ALL = 0x0003


def read_pcap(path: str | Path) -> Iterator[Packet]:
    """Classic libpcap files (microsecond or nanosecond, either byte order)."""
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            return
        magic = head[:4]
        order, scale = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
                        b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}.get(magic, (None, 0))
        if order is None:
            raise ValueError("not a classic pcap file (pcapng is not supported; convert with editcap -F pcap)")
        linktype = struct.unpack(order + "I", head[20:24])[0]
        rec = struct.Struct(order + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            sec, frac, incl, _orig = rec.unpack(h)
            data = f.read(incl)
            ts = sec + frac * scale
            if linktype == LINKTYPE_ETHERNET:
                p = parse_ethernet(ts, data)
            elif linktype == LINKTYPE_RAW:
                p = parse_ipv4(ts, data)
            elif linktype == LINKTYPE_LINUX_SLL and len(data) > 16 and data[14:16] == b"\x08\x00":
                p = parse_ipv4(ts, data[16:])
            else:
                p = None
            if p:
                yield p


def write_pcap(path: str | Path, frames: list[tuple[float, bytes]]):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts, fr in frames:
            sec = int(ts)
            f.write(struct.pack("<IIII", sec, int(round((ts - sec) * 1e6)), len(fr), len(fr)) + fr)


def live(iface: str, snaplen: int = 256) -> Iterator[Packet | None]:
    """Packets seen on a Linux interface (needs CAP_NET_RAW). Yields None once a second
    when idle, so the caller can expire flows on time.

    On the node, `iface` is the bridge port facing the charger (for example eth1): every
    packet the charger sends arrives as incoming and every packet to it leaves as
    outgoing, so each is seen exactly once."""
    if not sys.platform.startswith("linux"):
        raise RuntimeError("live capture needs Linux (AF_PACKET); use read_pcap elsewhere")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((iface, 0))
    s.settimeout(1.0)
    try:
        while True:
            try:
                frame, addr = s.recvfrom(snaplen if snaplen > 0 else 65535)
            except socket.timeout:
                yield None
                continue
            p = parse_ethernet(time.time(), frame)
            if p:
                yield p
    finally:
        s.close()
