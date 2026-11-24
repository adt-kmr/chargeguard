"""
Turn a BehaviorReport into an enforcement policy for wolfSentry.

wolfSentry (vendor/network-monitor/wolfsentry) is an embedded firewall /
IDPS for RTOS and bare-metal targets. It loads a JSON configuration; this
module renders one from the baseline:

  * NONE    – default accept; baseline peers green-listed
  * BLOCK   – default accept; offending peers penalty-boxed
  * ISOLATE – default reject; only baseline peers green-listed

The JSON follows wolfSentry's config schema (doc/json_configuration.md):
"wolfsentry-config-version", "default-policies", "events-insert",
"static-routes-insert".
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from .baseline import Action, Baseline, BehaviorReport

_PARENT = "chargeguard-route"


def _family_and_prefix(host: str) -> tuple[str, str, int] | None:
    if host == "localhost":
        host = "127.0.0.1"
    try:
        net = ipaddress.ip_network(host, strict=False)
    except ValueError:
        return None                                    # hostnames cannot be routed by address
    return ("inet" if net.version == 4 else "inet6", str(net.network_address), net.prefixlen)


def _route(host: str, *, green: bool, port: int | None = None, proto: str = "tcp") -> dict | None:
    fam = _family_and_prefix(host)
    if fam is None:
        return None
    family, addr, bits = fam
    remote = {"address": addr, "prefix-bits": bits}
    if port is not None:
        remote["port"] = port
    route = {"parent-event": _PARENT, "direction-in": True, "direction-out": True,
             "penalty-boxed": not green, "green-listed": green,
             "dont-count-hits": False, "dont-count-current-connections": False,
             "family": family, "remote": remote}
    if port is not None:
        route["protocol"] = proto
    return route


def render_wolfsentry_config(report: BehaviorReport, baseline: Baseline) -> dict:
    routes: list[dict] = []
    for peer in baseline.peers:
        for host in peer.get("hosts", []):
            for port in peer.get("ports", []) or [None]:
                if r := _route(host, green=True, port=port):
                    routes.append(r)
    if report.action is Action.BLOCK:
        routes += [r for h in report.blocked_peers if (r := _route(h, green=False))]

    return {
        "wolfsentry-config-version": 1,
        "default-policies": {
            "default-policy": "reject" if report.action is Action.ISOLATE else "accept",
            "default-event": _PARENT,
        },
        "events-insert": [{"label": _PARENT, "priority": 1,
                           "config": {"max-connection-count": 20, "penalty-box-duration": "1h"}}],
        "static-routes-insert": routes,
    }


def write_wolfsentry_config(report: BehaviorReport, baseline: Baseline, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(render_wolfsentry_config(report, baseline), indent=2))
    return path
