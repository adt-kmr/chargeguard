# integrations

Python adapters around the third-party security tools vendored in
[`vendor/`](../vendor/README.md). Each adapter returns the same
`ToolResult` / `Finding` types, so the orchestrator can treat every tool the
same way. (C1 identity and attestation is the sibling
[`attestation/`](../attestation/README.md) package.)

**Status:** standalone. None of this is connected to `checks/`, `orchestrator/`
or the dashboard yet.

## Layout

```
integrations/
├── core.py                 Tool registry, binary discovery, subprocess runner, Finding/ToolResult
├── __main__.py             `python -m integrations` -> which tools are installed
├── integrity/              C2  firmware integrity and secure update
│   ├── bootloader.py         MCUboot (imgtool verify), wolfBoot header + digest check
│   ├── linux_update.py       RAUC bundle info/verify, SWUpdate check mode
│   ├── cosign.py             Cosign sign-blob / verify-blob (key-based, offline)
│   └── tuf_metadata.py       TUF ngclient: is this hash the published target?
├── vulnerability/          C3  vulnerability and supply-chain audit
│   ├── tools.py              unblob, Syft, Grype, cve-bin-tool, mithril, checksec, kernel-hardening-checker
│   ├── pipeline.py           FirmwareAudit: run once per firmware, cache by SHA-256 (SQLite)
│   └── deep.py               EMBA runner + CSV import, FACT REST client
├── behavior/               C4  live behaviour monitor
│   ├── charger_baseline.yaml expected peers, ports, rates, protocol phases (custom)
│   ├── baseline.py           anomaly rules -> normal/suspicious + block/isolate
│   ├── enforcement.py        render the decision as a wolfSentry JSON policy
│   └── sources.py            iotaudit (pcap audit), tshark MQTT extraction
├── evidence/               C7  evidence bundle
│   ├── sarif.py              SARIF 2.1.0 writer
│   └── bundle.py             verdict + SARIF + CycloneDX + SHA-256 manifest, Cosign-signed
└── attack_lab/             C9  attack and test harness
    ├── renode.py             boot charger-controller firmware in emulation
    └── scenarios.py          attack catalogue -> expected check and verdict
```

## Feature map

| Feature | Output (as specified) | Entry point |
|---|---|---|
| C2 Integrity | pass/fail with signature and hash details | `integrity.verify_mcuboot`, `verify_wolfboot_hash`, `verify_rauc_bundle`, `verify_swupdate_image`, `verify_blob`, `check_tuf_target` |
| C3 Weaknesses | none / known-CVEs, keyed by firmware hash | `vulnerability.FirmwareAudit().audit(path)`; at verify time `AuditStore().get(sha256)` |
| C4 Behaviour | normal / suspicious + block or isolate | `behavior.Baseline.load().evaluate(flows)`, `render_wolfsentry_config(...)` |
| C7 Evidence | SARIF 2.1 + CycloneDX, hash-anchored, signed | `evidence.build_bundle(...)`, `verify_bundle(...)` |
| C9 Attacks | repeatable scenarios | `attack_lab.SCENARIOS`, `attack_lab.boot_firmware(...)` |

## Usage

```python
from integrations.vulnerability import FirmwareAudit
from integrations.behavior import Baseline
from integrations.evidence import build_bundle

audit = FirmwareAudit().audit("firmware/images/good_v2.1.0.bin")   # slow, once per version
behavior = Baseline.load().evaluate(simulator.get_traffic_sample())  # fast, every plug-in

sbom = next((t["artifacts"]["cyclonedx"] for t in audit["tools"] if t["tool"] == "syft" and t["ok"]), None)
build_bundle("evidence/bundles/<session>", verdict=verdict_dict, sbom=sbom, sign_key="cosign.key")
```

## Installing the tools

`python -m integrations` lists what is missing and how to get it. Each tool is
found in this order:

1. `CHARGEGUARD_TOOL_<NAME>` environment variable (e.g. `CHARGEGUARD_TOOL_SYFT=/opt/syft`)
2. the system `PATH`
3. a build output inside `vendor/`
4. an importable Python module

Build instructions for each vendored tool are in `vendor/README.md`.
Several tools (EMBA, RAUC, SWUpdate, unblob's extractors) are Linux-only; run
them on Linux or in WSL.

## Adding a tool

```python
from integrations.core import Tool, ToolResult, register_tool, run, timed

MYTOOL = register_tool(Tool("mytool", ("mytool",), "C3", install_hint="..."))

def scan(path) -> ToolResult:
    result = ToolResult(tool="mytool", ok=True)
    with timed(result):                       # records duration, turns missing tools into ok=False
        proc = run(MYTOOL, ["--json", path], timeout=60)
        ...
    return result
```

## Connecting to ChargeGuard later

| Existing module | Replace / extend with |
|---|---|
| `checks/integrity/integrity_check.py` | `integrity.*` verifier for the charger's platform |
| `checks/weaknesses/weakness_check.py` | `AuditStore().get(firmware_hash)["weaknesses"]` |
| `checks/behavior/behavior_check.py` | `Baseline.load().evaluate(flows)` (same flow format as the simulator) |
| `evidence/report_generator.py` | `evidence.build_bundle(...)` alongside the JSON report |
| `simulator/attacker.py` | `attack_lab.SCENARIOS` |

## Tests

```bash
python tests/test_integrations.py
```
These cover the parts that need no external tools: baseline rules against all
simulator attack modes, the wolfSentry policy, tool-output parsers, the
per-hash cache, wolfBoot digest checking, SARIF output and bundle tamper detection.
