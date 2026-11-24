# ChargeGuard

**Plug in an EV charger. Get a green, amber or red trust verdict in seconds, backed by independent security checks and a signed, compliance-mapped evidence report. Everything runs on the edge node; nothing goes to the cloud.**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-WebSocket%20dashboard-009688?logo=fastapi&logoColor=white)
![Target](https://img.shields.io/badge/Target-Raspberry%20Pi%205%20(Arm%20Cortex--A76)-A22846?logo=raspberrypi&logoColor=white)
![TPM](https://img.shields.io/badge/Root%20of%20trust-TPM%202.0-4B5563)
![Offline](https://img.shields.io/badge/Cloud%20dependency-none-16A34A)

## What this repository contains

ChargeGuard is an on-device security verifier for EV chargers, built for the Arm edge-AI challenge on on-device cybersecurity. A ChargeGuard node sits between a charger and the site network. When a charger is plugged in, the node checks:

- who the charger is
- whether its firmware is authentic
- whether that firmware has known vulnerabilities
- whether the charger is behaving normally

It then fuses those results into one verdict with a plain-English reason, and can isolate a charger that turns hostile mid-session.

This README describes what is in the repository today. Planned work is listed under [Roadmap](#roadmap). Each component's status is stated next to it. Every performance figure links to the committed measurement file that produced it.

The repository has three layers:

| Layer | What it is | Status |
|---|---|---|
| **Live verification system** | An OCPP 1.6-J charger process, the ChargeGuard gateway that terminates its connection inline, real C1–C4 checks on what the gateway observes, trust engine, enforcement, advisor, signed evidence and the live dashboard | Runs end to end today (`python main.py`); 11 attack scenarios verified, see [DEMO.md](DEMO.md) |
| **Security integration layer** | [`attestation/`](attestation/README.md) for TPM 2.0 identity, and [`integrations/`](integrations/README.md) adapters for firmware integrity, firmware audit, behaviour baseline, evidence bundles and the attack lab | Attestation verifier and behaviour baseline run in the live path; the external-tool adapters are unit-tested and used in audit mode |
| **Vendored toolchain** | 25 open-source security tools in [`vendor/`](vendor/README.md), grouped by capability, with license notices | Source snapshots; built per tool as needed |

## Contents

- [The problem](#the-problem)
- [Alignment with the challenge](#alignment-with-the-challenge)
- [How it works](#how-it-works)
- [Architecture](#architecture)
- [Demo scenarios](#demo-scenarios)
- [Arm architecture and tools](#arm-architecture-and-tools)
- [Performance and optimization](#performance-and-optimization)
- [Evidence and compliance](#evidence-and-compliance)
- [Quick start](#quick-start)
- [API](#api)
- [Configuration](#configuration)
- [Repository layout](#repository-layout)
- [Novelty](#novelty)
- [Roadmap](#roadmap)
- [Responsible use](#responsible-use)
- [License](#license)

## The problem

Public and depot EV chargers are networked embedded computers. A typical charger has:

- a microcontroller or embedded-Linux controller
- a firmware update channel
- a backend connection (usually OCPP over WebSocket)
- often local service ports

They are installed in places operators do not physically watch, maintained by third parties, and rarely re-checked after commissioning.

The threats that matter for a charger are concrete:

| Threat | What it looks like | What it costs |
|---|---|---|
| Rogue or cloned charger | A device that claims a legitimate identity | Fraudulent sessions, a foothold on the site network |
| Tampered firmware | Modified image after the vendor signed it | Arbitrary behaviour on high-power equipment |
| Authentic but vulnerable firmware | Correctly signed, but shipping libraries with known CVEs | A remotely exploitable device that passes signature checks |
| Live compromise | A healthy charger that starts scanning, beaconing or exfiltrating | Lateral movement into the operator's or the vehicle's network |

Existing tooling answers these questions separately. Firmware scanners run offline in a lab, attestation runs in data centres, and network monitors know nothing about firmware provenance. None of them gives the person plugging in a charger one answer they can act on.

The automotive regulations ChargeGuard maps to (UNECE R155 for cybersecurity, R156 for software updates) require exactly this kind of evidence across the supply chain.

**ChargeGuard's answer:** one inline Arm edge node that runs every check locally, keeps the slow analysis out of the plug-in path, and produces a single verdict plus a signed record of why.

## Alignment with the challenge

The challenge asks for an on-device AI security system that runs entirely on Arm edge hardware without cloud dependency. It should:

- monitor network traffic for intrusions
- explain threats in plain language
- recommend remediation

ChargeGuard applies that brief to one high-value device class. It fits two of the listed application areas directly: **IoT device behaviour monitoring** and **offline threat intelligence for air-gapped systems**.

| Challenge requirement | ChargeGuard component | Status today |
|---|---|---|
| Run entirely on Arm edge hardware, no cloud | Python services on a Raspberry Pi 5 class node; all lookups against local SQLite; offline signing and verification | Verification path runs locally. The dashboard page loads three.js and anime.js from a CDN; bundling them locally is on the [roadmap](#roadmap) |
| Monitor and classify network traffic for anomalies and intrusions | C4 behaviour monitor: per-charger baseline of peers, ports, message rates and protocol phases; detects port scans, C2 beacons, DNS exfiltration and floods ([`integrations/behavior`](integrations/behavior/baseline.py)) | Rule-based detector implemented and tested against all simulator attack modes. A learned traffic classifier is planned |
| IoT device behaviour monitoring | Same baseline, plus packet-capture inputs (iotaudit, tshark MQTT) | Implemented as adapters |
| Explain threats to non-expert users in plain language | [`advisor/`](advisor/engines.py) turns each signed verdict into a plain-language explanation, the risk, and up to three remediation steps, shown on the dashboard and stored in the report | Rule-based engine grounded in the evidence runs today and is labelled as such; the Llama engine is implemented against ExecuTorch's runner and activates when the model is exported |
| Recommend remediation actions | Verdict reasons include the action. The behaviour monitor outputs block, isolate or rate-limit and renders a wolfSentry firewall policy | Implemented |
| Offline threat intelligence | Firmware is audited once (SBOM, CVEs, secrets, hardening) and the result is cached by firmware hash for offline lookup | Implemented in the integration layer |
| **Required: Llama for advisory or reasoning, deployed with ExecuTorch** | `LlamaExecuTorchAdvisor` in [`advisor/engines.py`](advisor/engines.py) runs Llama 3.2 1B Instruct (4-bit SpinQuant) through ExecuTorch's in-process `TextLLMRunner`; [`advisor/export_llama.sh`](advisor/export_llama.sh) produces the `.pte` with the XNNPACK SpinQuant configuration | **ExecuTorch 1.6 toolchain installed and the export verified up to the licence-gated weight download.** The model is exported once the Llama 3.2 licence is accepted and Hugging Face login is done; until then the grounded engine runs and is labelled |
| Detect phishing URLs | [`threatintel/`](threatintel/README.md): hostname model trained on UCI PhiUSIIL (grouped split, no domain overlap) + explicit rules + curated known-good list; also checks the **payment QR code every charger displays** | Implemented: F1 0.750, ROC-AUC 0.888 on 30,093 held-out hostnames; exported to ExecuTorch |
| Detect scam SMS / fraudulent communications | [`threatintel/`](threatintel/README.md): message model trained on the UCI SMS Spam Collection, with link extraction and per-n-gram explanations; dashboard **Driver Safety Check** | Implemented: F1 0.942, false-positive rate 0.44% on 776 held-out messages; exported to ExecuTorch |

## How it works

### Audit once, verify fast

A deep firmware scan takes minutes to hours: unpacking, building the software inventory (SBOM), CVE matching and secret search. That cannot fit in a plug-in window. ChargeGuard therefore splits the work:

- **Audit mode (offline, once per firmware version).** The full scan runs ahead of time and stores its result keyed by the firmware's SHA-256 ([`integrations/vulnerability/pipeline.py`](integrations/vulnerability/pipeline.py)).
- **Verify mode (at plug-in).** The node measures the charger's firmware and does a single lookup by hash. The weakness check becomes a database read instead of a scan.

### The verification timeline

The design budget is 5 seconds, split into fixed windows ([`config.py`](config.py)):

| Window | Check | Question | How it is answered |
|---|---|---|---|
| 0.0 – 1.0 s | **C1 Identity** | Is this really that charger? | The gateway sends a nonce over OCPP `DataTransfer`; the charger returns a signature from its device key and a TPM quote over PCR0. Both are verified against the enrolled keys ([`gateway/checks.py`](gateway/checks.py), [`attestation/`](attestation/README.md)) |
| 1.0 – 2.0 s | **C2 Integrity** | Is its software untampered? | Firmware hash is looked up in the vendor registry, the vendor signature is verified, and the measured-boot PCR0 from the quote must equal the golden value for that image |
| 2.0 – 3.0 s | **C3 Weaknesses** | Does it contain known weaknesses? | Lookup of the firmware hash in the pre-audit CVE database |
| 3.0 – 4.5 s | **C4 Behaviour** | Is it acting normally right now? | The OCPP messages the gateway saw inline and the flow records from the network tap are compared with the charger's baseline; monitoring continues for the whole session |
| 4.5 – 5.0 s | **C5 Verdict** | Should we trust it? | Trust engine fuses the four results, the gateway gates `Authorize`/`StartTransaction` on it, and the report is signed |

The checks themselves take milliseconds (shown next to each check on the dashboard and in the report); the dashboard holds each step to its window so an audience can follow it.

### Trust engine rules

The trust engine is [`orchestrator/trust_engine.py`](orchestrator/trust_engine.py). The rules are applied in order:

| Verdict | Condition | Score |
|---|---|---|
| **Red** | Identity fails | 0 |
| **Red** | Firmware integrity fails | 10 |
| **Red** | Behaviour is suspicious (the session is isolated) | 15 |
| **Amber** | Identity, integrity and behaviour pass, but known CVEs exist | 60 |
| **Green** | Every check passes | 100 |

## Architecture

```mermaid
flowchart LR
    subgraph Charger["Charger under test"]
        FW["Firmware image<br/>(good / tampered / vulnerable)"]
        KEY["Device key<br/>(TPM 2.0 / wolfTPM)"]
        NET["Network traffic<br/>(OCPP, heartbeat, meter)"]
    end

    subgraph Node["ChargeGuard node · Raspberry Pi 5 (Arm Cortex-A76)"]
        ORCH["C5 Orchestrator<br/>5-second schedule"]
        C1["C1 Identity"]
        C2["C2 Integrity"]
        C3["C3 Weakness lookup"]
        C4["C4 Behaviour baseline"]
        TE["Trust engine"]
        DB[("SQLite<br/>firmware registry · CVEs<br/>identities · audit cache")]
        EV["C6 Compliance mapper<br/>C7 Signed evidence"]
        ENF["Enforcement<br/>block / isolate"]
    end

    subgraph Offline["Audit mode (offline, per firmware version)"]
        AUD["unblob → Syft → Grype · cve-bin-tool<br/>mithril · checksec · kernel-hardening-checker"]
    end

    UI["C8 Dashboard<br/>WebSocket"]

    KEY --> C1
    FW --> C2
    FW -. hash .-> C3
    NET --> C4
    ORCH --> C1 --> C2 --> C3 --> C4 --> TE
    C1 & C2 & C3 --> DB
    AUD -- results keyed by SHA-256 --> DB
    TE --> EV --> UI
    TE --> ENF
    ORCH -- live events --> UI
```

**Components**

| ID | Component | Location |
|---|---|---|
| C1 | Identity and attestation | [`gateway/checks.py`](gateway/checks.py) (live), [`attestation/`](attestation/README.md) (TPM 2.0: software TPM, tpm2-tss, Keylime verifier, IBM TPM emulator) |
| C2 | Firmware integrity and secure update | [`checks/integrity`](checks/integrity/integrity_check.py), [`integrations/integrity`](integrations/integrity/__init__.py) (MCUboot, wolfBoot, RAUC, SWUpdate, Cosign, TUF) |
| C3 | Vulnerability and supply-chain audit | [`checks/weaknesses`](checks/weaknesses/weakness_check.py), [`integrations/vulnerability`](integrations/vulnerability/__init__.py) (unblob, Syft, Grype, cve-bin-tool, mithril, checksec, kernel-hardening-checker, EMBA, FACT) |
| C4 | Live behaviour monitor | [`gateway/csms.py`](gateway/csms.py) (inline OCPP + continuous monitoring + enforcement), [`gateway/sensor.py`](gateway/sensor.py) (flow collector), [`integrations/behavior`](integrations/behavior/__init__.py) (baseline rules, iotaudit, tshark MQTT, wolfSentry policy) |
| C5 | Orchestrator and trust engine | [`orchestrator/`](orchestrator/orchestrator.py) |
| C6 | Compliance mapper | [`policy/compliance_map.yaml`](policy/compliance_map.yaml), [`policy/mapper.py`](policy/mapper.py) |
| C7 | Evidence bundle | [`evidence/`](evidence/report_generator.py) (signed SARIF-structured report), [`integrations/evidence`](integrations/evidence/bundle.py) (SARIF 2.1.0 + CycloneDX + SHA-256 manifest + Cosign) |
| C8 | Dashboard | [`dashboard/`](dashboard/main.py) (FastAPI + WebSocket, single-page UI with a three.js scene of a real glTF vehicle model, image-based lighting and live check status) |
| C9 | Attack and test harness | [`simulator/attacker.py`](simulator/attacker.py), [`integrations/attack_lab`](integrations/attack_lab/scenarios.py) (Renode, IoTGoat, Bruce, Facedancer) |
| C10 | Charger | [`charger/agent.py`](charger/agent.py): OCPP 1.6-J charge point process (boot, heartbeat, authorise, transaction, meter values, attestation responder); [`simlab/`](simlab/scenarios.py) stages scenarios and simulates the network tap |

## Demo scenarios

Each scenario launches the charger as its own OCPP 1.6 process plus the network tap, and the gateway verifies it live. The verdicts below come from the committed run of all scenarios ([`benchmarks/results/scenario_matrix.json`](benchmarks/results/scenario_matrix.json)); [DEMO.md](DEMO.md) is the presenter's runbook.

| Act | Scenario | What happens | Verdict |
|---|---|---|---|
| 1. Healthy | `healthy` | Genuine device, authentic firmware v2.1.0, no CVEs, normal traffic | **Green**; charging starts |
| 2. Tampered firmware | `tampered` | Payload modified after signing; hash not in the registry | **Red** at the integrity step; authorisation refused |
| 3. Signed but vulnerable | `vulnerable` | Authentic v1.8.3 image whose audit found OpenSSL 1.1.1k, zlib 1.2.11 and BusyBox 1.33.0: CVE-2022-2068, CVE-2022-37434, CVE-2022-0778, CVE-2021-28831, CVE-2023-0286 | **Amber**, with the CVE list and an upgrade recommendation |
| 4. Live compromise | `compromised` | Healthy device charging, then scans the LAN | **Green → red mid-session**; `RemoteStopTransaction`, connection closed, charger quarantined |

Six further scenarios pass the same way: cloned identity, rogue device, C2 beacon, DNS exfiltration, OCPP message flood, and C2 over an OCPP vendor extension mid-session.

The dashboard's attack panel also composes attacks individually:

- **Identity:** legitimate, unknown or cloned
- **Firmware:** good, tampered or vulnerable
- **CVEs:** manual injection of chosen CVEs
- **Behaviour:** port scan, C2 beacon, DNS exfiltration or burst, with a configurable target and rate

**User flow: three clicks.**
1. **Verify:** the charger is connected and verification starts.
2. **Watch:** the checks tick off live while the status ring fills.
3. **Evidence:** open the reasoning and download the signed report.

## Arm architecture and tools

### Where Arm runs in the system (target deployment)

| Role | Hardware | Arm core | What runs there |
|---|---|---|---|
| ChargeGuard node | Raspberry Pi 5 | 4× Cortex-A76 (Armv8.2-A) | Orchestrator, checks, trust engine, dashboard server, audit cache; planned Llama advisor |
| Charger controller (MCU class) | Cortex-M microcontroller; emulated in Renode on the STM32F4 Discovery platform (Cortex-M4) | Cortex-M | Firmware verified by MCUboot or wolfBoot; device identity on an SPI/I2C TPM via wolfTPM; wolfSentry firewall |
| Charger controller (Linux class) | Arm Linux board (for example a second Raspberry Pi) | Cortex-A | A/B updates via RAUC or SWUpdate; Keylime agent for continuous attestation |

### Arm ecosystem components in the repository

- **MCUboot** ([`vendor/secure-boot/mcuboot`](vendor/secure-boot/mcuboot)). The bootloader used by Trusted Firmware-M and Zephyr on Cortex-M. `imgtool verify` checks charger images in [`integrations/integrity/bootloader.py`](integrations/integrity/bootloader.py).
- **Mbed TLS.** MCUboot's crypto backend, pinned at exact commits in [`vendor/submodules.lock`](vendor/submodules.lock).
- **Renode** ([`vendor/attack-lab/renode`](vendor/attack-lab/renode)). Boots Cortex-M charger firmware without hardware ([`integrations/attack_lab/renode.py`](integrations/attack_lab/renode.py)), so tampered-image tests run in CI.
- **wolfBoot, wolfTPM, wolfSentry.** Bootloader, TPM and firewall libraries for Cortex-M targets.

### On-device AI: two separate pipelines

| | Advisor (required technology) | Threat detectors | Traffic classifier (optional accelerator) |
|---|---|---|---|
| Status | Toolchain installed and export script verified; weights pending licence acceptance | **Built, evaluated and exported to ExecuTorch** | Planned |
| Model | Llama 3.2 1B Instruct, 4-bit SpinQuant | Two linear models over hashed n-grams (scam messages, phishing hostnames) | Compact classifier on CICIDS2017 / UNSW-NB15 flow features plus recorded charger baselines |
| Runtime | ExecuTorch `TextLLMRunner`, XNNPACK backend (KleidiAI micro-kernels on Arm) | ExecuTorch `.pte` (embedding-lookup network) or the identical NumPy path | HailoRT on the AI HAT+ NPU when fitted; otherwise ExecuTorch on the CPU |
| Compute unit | Cortex-A76 CPU | Cortex-A76 CPU | Hailo NPU, or the Cortex-A76 CPU |
| Input | Verdict, per-check findings, CVEs, anomalies, detector results (structured JSON) | Message text, links, QR payloads | Flow features from the behaviour monitor |
| Output | Plain-language explanation and up to three remediation steps, grounded only in the facts given | Score, decision and the n-grams and rules behind it | Anomaly score feeding C4 alongside the rule baseline |
| Place in the 5-second budget | Outside it: runs after the verdict is signed | Inside it: the charger's payment QR is checked during verification | Inside the C4 window |

The pipelines are independent. Llama never runs on the Hailo NPU, and neither detector depends on Llama.

**Profiling plan.** Arm Performance Studio (Streamline) on the Pi 5, to attribute advisor latency to prefill, decode and memory bandwidth, and to confirm the verification path stays within its window while the advisor runs.

## Performance and optimization

### Measured: live gateway path

Measured compute per check across the 11 scenarios in [`benchmarks/results/scenario_matrix.json`](benchmarks/results/scenario_matrix.json) (same development host as below, charger and gateway as separate processes on loopback):

| Check | Range across scenarios | Includes |
|---|---|---|
| C1 identity | 7.6 – 45.7 ms | OCPP `DataTransfer` round trip to the charger, Ed25519 check, TPM quote verification |
| C2 integrity | 0.01 – 21.5 ms | Registry lookup, vendor signature, PCR0 comparison |
| C3 weaknesses | 3.3 – 19.0 ms | Audit-cache lookup by firmware hash |
| C4 behaviour | 0.2 – 2.8 ms | Baseline over the OCPP transcript, tap flows and the payment-QR check |

A verification therefore needs well under 100 ms of real work. The 5-second figure is the presentation schedule.

### Measured: threat detectors

Accuracy on held-out test splits ([`benchmarks/results/threatintel_metrics.json`](benchmarks/results/threatintel_metrics.json); protocol in [`threatintel/README.md`](threatintel/README.md)):

| Model | Test size | Precision | Recall | F1 | ROC-AUC | False-positive rate |
|---|---|---|---|---|---|---|
| Scam messages | 776 messages | 0.968 | 0.918 | 0.942 | 0.991 | 0.44% |
| Phishing hostnames (grouped by domain, no overlap) | 30,093 hostnames | 0.837 | 0.679 | 0.750 | 0.888 | 6.3% |

ExecuTorch programs ([`benchmarks/results/executorch_detectors_x86_64-linux.json`](benchmarks/results/executorch_detectors_x86_64-linux.json)), ExecuTorch 1.6.0 with XNNPACK, measured on the development host's x86-64 CPU under WSL2, **not** the Arm target:

| Program | Size | Max difference vs Python model | Decisions agreeing | Latency p50 / p95 |
|---|---|---|---|---|
| `sms_scam.pte` (300 real messages) | 2.1 MB | 5.0×10⁻⁵ | 100% | 0.012 / 0.013 ms |
| `phishing_url.pte` | 1.05 MB | 1.2×10⁻⁷ | 100% | 0.013 / 0.015 ms |

### Measured: component micro-benchmarks

All numbers below come from [`benchmarks/results/amd64-win32.json`](benchmarks/results/amd64-win32.json), produced by [`benchmarks/bench_hotpath.py`](benchmarks/bench_hotpath.py), which measures the original in-process verification path and the individual operations.

**Measurement setup**

| | |
|---|---|
| Host | Intel Core i9-14900HX, Windows 11, Python 3.12.10, cryptography 46.0.7 (development host, **not** the Arm target) |
| Component timings | 1,000 calls each after 20 warm-up calls, single thread |
| End-to-end timings | 5 runs per scenario |

**End to end, as the dashboard runs it**

| Scenario | Verdict | p50 wall time | max |
|---|---|---|---|
| healthy | green | 3.016 s | 3.047 s |
| tampered | red | 2.713 s | 2.721 s |
| vulnerable | amber | 3.005 s | 3.028 s |
| compromised | red | 3.019 s | 3.037 s |

The checks contain fixed `asyncio.sleep()` delays totalling 2.95 s. These stand in for TPM and network round-trips. The end-to-end figure is therefore the user-facing timeline, and it lands inside the 5-second budget with about 2 seconds of headroom.

**Compute on the hot path (no simulated delays)**

| Operation | p50 | p95 |
|---|---|---|
| C1 nonce sign + verify (Ed25519) | 0.086 ms | 0.089 ms |
| C1 identity registry lookup (SQLite) | 1.522 ms | 1.771 ms |
| C2 firmware registry lookup (SQLite) | 1.495 ms | 1.713 ms |
| C2 vendor signature verify (Ed25519) | 0.063 ms | 0.071 ms |
| C3 CVE lookup by firmware hash (SQLite) | 0.509 ms | 0.672 ms |
| C4 baseline, normal traffic | 0.020 ms | 0.022 ms |
| C4 baseline, C2-beacon traffic | 0.047 ms | 0.050 ms |
| C5 verdict fusion | 0.0003 ms | 0.0004 ms |
| C7 verdict signing (Ed25519, includes loading the key) | 0.164 ms | 0.186 ms |
| TPM quote, software TPM (ECDSA P-256) | 0.031 ms | 0.032 ms |
| TPM quote verification (signature, nonce, PCR digest) | 0.066 ms | 0.070 ms |

The real work in a verification adds up to about 4 ms; the cryptography is a small fraction of it.

**The largest cost is the database access pattern, not the security logic.** Each registry lookup opens a new SQLite connection, re-applies `PRAGMA journal_mode=WAL` and closes it. The same query on a connection that stays open takes **0.005 ms** (`reference_same_lookup_persistent_connection` in the results file), about 280× faster.

### Design choices for the edge

| Constraint | Decision |
|---|---|
| Latency | The heavy analysis (SBOM, CVE matching, secret search) is moved to audit mode; plug-in time does hash lookups only. The advisor runs after the verdict, never in its path |
| Compute and power | Plain CPU code with no GPU or always-on accelerator in the verification path. The node idles between plug-in events, and the audit pipeline runs once per firmware version, not per session |
| Memory | A small SQLite store and a YAML baseline per charger model. A 1B-parameter Llama with 4-bit weights is the planned advisor size, chosen to fit beside the services on a Pi 5 |
| Cost | A single Raspberry Pi 5 with a TPM module per site entrance, rather than a server; the optional AI HAT+ is used only if the traffic classifier needs it |
| Reliability | Each check has a 2-second timeout in the orchestrator, so a hung check yields a failed check, not a hung verdict |

### Next measurements

- Run `python benchmarks/bench_hotpath.py` on the Raspberry Pi 5 and commit `benchmarks/results/aarch64-linux.json`.
- Switch the registry lookups to a persistent connection and re-measure.
- Measure advisor tokens per second and time-to-first-token with ExecuTorch on the Cortex-A76.

## Evidence and compliance

Each verification produces a JSON evidence report in `evidence/reports/<session_id>.json`, containing:

- the verdict, score and reason
- the per-check results, structured as SARIF runs
- the compliance controls each check provides evidence for
- an Ed25519 signature over the payload ([`evidence/signer.py`](evidence/signer.py))

The report is available from the dashboard's evidence button and `GET /api/report/{session_id}`.

The compliance map ([`policy/compliance_map.yaml`](policy/compliance_map.yaml)) links the four checks to **17 controls**:

| Standard | Controls mapped |
|---|---|
| UNECE R155 (vehicle cybersecurity management) | 4 |
| UNECE R156 (software update management) | 1 |
| ETSI EN 303 645 (consumer IoT security) | 4 |
| ISA/IEC 62443-4-2 (industrial component security) | 4 |
| NIST SP 800-193 (platform firmware resiliency) | 4 |

The integration layer extends this to a standards-format bundle ([`integrations/evidence/bundle.py`](integrations/evidence/bundle.py)):

- `verdict.json`
- `findings.sarif` (SARIF 2.1.0)
- `sbom.cdx.json` (CycloneDX from Syft)
- `manifest.json`, which records the SHA-256 of every file, signed with Cosign

Changing any byte of any file fails `verify_bundle`.

## Quick start

Requires Python 3.10 or newer.

```bash
pip install -r requirements.txt
python main.py
```

On first run, `main.py`:

1. initialises the SQLite database
2. generates the three demo firmware images and the vendor and device keys
3. seeds the firmware registry, CVE database and identity registry
4. checks the compliance map
5. opens the dashboard at <http://localhost:8000>

Generated files (`db/*.db`, `firmware/images/`, `firmware/keys/`, `evidence/reports/`) stay local and are not committed.

**Tests**

```bash
python -m pytest tests
```
47 tests cover:

- end to end: a real charger process over OCPP 1.6 against the live gateway for the healthy, tampered, vulnerable, clone, mid-session compromise and quishing scenarios, including signed-report verification ([`tests/test_live_gateway.py`](tests/test_live_gateway.py); stop the dashboard first, both use ports 9000 and 9100)
- the scam-message and phishing-URL detectors, their explanations, the known-good list and the published metrics
- the attestation layer
- the behaviour baseline against every simulator attack mode
- the wolfSentry policy output
- tool-output parsers and the per-firmware audit cache
- wolfBoot digest checks
- SARIF output and evidence-bundle tamper detection

**Scenario rehearsal**

```bash
python -m simlab.run_headless          # all 11 scenarios, prints the verdict and enforcement for each
```

**Benchmark**

```bash
python benchmarks/bench_hotpath.py
```
Writes `benchmarks/results/<machine>-<os>.json`.

**Security tools available on this machine**

```bash
python -m integrations
```
Lists each external tool, whether it was found, and how to build or install it. Several tools (EMBA, RAUC, SWUpdate, unblob's extractors) are Linux-only and run on the Pi or in WSL.

## API

| Method | Path | Description |
|---|---|---|
| GET | `/` | Dashboard |
| GET | `/api/scenarios` | Preset attack scenarios |
| POST | `/api/verify` | Stage a scenario (preset `mode` or identity, firmware, behaviour and timing): launches the charger process and the tap; returns `session_id` |
| WS | `/ws/{session_id}` | Live stream: `ocpp` frames, `check_start`/`check_done`, `verdict` (also mid-session), `session` (charging state, kW, kWh), `traffic`, `monitor`, `enforcement`, `advisory`, `report_ready` |
| GET | `/api/report/{session_id}` | Signed evidence report (JSON) |
| GET | `/api/report/{session_id}/verify` | Checks the report's Ed25519 signature and that its body is unmodified |
| GET | `/api/session/{session_id}` | Session status |
| GET | `/api/status` | Gateway endpoint, advisor engine, active session, quarantined chargers |

The gateway itself listens for chargers on `ws://<node>:9000/ocpp/<charge-point-id>` (OCPP 1.6-J) and for flow records on `udp/9100`.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `CHARGEGUARD_TPM_BACKEND` | `software` | Attestation backend: `software`, `tpm2-tss`, `wolftpm` |
| `CHARGEGUARD_TPM_TCTI` | `mssim:host=127.0.0.1,port=2321` | tpm2-tss transport; `device:/dev/tpmrm0` for a hardware TPM |
| `CHARGEGUARD_TPM_EMULATOR` | `vendor/tpm/ibmswtpm2/src/tpm_server` | IBM software TPM binary |
| `CHARGEGUARD_TPM_EMULATOR_PORT` | `2321` | Emulator command port |
| `CHARGEGUARD_KEYLIME_VERIFIER` | `https://127.0.0.1:8881` | Keylime verifier URL |
| `CHARGEGUARD_KEYLIME_API` | `2.3` | Keylime REST API version |
| `CHARGEGUARD_KEYLIME_CERT`, `_KEY`, `_CA` | unset | Mutual-TLS client certificate, key and CA for Keylime |
| `CHARGEGUARD_TOOL_<NAME>` | unset | Explicit path to an external tool, for example `CHARGEGUARD_TOOL_SYFT=/opt/syft` |
| `CHARGEGUARD_PORT` | `8000` | Dashboard port |
| `CHARGEGUARD_NO_BROWSER` | unset | Do not open a browser on start (headless node) |
| `CHARGEGUARD_LLAMA_PTE`, `_TOKENIZER`, `_RUNNER` | `models/llama3_2_1b.pte`, `models/tokenizer.model`, `models/llama_main` | Llama advisor model, tokenizer and ExecuTorch runner |

## Repository layout

```
main.py            Entry point: provisioning, then gateway + dashboard
config.py          Paths, the 5-second schedule, gateway ports, site addressing
gateway/           Inline OCPP 1.6 gateway: live C1–C4 checks, monitoring, enforcement, flow collector
charger/           C10 OCPP 1.6 charger agent (separate process; runs on the charger Pi)
simlab/            Scenario staging, network tap simulator, headless scenario runner
advisor/           Plain-language advisor: Llama on ExecuTorch, grounded rule-based fallback, export script
threatintel/       On-device scam-message and phishing-URL detectors, training, ExecuTorch export
data/              Dataset checksums (raw data is fetched by scripts/fetch_datasets.py, git-ignored)
audit/             One-time firmware audit (component banners → curated real-CVE feed)
checks/            Original in-process C1–C4 checks (used by the benchmark)
orchestrator/      C5 orchestrator and trust engine
policy/            C6 compliance map and mapper
evidence/          C7 report generator, signer and report verification
dashboard/         C8 FastAPI backend, WebSocket stream, web UI
simulator/         Original in-process simulator and attack modes (used by the benchmark)
firmware/          Firmware image generator, provisioning and attestation enrolment
db/                SQLite registry: firmware, CVEs, identities, attestation keys, golden PCR0, runs
attestation/       C1 TPM 2.0 attestation: backends, verifiers, emulator launcher
integrations/      C2–C4, C7, C9 adapters for the vendored security tools
benchmarks/        Hot-path benchmark and committed results
scripts/           Dataset fetcher and asset preparation (dashboard 3D vehicle model)
tests/             pytest suite
vendor/            Vendored open-source tools, grouped by capability
```

Each layer has its own documentation: [`attestation/README.md`](attestation/README.md), [`integrations/README.md`](integrations/README.md) and [`vendor/README.md`](vendor/README.md). The vendored tools are:

| Capability | Tools |
|---|---|
| TPM and attestation | tpm2-tss, wolfTPM, Keylime, IBM Software TPM |
| Secure boot | MCUboot, wolfBoot |
| Updates | RAUC, SWUpdate, python-tuf |
| Signing | Cosign |
| Firmware analysis | unblob, Syft, Grype, cve-bin-tool, mithril, checksec, kernel-hardening-checker, FACT, EMBA |
| Network | iotaudit, wolfSentry |
| Attack lab | IoTGoat, Bruce, Facedancer, Renode |

## Novelty

- **A plug-in-time trust verdict for chargers.** Attestation, firmware provenance, known-vulnerability status and live behaviour are fused into one green / amber / red decision at the moment of connection, instead of four separate tools run by four teams.
- **Audit once, verify fast.** Minutes of firmware analysis become a single hash lookup at plug-in (0.5 ms measured), which is what makes a seconds-scale verdict possible on a single-board computer.
- **"Authentic but vulnerable" is a first-class outcome.** Signature checks alone pass a correctly signed image with exploitable libraries; ChargeGuard reports it as amber with the CVEs and the fix.
- **Verification that keeps watching.** The behaviour baseline encodes what a charger should do (peers, ports, rates and protocol phase order), so a charger that passed at plug-in can still be isolated mid-session, with the enforcement rendered as an embedded firewall policy.
- **Evidence as an output, not an afterthought.** Every verdict is signed and mapped to automotive and IoT standards controls, ready for an auditor.

## Roadmap

**Done**

- Live system: OCPP 1.6 charger process, inline gateway, real C1–C4 checks on observed data, continuous monitoring, enforcement (remote stop, disconnect, quarantine), 11 scenarios passing end to end
- Measured-boot attestation over OCPP `DataTransfer` and a one-time firmware audit against real CVEs
- Advisor with labelled engines; signed report covering the full body, verifiable from the dashboard
- Signed, compliance-mapped evidence report (17 controls, five standards)
- On-device scam-message and phishing-URL detectors with an honest evaluation protocol, exported to ExecuTorch with verified parity
- Payment-QR ("quishing") check on every charger, and a Driver Safety Check in the dashboard
- ExecuTorch 1.6 toolchain and the Llama 3.2 1B SpinQuant export path, ready for the licence-gated weights
- TPM 2.0 attestation layer with software, tpm2-tss and Keylime paths, and an IBM TPM emulator launcher
- Integration adapters for firmware integrity, firmware audit with a per-hash cache, behaviour baseline with block and isolate, SARIF + CycloneDX evidence bundles and a Renode attack lab
- Hot-path benchmark with committed results

**Next**

- Export Llama 3.2 1B Instruct (SpinQuant) with the prepared script once the licence is accepted, and measure tokens per second on the Pi 5
- Learned traffic classifier (CICIDS2017 / UNSW-NB15 plus charger captures) beside the rule baseline; HailoRT on the AI HAT+ where fitted
- Hardware path: tpm2-tss backend against a real TPM, packet capture on the node's bridge instead of the tap simulator, nftables rules applied
- Persistent SQLite connections on the hot path
- Bundle the dashboard's JavaScript libraries for fully air-gapped operation
- Run the benchmark on the Raspberry Pi 5, and profile with Arm Performance Studio
- Hardware demo: a Pi 5 node with an SPI TPM, and a second board or Renode-emulated Cortex-M as the charger

## Responsible use

The attack harness exists to exercise ChargeGuard in a lab:

- tampered images
- emulated controllers
- wireless and USB test firmware for separate hardware

Use it only on equipment and networks you own or are authorised to test. ChargeGuard never invokes the wireless or USB tools automatically.

## License

ChargeGuard's own source code has no open-source license file yet.

Vendored components remain under their own licenses, which are kept in each component's folder. [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) lists every component, its snapshot and its obligations.
