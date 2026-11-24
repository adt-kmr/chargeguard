# ChargeGuard

**EV charger security verification in under 5 seconds.**

ChargeGuard verifies an EV charger the moment it is plugged in. It runs four
security checks against the charger, fuses the results into a single
green / amber / red trust verdict, and produces a signed evidence report mapped
to automotive and IoT cybersecurity standards.

## How it works

Each verification runs inside a fixed 5-second budget:

| Window      | Check                     | What it verifies                                              |
|-------------|---------------------------|---------------------------------------------------------------|
| 0.0 – 1.0 s | **Identity & attestation** | Challenge-response: charger signs a nonce with its device key (Ed25519, TPM mock) |
| 1.0 – 2.0 s | **Firmware integrity**     | Image hash and vendor signature against the firmware registry |
| 2.0 – 3.0 s | **Known weaknesses**       | Firmware hash matched against a CVE database                  |
| 3.0 – 4.5 s | **Behaviour**              | Traffic sample analysed for port scans, C2 beacons, DNS exfiltration, bursts |
| 4.5 – 5.0 s | **Verdict**                | Trust engine fuses results into green / amber / red           |

Every run produces a signed JSON evidence report, with each result annotated
against **UNECE R155/R156**, **ETSI EN 303 645** and **ISA/IEC 62443-4-2** controls.

## Project layout

```
chargeguard/
├── main.py              # Entry point: setup + dashboard server
├── config.py            # Paths, timing budget, verdicts, modes
├── checks/              # C1–C4: identity, integrity, weaknesses, behavior
├── orchestrator/        # Runs checks on schedule; trust engine (C5)
├── policy/              # Compliance map (YAML) and mapper (C6)
├── evidence/            # Report generator and signer (C7)
├── dashboard/           # FastAPI backend + WebSocket stream + web UI (C8)
├── simulator/           # Attack harness (C9) and charger simulator (C10)
├── firmware/            # Firmware image and key generator
├── db/                  # SQLite registry: firmware, CVEs, identities, runs
├── attestation/         # TPM 2.0 attestation layer (pluggable backends + verifiers)
├── third_party/tpm/     # Vendored TPM stacks: tpm2-tss, wolfTPM, Keylime, IBM SW TPM
└── tests/               # Unit tests
```

See [`attestation/README.md`](attestation/README.md) for the TPM layer and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for third-party licenses.

## Getting started

Requires Python 3.10+.

```bash
pip install -r requirements.txt
python main.py
```

On first run ChargeGuard initialises the SQLite database, generates the demo
firmware images and keys, seeds the firmware registry and CVE database, then
opens the dashboard at <http://localhost:8000>.

Generated artifacts (`db/*.db`, `firmware/images/`, `firmware/keys/`,
`evidence/reports/`) are created locally and are not tracked in git.

## Demo scenarios

Use the attack control panel in the dashboard to pick a preset or compose your own:

- **Healthy** – genuine device, authentic firmware, no CVEs → **GREEN**
- **Tampered** – firmware payload modified, signature mismatch → **RED**
- **Vulnerable** – authentic but outdated firmware with known CVEs → **AMBER**
- **Compromised** – malicious network behaviour (C2 / exfiltration) → **RED**

## API

| Method | Path                        | Description                          |
|--------|-----------------------------|--------------------------------------|
| GET    | `/`                         | Dashboard UI                         |
| GET    | `/api/scenarios`            | Available attack scenarios           |
| POST   | `/api/verify`               | Start a verification session         |
| WS     | `/ws/{session_id}`          | Live stream of check events          |
| GET    | `/api/report/{session_id}`  | Download the signed evidence report  |
| GET    | `/api/session/{session_id}` | Session status                       |
