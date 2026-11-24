# ChargeGuard demo runbook

How to run and present the live software demo. Everything on screen is produced
by the ChargeGuard gateway observing a real charger process; nothing is replayed.

## What is real and what is simulated

| Part | In this demo | On the Raspberry Pi deployment |
|---|---|---|
| Charger | Separate process (`charger/agent.py`) speaking **OCPP 1.6-J** over WebSocket via the `ocpp` library | Same agent on the charger Pi |
| Gateway | ChargeGuard node terminates the charger's OCPP connection (`gateway/csms.py`) | Same code on the node Pi |
| Identity (C1) | Ed25519 device key + TPM quote (software TPM, ECDSA P-256 attestation key) over OCPP `DataTransfer` | Hardware TPM 2.0 through tpm2-tss (`attestation/backends/tss.py`) |
| Integrity (C2) | Vendor Ed25519 signature, firmware registry, measured boot PCR0 vs golden value | Same, with PCR0 from the hardware TPM |
| Weaknesses (C3) | Firmware bytes audited once at start-up against a curated feed of real CVEs; lookup by hash at plug-in | Same, or Syft + Grype in audit mode |
| Behaviour (C4) | Inline OCPP transcript + flow records from the tap simulator (`simlab/tap.py`) | Inline OCPP + flows from the network bridge |
| Enforcement | OCPP `RemoteStopTransaction`, connection closed, device quarantined, authorisation refused; nftables and wolfSentry rules rendered | nftables rules applied on the node |
| Advisor | Rule-based engine grounded in the evidence, labelled as such on screen | Llama 3.2 1B on ExecuTorch once the model is exported |
| Timing | Checks take milliseconds; the dashboard holds each step to its window so the audience can follow. Real compute time is shown next to every check | Same |

## Start

```bash
pip install -r requirements.txt
python main.py
```

The console shows the provisioning steps, then the gateway (`ws://127.0.0.1:9000/ocpp/<id>`) and the dashboard at <http://localhost:8000>. Set `CHARGEGUARD_PORT` to use another port, and `CHARGEGUARD_NO_BROWSER=1` to skip opening a browser.

## The four acts (about 4 minutes)

| Act | Preset | Say | Audience sees |
|---|---|---|---|
| 1 | Healthy | "A genuine charger is plugged in." | Charger connects over OCPP, four checks tick off, **green 100/100** at 5.0 s, charging starts at about 7.2 kW and energy climbs |
| 2 | Tampered | "Someone modified the firmware after the vendor signed it." | Identity passes (it is the real device), integrity **fails**, verdict **red**, authorisation for the RFID card is refused |
| 3 | Vulnerable | "This firmware is genuine, but old." | **Amber 60/100**: 5 real CVEs in OpenSSL 1.1.1k, zlib 1.2.11, BusyBox 1.33.0, max CVSS 9.8; charging allowed with an upgrade recommendation |
| 4 | Compromised | "It passes at plug-in — but ChargeGuard keeps watching. Mid-session, the charger starts scanning the LAN." | Green, charging, status **LIVE MONITORING** with a check counter ("Check #8: normal…"). About 9 s in: **THREAT DETECTED MID-SESSION**, ring flips to **red 15/100**, then **CHARGER ISOLATED** with the remote stop and quarantine steps |
| Bonus | Custom → Payment QR: Quishing QR | "Attackers stick fake QR codes on chargers. ChargeGuard checks the QR every charger displays." | **Red**: the payment QR points to `chargepoint-pay.top`; charger isolated, with a plain-language explanation for the operator |
| Bonus | Driver Safety Check: Scam SMS / Fake pay link | "Drivers get scam texts about their charging account. The same on-device models check them in a few milliseconds." | Verdict, score, the words and rules behind it, and the advisor's steps |
| Close | Open Evidence Report | "Every verdict is signed and mapped to the standards." | Per-check results, CVEs, attestation (payload hash, PCR0, quote), enforcement steps, advisor, **Verify signature** |

The **Custom** preset composes any identity (legitimate, rogue, clone), firmware (good, tampered, vulnerable), behaviour (port scan, C2 beacon, DNS exfiltration, OCPP flood) and timing (at plug-in or mid-session).

## Rehearse without the dashboard

```bash
python -m simlab.run_headless                  # all 11 scenarios
python -m simlab.run_headless compromised -v   # one scenario, event by event
```

Stop the dashboard first; both use ports 9000/tcp and 9100/udp. The last full run is in [`benchmarks/results/scenario_matrix.json`](benchmarks/results/scenario_matrix.json).

| Scenario | Expected | What triggers it |
|---|---|---|
| healthy | green | — |
| tampered | red | firmware hash not in vendor registry |
| vulnerable | amber | 5 CVEs from the image audit |
| compromised | red, mid-session | port scan of a LAN host → isolate |
| clone | red | nonce signature does not match the enrolled device key |
| rogue | red | device ID not enrolled |
| c2_beacon | red | outbound beacons to 203.0.113.66:4444 + OCPP extension to an unapproved vendor → isolate |
| dns_exfil | red | high-rate DNS to a public resolver with encoded labels → isolate |
| ocpp_flood | red | MeterValues flood above the OCPP rate baseline → block |
| c2_mid_session | red, mid-session | C2 over an OCPP `DataTransfer` extension during charging → isolate |
| quishing | red | the payment QR on the charger screen points to a look-alike payment site → isolate |

## If something goes wrong

| Symptom | Fix |
|---|---|
| `error while attempting to bind on address ('127.0.0.1', 8000)` | Another dashboard is running. Close it or set `CHARGEGUARD_PORT=8001` |
| Charger never connects | Port 9000 is in use by another ChargeGuard; stop it |
| Verify button greyed out | Wait for the verdict; it re-enables once the report is signed |
