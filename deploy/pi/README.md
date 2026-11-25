# Raspberry Pi deployment

Two Raspberry Pis: the **node** sits inline between a charger and the site network and
runs ChargeGuard; the **charger** Pi plays a charger controller with a hardware TPM.

```
 charger Pi (10.20.0.15)            node Pi                           site switch
 ┌──────────────────────┐   eth1  ┌────────────────────────────┐ eth0
 │ OCPP 1.6 agent       │─────────│ br0 10.20.0.1              │──────────  site network
 │ TPM: PCR 23 measured │  cable  │ flows: capture on eth1     │
 │ launch, quotes       │         │ node: gateway, checks,     │
 └──────────────────────┘         │ learned models, nftables,  │
                                  │ Llama advisor, dashboard   │
                                  └────────────────────────────┘
```

## What you need

| Item | For |
|---|---|
| Raspberry Pi 5, 8 GB, active cooler, 27 W USB-C supply | node |
| Raspberry Pi 5 (4 GB is enough) or Pi 4, supply | charger controller |
| 2 × SPI TPM 2.0 modules (Infineon SLB9670, e.g. LetsTrust TPM) | one per Pi |
| USB 3 gigabit Ethernet adapter | node's second port (eth1, towards the charger) |
| 2 × microSD 32 GB+ (or NVMe on the node) with 64-bit Raspberry Pi OS Bookworm | |
| 2–3 Ethernet cables, small switch | |

## Node

```bash
git clone <this repository> && cd chargeguard
sudo bash deploy/pi/node/install.sh        # CHARGER_PORT=eth1 UPLINK_PORT=eth0 by default
sudo reboot
sudo -u chargeguard /opt/chargeguard/venv/bin/python /opt/chargeguard/app/scripts/pi_preflight.py --role node
```

The installer bridges `eth0` and `eth1` into `br0` (address 10.20.0.1/24), enables the
SPI TPM overlay, creates `/opt/chargeguard`, and installs two services:

| Service | Runs | Privilege |
|---|---|---|
| `chargeguard-node` | `main.py` in node mode: OCPP gateway on 0.0.0.0:9000, checks, learned models, enforcement, dashboard on :8000 | `CAP_NET_ADMIN` (nftables) |
| `chargeguard-flows` | `python -m netflow.exporter --iface eth1`: packets -> NetFlow records -> the node | `CAP_NET_RAW` |

Settings live in `/etc/default/chargeguard` (see `node/chargeguard.env`). In **node mode**
a verification starts whenever a charger connects; the dashboard follows it automatically,
and a quarantine stays in force until an operator releases it:

```bash
curl -X POST http://10.20.0.1:8000/api/quarantine/CG-CHARGER-001/release
```

**Firewall.** `CHARGEGUARD_FIREWALL=check` validates the generated rules with `nft --check`
on every enforcement; once the preflight shows them valid, set `apply` and restart the
node. Quarantine drops the charger's traffic on the bridge and to the node; blocks expire
after an hour.

**Llama advisor.** Copy the exported program from the development machine; the node uses
it in-process through ExecuTorch (no separate service on the Pi):

```bash
scp models/llama3_2_1b.pte models/tokenizer.model <node>:/opt/chargeguard/app/models/
```

If `pip install executorch==1.6.0` finds no wheel for the Pi, build ExecuTorch from source
(`./install_executorch.sh` in the ExecuTorch repository, about 30 minutes on a Pi 5) or
leave it out: the detectors fall back to NumPy and the advisor to the grounded engine.

**Measure on the Pi.** `python advisor/bench_llama.py` and `python -m trafficml.executorch_export`
write Arm results to `benchmarks/results/`.

## Charger

```bash
sudo bash deploy/pi/charger/install.sh
sudo reboot
sudo -u chargeguard /opt/chargeguard-charger/venv/bin/python /opt/chargeguard-charger/app/scripts/pi_preflight.py --role charger
```

1. **Firmware and device key.** The node builds and signs the vendor images on first start.
   Copy `firmware/images/` and `firmware/keys/CG-CHARGER-001_private.pem` from the node to
   `/opt/chargeguard-charger/app/firmware/`.
2. **Enrol the TPM.** On the charger:
   ```bash
   sudo -u chargeguard env CHARGEGUARD_TPM_TCTI=device:/dev/tpmrm0 \
     /opt/chargeguard-charger/venv/bin/python -m charger.enroll --tpm tpm2-tss > enrol.json
   ```
   copy `enrol.json` to the node, then `sudo -u chargeguard /opt/chargeguard/venv/bin/python -m firmware.provision --enrol enrol.json`
   and restart `chargeguard-node`. The file holds public keys only.
3. **Start.** `sudo systemctl start chargeguard-charger`. At every start the agent resets
   PCR 23, extends the firmware image into it (measured launch) and connects to the node,
   which challenges it with a fresh nonce and checks the quote and PCR 23 against the
   golden value.

Why PCR 23: on a hardware TPM, PCR 0 is reset only at power-on and belongs to the boot
firmware, so a process restart could never reproduce its value. PCR 23 is resettable by
software at locality 0; reset-then-extend gives SHA-256(0³² ‖ SHA-256(image)), the same
golden value the node already holds. A Raspberry Pi has no measured boot of its own; on
a microcontroller charger, MCUboot or wolfBoot measures the image before it runs.

## Learned baseline from the real charger

The shipped baseline was fitted on simulated healthy traffic. After deployment, record
the real charger's traffic for a while and refit:

```bash
# on the node: capture healthy traffic (one JSON flow record per line) for an hour or more
sudo -u chargeguard /opt/chargeguard/venv/bin/python -m netflow.exporter --iface eth1 \
     --collector 127.0.0.1:9199 --active 1 --idle 2 &
nc -klu 127.0.0.1 9199 > enrolment.jsonl            # stop both after the capture window
python -m trafficml.behaviour fit --records enrolment.jsonl
sudo systemctl restart chargeguard-node
```

## What has not been run on hardware yet

The software above is exercised in simulation and by the test suite, but the following
need the real boards and are the first things to verify:

- the tpm2-tss path end to end (`pi_preflight.py --role charger` exercises reset, extend and quote on PCR 23);
- `nft --check` and `apply` of the generated ruleset on the bridge;
- live capture on `eth1` with `CAP_NET_RAW` and the learned baseline on real charger traffic;
- ExecuTorch on aarch64 and the Llama tokens-per-second figure.
