# vendor

Vendored source snapshots of the open-source tools ChargeGuard builds on,
grouped by capability. Version-control history, CI pipelines and
project-governance files (contributor, maintainer, code-of-conduct,
security-policy and AI-assistant files) were removed. Source, build systems,
tests and license files are kept.

Python adapters for these tools live in [`attestation/`](../attestation/README.md) (C1)
and [`integrations/`](../integrations/README.md) (C2–C9). Snapshot versions and
license obligations: [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

| Folder | Feature | Components |
|---|---|---|
| [`tpm/`](tpm/README.md) | C1 identity and attestation | tpm2-tss, wolfTPM, Keylime, IBM Software TPM |
| `secure-boot/` | C2 MCU firmware integrity | MCUboot, wolfBoot |
| `update/` | C2 Linux update + update metadata | RAUC, SWUpdate, python-tuf |
| `signing/` | C2 / C7 signatures | Sigstore Cosign |
| `firmware-analysis/` | C3 vulnerability audit | unblob, Syft, Grype, cve-bin-tool, mithril, checksec, kernel-hardening-checker, FACT, EMBA |
| `network-monitor/` | C4 behaviour monitor | iotaudit, wolfSentry |
| `attack-lab/` | C9 attack and test harness | IoTGoat, Bruce, Facedancer, Renode |

## Not vendored

| Tool | Reason | How ChargeGuard uses it instead |
|---|---|---|
| Wireshark | ~1.5 GB source tree | `tshark` from the OS package (`integrations/behavior/sources.py`) |
| ESP32 Marauder | Repository has no license, so it cannot be redistributed | Bruce (AGPL-3.0) covers the ESP32 wireless role |
| SCOUT | An exploit-generation platform rather than an evidence bundler; did not fit C7 | SARIF from Grype + our SARIF writer, CycloneDX from Syft, signed with Cosign |
| Uptane | Reference implementation is archived | python-tuf (Uptane is built on TUF); `aktualizr` can be added if a vehicle-grade client is needed |
| OCPP / ISO 15118 / EVerest | Not in the source list (open question) | in-house charger simulator |

## Former submodules

Some components depend on external repositories that were git submodules
upstream (Mbed TLS, wolfSSL, HAL packs, Renode infrastructure). They are not
stored here; their exact commits are pinned in [`submodules.lock`](submodules.lock):

```bash
python vendor/fetch_submodules.py --list
python vendor/fetch_submodules.py secure-boot/wolfboot
```

## Trimmed content

To keep the repository small, these upstream folders were left out of the snapshots:

- `firmware-analysis/cve-bin-tool`: `test/` (640 MB of binary fixtures), `presentation/`, `doc/`
- `firmware-analysis/unblob`: `tests/integration/` and `tests/files/` (Git LFS fixtures; some also have Windows-invalid file names), `docs/demo.gif`
- `firmware-analysis/fact-core`: `docs/`, `docsrc/`
- `attack-lab/iotgoat`: `images/` (README screenshots)
- `attack-lab/bruce`: `media/`, `pcbs/`
- `tpm/keylime`: `docs/`, `demo/`, `media/`

## Building

Most tools build natively on Linux (or WSL on Windows):

| Tool | Build |
|---|---|
| Cosign, Syft, Grype, checksec | `go build` in the tool folder (see `integrations/README.md`) |
| MCUboot imgtool | `pip install -r secure-boot/mcuboot/scripts/requirements.txt` |
| wolfBoot | `fetch_submodules.py secure-boot/wolfboot`, then `make` with a target config |
| RAUC | `meson setup build && meson compile -C build` |
| SWUpdate | `make defconfig && make` (enable `CONFIG_SIGNED_IMAGES`) |
| python-tuf, unblob, cve-bin-tool, iotaudit, kernel-hardening-checker, Facedancer | `pip install -e <folder>` |
| mithril | `cmake -S . -B build && cmake --build build` |
| wolfSentry | `make` (see its README for RTOS ports) |
| EMBA | Linux only: `sudo ./installer.sh -d` |
| FACT | Linux only: see `fact-core/INSTALL.md` |
| Renode | prefer a release package; source build needs `fetch_submodules.py attack-lab/renode` |
| IoTGoat | OpenWrt build (`attack-lab/iotgoat/OpenWrt`) |
| Bruce | PlatformIO, for ESP32 boards |
