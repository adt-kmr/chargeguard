# Third-party notices

ChargeGuard includes source code from the open-source projects below,
located under `vendor/`. Each is used under its own license; the full
license text (and any NOTICE / COPYRIGHT file) is kept in that component's
folder and must stay there. Copyright headers inside source files must also
be preserved.

| Component | Snapshot (commit, date) | Path | License |
|-----------|-------------------------|------|---------|
| **C1 – identity and attestation** ||||
| tpm2-tss | 4.2.2+ `8de0ea0`, 2026-11-17 | `tpm/tpm2-tss` | BSD-2-Clause |
| wolfTPM | 4.2.0 `a1a81c4`, 2026-11-19 | `tpm/wolftpm` | GPL-3.0 (with exception) or commercial |
| Keylime | 7.14.3 `fb659a9`, 2026-11-23 | `tpm/keylime` | Apache-2.0 |
| IBM Software TPM 2.0 | `ad16986`, 2026-10-14 | `tpm/ibmswtpm2` | BSD-style (TCG reference code) |
| **C2 – firmware integrity and secure update** ||||
| MCUboot | `8e51bcb`, 2026-11-23 | `secure-boot/mcuboot` | Apache-2.0 (`NOTICE`) |
| wolfBoot | `0625155`, 2026-11-19 | `secure-boot/wolfboot` | GPL-3.0 or commercial |
| RAUC | `0d16baa`, 2026-11-23 | `update/rauc` | LGPL-2.1 |
| SWUpdate | `763eb2b`, 2026-11-22 | `update/swupdate` | GPL-2.0 (parts LGPL-2.1 / MIT / BSD, see `LICENSES/`) |
| python-tuf | `a027646`, 2026-11-20 | `update/python-tuf` | Apache-2.0 OR MIT |
| Sigstore Cosign | `19c90f9`, 2026-11-22 | `signing/cosign` | Apache-2.0 (`COPYRIGHT.txt`) |
| **C3 – vulnerability and supply-chain audit** ||||
| unblob | `1179e5f`, 2026-11-23 | `firmware-analysis/unblob` | MIT (`NOTICE`) |
| Syft | `9ad9aa5`, 2026-11-23 | `firmware-analysis/syft` | Apache-2.0 (`COPYRIGHT`) |
| Grype | `8b2987c`, 2026-11-20 | `firmware-analysis/grype` | Apache-2.0 (`COPYRIGHT`) |
| CVE Binary Tool | `09539e7`, 2026-11-23 | `firmware-analysis/cve-bin-tool` | GPL-3.0 |
| mithril | `8dcf577`, 2026-11-12 | `firmware-analysis/mithril` | MIT |
| checksec | `7d6a92d`, 2026-10-28 | `firmware-analysis/checksec` | BSD |
| kernel-hardening-checker | `b2acfd4`, 2026-09-19 | `firmware-analysis/kernel-hardening-checker` | GPL-3.0 |
| FACT | `372924c`, 2026-11-18 | `firmware-analysis/fact-core` | GPL-3.0 |
| EMBA | `c509f66`, 2026-11-23 | `firmware-analysis/emba` | GPL-3.0 (bundled parts: `licenses/`) |
| **C4 – live behaviour monitor** ||||
| iotaudit | `8985d51`, 2026-11-24 | `network-monitor/iotaudit` | MIT |
| wolfSentry | `2ccc12d`, 2026-10-21 | `network-monitor/wolfsentry` | GPL-2.0-or-later or commercial (`LICENSING`) |
| **C9 – attack and test harness** ||||
| IoTGoat | `f67b7f9`, 2025-10-04 | `attack-lab/iotgoat` | MIT (OpenWrt sources: GPL-2.0) |
| Bruce | `2b6ba4d`, 2026-11-12 | `attack-lab/bruce` | AGPL-3.0 |
| Facedancer | `98790aa`, 2026-11-05 | `attack-lab/facedancer` | BSD-3-Clause |
| Renode | `b366439`, 2026-11-23 | `attack-lab/renode` | MIT |

## Training data

The threat-detector weights in `threatintel/weights/` were trained on these
datasets. The raw data is not redistributed: `scripts/fetch_datasets.py`
downloads it into the git-ignored `data/raw/` and checks it against
`data/checksums.json`.

| Dataset | Source | License | Use |
|---------|--------|---------|-----|
| SMS Spam Collection (T. A. Almeida, J. M. Gómez Hidalgo) | UCI Machine Learning Repository, dataset 228 | CC-BY-4.0 | Scam-message model |
| PhiUSIIL Phishing URL Dataset (A. Prasad, S. Chandra) | UCI Machine Learning Repository, dataset 967 | CC-BY-4.0 | Phishing-hostname model |

**Changes made:** duplicate messages removed; URLs reduced to hostnames (scheme,
`www.` and path removed); hostnames labelled both ways dropped. See `threatintel/README.md`.

## Runtime (not vendored)

ExecuTorch 1.6.0 (BSD-3-Clause, PyTorch / Meta) and PyTorch are installed from PyPI
in a separate environment for model export and the on-device runtime. Llama 3.2
weights are not included in this repository and are subject to Meta's Llama 3.2
Community License, which each user accepts individually.

## Dashboard assets

| Asset | Source | Path | License |
|-------|--------|------|---------|
| Car Concept 3D model | Khronos glTF Sample Assets, `Models/CarConcept` (`7d4ba18`). Model and textures by Eric Chadwick, © 2024 Darmstadt Graphics Group GmbH | `dashboard/static/models/car_concept.glb` | CC-BY-4.0 |

**Changes made:** the three textures carrying the Khronos and 3D Commerce logos (which that
licence excludes) were replaced with plain colours by
[`scripts/prepare_car_model.py`](scripts/prepare_car_model.py), and the licence plate is
rendered blank. Geometry and every other texture are unchanged. Details:
[`dashboard/static/models/ATTRIBUTION.md`](dashboard/static/models/ATTRIBUTION.md).

External repositories that were git submodules upstream are not included;
they are pinned in `vendor/submodules.lock` and keep their own licenses
when fetched.

## Obligations

- **Permissive (BSD, MIT, Apache-2.0)**: keep copyright notices and license
  text in source and binary redistributions. For Apache-2.0 components, also
  ship their `NOTICE` file and mark files you modify as changed.
- **Tools run as separate programs** (cve-bin-tool, EMBA, FACT,
  kernel-hardening-checker, SWUpdate, RAUC): ChargeGuard calls them as
  external processes, which does not place ChargeGuard's own code under their
  license. If you redistribute the tools themselves, include their license
  and source.
- **Libraries linked into firmware** (wolfTPM, wolfBoot, wolfSentry): a
  firmware image that links them must be released under the GPL, unless you
  obtain wolfSSL's commercial license. Nothing in ChargeGuard links them
  today; review this before shipping charger firmware.
- **AGPL-3.0 (Bruce)**: runs on separate ESP32 test hardware. If you modify it
  and offer it over a network, you must provide the modified source.

Modifications made to snapshots are listed in `vendor/README.md` and
`vendor/tpm/README.md`.
