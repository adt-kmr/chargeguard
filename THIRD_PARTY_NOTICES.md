# Third-party notices

ChargeGuard includes source code from the open-source projects below,
located under `third_party/tpm/`. Each is used under its own license; the
full license text is kept in that component's folder and must stay there.
Copyright headers inside the source files must also be preserved.

| Component | Snapshot | Path | License | License file(s) |
|-----------|----------|------|---------|-----------------|
| tpm2-tss | 4.2.2+ (commit `8de0ea0`, 2026-11-17) | `third_party/tpm/tpm2-tss` | BSD-2-Clause | `LICENSE`, `LICENSES/` |
| wolfTPM | 4.2.0 (commit `a1a81c4`, 2026-11-19) | `third_party/tpm/wolftpm` | GPL-3.0 with exception, or commercial | `LICENSE`, `COPYING` |
| Keylime | 7.14.3 (commit `fb659a9`, 2026-11-23) | `third_party/tpm/keylime` | Apache-2.0 | `LICENSE` |
| IBM Software TPM 2.0 | commit `ad16986`, 2026-10-14 | `third_party/tpm/ibmswtpm2` | BSD-style (TCG reference code) | `LICENSE` |

## Obligations

- **BSD (tpm2-tss, IBM Software TPM)**: keep the copyright notice and license
  text in source and binary redistributions.
- **Apache-2.0 (Keylime)**: keep `LICENSE`; mark files you modify as changed;
  include this notice with distributions.
- **GPL-3.0 (wolfTPM)**: distributing software that links wolfTPM requires
  releasing that combined work under GPL-3.0, unless a commercial license is
  obtained. ChargeGuard's Python code does not link wolfTPM today; review this
  before shipping firmware or binaries that include it.

Modifications made to these snapshots are listed in `third_party/tpm/README.md`.
