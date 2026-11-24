# Vendored TPM stacks

Source snapshots of four open-source TPM 2.0 projects, kept in-tree so
ChargeGuard can modify and build them. Version-control history, CI
pipelines and upstream project-governance files have been removed;
source, build system, tests and license files are kept.

| Folder        | Component                       | Role in ChargeGuard                                     | License        |
|---------------|---------------------------------|---------------------------------------------------------|----------------|
| `tpm2-tss/`   | TPM2 Software Stack (C)         | Host-side TPM access (ESAPI/FAPI/TCTI) for the `tpm2-tss` backend | BSD-2-Clause |
| `wolftpm/`    | wolfTPM (C, embedded)           | TPM 2.0 over SPI/I2C on charger controllers (`wolftpm` backend) | GPL-3.0 (+ exception) / commercial |
| `keylime/`    | Keylime (Python)                | Continuous remote attestation (registrar + verifier); `keylime` verifier | Apache-2.0 |
| `ibmswtpm2/`  | IBM Software TPM 2.0 (C)        | TPM emulator for development and CI (`attestation.TPMEmulator`) | BSD-style (TCG) |

The Python integration layer that uses these lives in [`attestation/`](../../attestation/README.md).
Snapshot versions and license obligations are recorded in
[`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md).

## Building

All four build natively on Linux (or WSL on Windows).

**IBM software TPM (emulator)**
```bash
cd ibmswtpm2/src && make            # produces tpm_server
./tpm_server -port 2321 -rm         # command port 2321, platform port 2322
```
Windows: open `ibmswtpm2/tpmvstudio/` in Visual Studio.

**tpm2-tss**
```bash
cd tpm2-tss
./bootstrap && ./configure --disable-doxygen-doc && make -j && sudo make install
pip install tpm2-pytss               # Python bindings used by attestation/backends/tss.py
```
`VERSION` is pinned because the snapshot has no git history (`bootstrap` keeps it).

**wolfTPM**
```bash
cd wolftpm
./autogen.sh && ./configure --enable-swtpm && make     # --enable-swtpm talks to the emulator
```
Requires wolfSSL installed. The optional `lib/wolfSPDM` and `lib/wolfHAL`
submodules are not included; `--enable-spdm` is therefore unavailable.

**Keylime**
```bash
cd keylime && pip install -e .       # keylime_verifier, keylime_registrar, keylime_tenant
```

## Local modifications

Changes made to the snapshots are listed here so they can be re-applied when updating.

- `tpm2-tss/bootstrap`: only regenerate `VERSION` when a `.git` directory exists.
- `tpm2-tss/VERSION`: added (pinned).
- `tpm2-tss/Makefile.am`, `wolftpm/Makefile.am`: dropped removed files from `EXTRA_DIST`.
- `wolftpm/.gitignore`: un-ignore `m4/` and `examples/firmware/Makefile`, which upstream tracks.
- Keylime `docs/`, `demo/`, `media/` removed (not needed to build or run).
