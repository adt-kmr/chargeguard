# attestation

Backend-neutral TPM 2.0 attestation for ChargeGuard. It wraps the vendored
stacks in `third_party/tpm/` behind one small API so the rest of the app
never depends on a specific TPM library.

**Status:** standalone. Not wired into `checks/`, `orchestrator/` or the
dashboard yet.

## Layout

```
attestation/
├── __init__.py        # public API
├── types.py           # PCRSelection, PCRValues, Quote, AttestationEvidence, AttestationResult
├── base.py            # TPMBackend (prover) and Verifier (appraiser) interfaces
├── registry.py        # register_backend / get_backend, register_verifier / get_verifier
├── config.py          # AttestationConfig (env-overridable)
├── formats.py         # quote encoding; pure-Python TPMS_ATTEST parser
├── emulator.py        # start/stop the IBM software TPM
├── backends/
│   ├── software.py    # pure-Python TPM (works now, no native deps)
│   ├── tss.py         # tpm2-tss via tpm2-pytss: emulator, swtpm or hardware (experimental)
│   └── wolftpm.py     # embedded SPI/I2C TPM: interface contract, transport TODO
└── verifiers/
    ├── local.py       # in-process: signature, nonce, PCR digest, golden values
    └── keylime.py     # queries a Keylime verifier's agent state over REST
```

## Usage

```python
from attestation import get_backend, get_verifier, PCRSelection

sel = PCRSelection(indices=(0, 1, 7))
with get_backend("software") as tpm:           # or "tpm2-tss"
    tpm.extend_pcr(0, firmware_image_bytes)     # measured boot
    nonce = tpm.get_random(32)                  # in production the verifier makes the nonce
    evidence = tpm.collect_evidence("CG-CHARGER-001", nonce, sel)
    enrolled_key = tpm.get_endorsement_key()    # stored at enrolment time

result = get_verifier("local").verify(evidence, nonce,
                                      trusted_key=enrolled_key,
                                      golden_pcrs=reference_values)
result.trusted, result.reason, result.to_dict()
```

Against the IBM emulator (after building it, and with `pip install tpm2-pytss`):

```python
from attestation import TPMEmulator, get_backend
with TPMEmulator() as emu, get_backend("tpm2-tss", tcti=emu.tcti) as tpm:
    ...
```

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `CHARGEGUARD_TPM_BACKEND` | `software` | Default backend for `get_backend()` |
| `CHARGEGUARD_TPM_TCTI` | `mssim:host=127.0.0.1,port=2321` | tpm2-tss transport (`device:/dev/tpmrm0` for hardware) |
| `CHARGEGUARD_TPM_EMULATOR` | `third_party/tpm/ibmswtpm2/src/tpm_server` | Emulator binary |
| `CHARGEGUARD_TPM_EMULATOR_PORT` | `2321` | Emulator command port |
| `CHARGEGUARD_KEYLIME_VERIFIER` | `https://127.0.0.1:8881` | Keylime verifier URL |
| `CHARGEGUARD_KEYLIME_API` | `2.3` | Keylime REST API version |
| `CHARGEGUARD_KEYLIME_CERT` / `_KEY` / `_CA` | – | mTLS client cert, key and CA |

## Extending

Add a backend by subclassing `TPMBackend` and decorating it:

```python
@register_backend("my-tpm")
class MyTPM(TPMBackend): ...
```

then import it in `backends/__init__.py`. Verifiers work the same way with
`Verifier` and `@register_verifier`.

## Connecting to ChargeGuard later

The natural integration point is `checks/identity/identity_check.py`, which
today does an Ed25519 challenge-response. To switch it to TPM attestation:

1. At enrolment, store `tpm.get_endorsement_key()` and golden PCRs in the identity table.
2. In the check, issue a nonce, call `collect_evidence`, and run `get_verifier("local").verify(...)`.
3. Map `AttestationResult.status` to the check's pass/fail and put `result.to_dict()` in the evidence report.

## Tests

```bash
python tests/test_attestation.py
```
