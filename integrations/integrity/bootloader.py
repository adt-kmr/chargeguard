"""
Microcontroller bootloader image checks: MCUboot and wolfBoot.

MCUboot  – delegates to the vendored `imgtool verify`, which checks the image
           hash TLV and the signature against the vendor key.
wolfBoot – pure-Python parser for the wolfBoot manifest header (magic, size,
           TLVs). It recomputes the SHA-256 digest exactly as wolfBoot's
           image.c does. Signature checking needs the target's keystore format
           and is left to wolfBoot's own `keytools` until a key format is chosen.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path

from ..core import Finding, Severity, Tool, ToolResult, register_tool, run, timed

IMGTOOL = register_tool(Tool(
    name="imgtool", executables=("imgtool",), feature="C2",
    vendored="secure-boot/mcuboot",
    build_outputs=("python:secure-boot/mcuboot/scripts/imgtool.py",),
    requires_modules=("click", "cryptography", "intelhex", "cbor2"),
    install_hint="pip install -r vendor/secure-boot/mcuboot/scripts/requirements.txt",
))


def verify_mcuboot(image: str | Path, pubkey: str | Path, timeout: float = 20.0) -> ToolResult:
    result = ToolResult(tool="imgtool", ok=False)
    with timed(result):
        proc = run(IMGTOOL, ["verify", "-k", pubkey, image], timeout=timeout, check=False)
        result.ok = proc.returncode == 0
        result.raw = (proc.stdout + proc.stderr).strip()
        if not result.ok:
            result.findings.append(Finding("imgtool", "mcuboot-verify-failed",
                                           "MCUboot image hash or signature invalid",
                                           Severity.CRITICAL, str(image), {"output": result.raw[-500:]}))
    return result


# ── wolfBoot ──────────────────────────────────────────────────────────────

WOLFBOOT_MAGIC = b"WOLF"        # 0x574F4C46 stored little-endian on target -> b"FLOW" in file
_HDR = {0x01: "version", 0x02: "timestamp", 0x03: "sha256", 0x04: "img_type",
        0x10: "pubkey_hint", 0x14: "sha384", 0x20: "signature"}


@dataclass
class WolfBootImage:
    size: int
    fields: dict[str, bytes] = field(default_factory=dict)
    sha_tlv_offset: int | None = None

    @property
    def version(self) -> int | None:
        v = self.fields.get("version")
        return struct.unpack("<I", v)[0] if v and len(v) == 4 else None


def parse_wolfboot(data: bytes, header_size: int = 256) -> WolfBootImage:
    if data[:4] not in (WOLFBOOT_MAGIC, WOLFBOOT_MAGIC[::-1]):
        raise ValueError("not a wolfBoot image (bad magic)")
    (size,) = struct.unpack_from("<I", data, 4)
    img, pos = WolfBootImage(size=size), 8
    while pos + 4 <= header_size:
        if data[pos] == 0xFF:                  # HDR_PADDING
            pos += 1
            continue
        t, ln = struct.unpack_from("<HH", data, pos)
        if t == 0x00:                          # HDR_END
            break
        if t == 0x03:
            img.sha_tlv_offset = pos
        img.fields[_HDR.get(t, f"tlv_{t:#06x}")] = data[pos + 4:pos + 4 + ln]
        pos += 4 + ln
    return img


def verify_wolfboot_hash(path: str | Path, header_size: int = 256) -> ToolResult:
    result = ToolResult(tool="wolfboot", ok=False)
    with timed(result):
        data = Path(path).read_bytes()
        img = parse_wolfboot(data, header_size)
        stored = img.fields.get("sha256")
        if stored is None or img.sha_tlv_offset is None:
            raise ValueError("image has no SHA-256 TLV")
        fw = data[header_size:header_size + img.size]
        calc = hashlib.sha256(data[:img.sha_tlv_offset] + fw).digest()
        result.ok = calc == stored and len(fw) == img.size
        result.raw = {"version": img.version, "size": img.size, "sha256": stored.hex(),
                      "has_signature": "signature" in img.fields}
        if not result.ok:
            result.findings.append(Finding("wolfboot", "wolfboot-hash-mismatch",
                                           "wolfBoot image digest does not match its header",
                                           Severity.CRITICAL, str(path),
                                           {"expected": stored.hex(), "computed": calc.hex()}))
    return result
