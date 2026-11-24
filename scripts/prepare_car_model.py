"""
Prepare the dashboard's 3D car model.

Source: "Car Concept" from the Khronos glTF Sample Assets
(Models/CarConcept/glTF-Binary/CarConcept.glb), model and textures by
Eric Chadwick, (c) 2024 Darmstadt Graphics Group GmbH, CC-BY 4.0.

The CC-BY licence of that asset excludes the Khronos and 3D Commerce logos
it carries. This script rebuilds the GLB so those logos are not
redistributed with ChargeGuard:

  * the Khronos logo texture (licence plate colour, emissive mask on rims,
    mirrors, brakes and hardware) is replaced by a plain black texture
  * the tyre sidewall colour texture (Khronos + 3D Commerce marks) is
    replaced by a uniform rubber colour
  * the tyre sidewall normal map (embossed logo text) is replaced by a flat
    normal map

Every other byte of geometry, material and texture data is unchanged. The
result is written to dashboard/static/models/car_concept.glb.

    python scripts/prepare_car_model.py path/to/CarConcept.glb
Requires Pillow.
"""
from __future__ import annotations

import hashlib
import io
import json
import struct
import sys
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dashboard" / "static" / "models" / "car_concept.glb"
SOURCE_SHA256 = "c272098089d78c5cd9fd9f24ff50ee8acf8d932c55f2d55fc10adb6c8998966b"


def _png(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def _pad(b: bytes, fill: bytes = b"\x00") -> bytes:
    return b + fill * ((4 - len(b) % 4) % 4)


def read_glb(data: bytes) -> tuple[dict, bytes]:
    magic, version, _ = struct.unpack_from("<4sII", data, 0)
    assert magic == b"glTF" and version == 2, "not a glTF 2.0 binary"
    jlen, jtype = struct.unpack_from("<I4s", data, 12)
    assert jtype == b"JSON"
    gltf = json.loads(data[20:20 + jlen])
    blen, btype = struct.unpack_from("<I4s", data, 20 + jlen)
    assert btype == b"BIN\x00"
    return gltf, data[28 + jlen:28 + jlen + blen]


def write_glb(gltf: dict, binary: bytes) -> bytes:
    j = _pad(json.dumps(gltf, separators=(",", ":")).encode(), b" ")
    b = _pad(binary)
    total = 12 + 8 + len(j) + 8 + len(b)
    return (struct.pack("<4sII", b"glTF", 2, total) + struct.pack("<I4s", len(j), b"JSON") + j +
            struct.pack("<I4s", len(b), b"BIN\x00") + b)


def image_bytes(gltf: dict, binary: bytes, index: int) -> bytes:
    bv = gltf["bufferViews"][gltf["images"][index]["bufferView"]]
    off = bv.get("byteOffset", 0)
    return binary[off:off + bv["byteLength"]]


def find_logo_images(gltf: dict) -> dict[int, str]:
    """Locate the logo-bearing images by the materials that use them."""
    tex = {i: t["source"] for i, t in enumerate(gltf["textures"])}
    mats = {m.get("name"): m for m in gltf["materials"]}
    plate = tex[mats["License"]["pbrMetallicRoughness"]["baseColorTexture"]["index"]]
    side_color = tex[mats["Tireside"]["pbrMetallicRoughness"]["baseColorTexture"]["index"]]
    side_normal = tex[mats["Tireside"]["normalTexture"]["index"]]
    return {plate: "khronos-logo", side_color: "tyre-sidewall-colour", side_normal: "tyre-sidewall-normal"}


def replacement(kind: str, original: bytes) -> bytes:
    src = Image.open(io.BytesIO(original))
    w, h = src.size
    if kind == "khronos-logo":
        return _png(Image.new("RGB", (w, h), (0, 0, 0)))
    if kind == "tyre-sidewall-colour":
        rgb = src.convert("RGB")
        hist = sorted(rgb.getcolors(maxcolors=w * h) or [], reverse=True)
        base = hist[0][1] if hist else (28, 28, 28)          # dominant rubber colour
        return _png(Image.new("RGB", (w, h), base))
    if kind == "tyre-sidewall-normal":
        return _png(Image.new("RGB", (w, h), (128, 128, 255)))  # flat tangent-space normal
    raise ValueError(kind)


def rebuild(data: bytes) -> tuple[bytes, dict[int, str]]:
    gltf, binary = read_glb(data)
    targets = find_logo_images(gltf)
    swap = {gltf["images"][i]["bufferView"]: replacement(kind, image_bytes(gltf, binary, i))
            for i, kind in targets.items()}
    out = bytearray()
    for idx, bv in enumerate(gltf["bufferViews"]):
        off = bv.get("byteOffset", 0)
        chunk = swap.get(idx, binary[off:off + bv["byteLength"]])
        while len(out) % 4:
            out += b"\x00"
        bv["byteOffset"] = len(out)
        bv["byteLength"] = len(chunk)
        out += chunk
    gltf["buffers"][0]["byteLength"] = len(out)
    gltf.setdefault("asset", {})["extras"] = {
        "chargeguard": "Logo textures removed (Khronos, 3D Commerce); see scripts/prepare_car_model.py"}
    return write_glb(gltf, bytes(out)), targets


def main(src: str) -> int:
    data = Path(src).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SOURCE_SHA256:
        print(f"warning: source SHA-256 {digest} differs from the expected {SOURCE_SHA256}")
    result, targets = rebuild(data)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(result)
    print(f"replaced images {targets}")
    print(f"wrote {OUT} ({len(result):,} bytes, was {len(data):,})")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
