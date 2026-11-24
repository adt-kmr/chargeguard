# car_concept.glb

**"Car Concept"** — model and textures by **Eric Chadwick**, © 2024 **Darmstadt Graphics Group GmbH**,
from the Khronos glTF Sample Assets (`Models/CarConcept/glTF-Binary/CarConcept.glb`, repository commit `7d4ba18`).
Built from a public-domain (CC0) concept car by Unity Fan.

Licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/) (CC-BY-4.0).

## Changes made by ChargeGuard

The source licence excludes the Khronos and 3D Commerce logos embedded in the asset. They are removed:

| Texture | Used by | Change |
|---|---|---|
| Khronos logo | licence plate colour; emissive mask on rims, mirrors, brakes and hardware | replaced with plain black |
| Tyre sidewall colour (Khronos and 3D Commerce marks) | tyre sidewalls | replaced with the dominant rubber colour |
| Tyre sidewall normal map (embossed logo text) | tyre sidewalls | replaced with a flat normal map |

The dashboard also renders the licence plate blank. Geometry, materials and all other textures are unchanged.

The file is reproduced from the original with
[`scripts/prepare_car_model.py`](../../../scripts/prepare_car_model.py), which checks the source SHA-256
(`c272098089d78c5cd9fd9f24ff50ee8acf8d932c55f2d55fc10adb6c8998966b`).

No endorsement by the authors, Darmstadt Graphics Group or the Khronos Group is implied.
