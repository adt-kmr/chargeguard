"""
Download the public datasets used to train ChargeGuard's threat detectors.

  sms_spam   UCI SMS Spam Collection (5,574 SMS, ham/spam)                   CC BY 4.0
             https://archive.ics.uci.edu/dataset/228/sms+spam+collection
  phiusiil   UCI PhiUSIIL Phishing URL Dataset (235,795 URLs)                CC BY 4.0
             https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

Files land in data/raw/<name>/ (git-ignored). SHA-256 of every downloaded
archive is written to data/raw/<name>/SHA256 and printed, and compared with
data/checksums.json when an entry exists there.

    python scripts/fetch_datasets.py            # both
    python scripts/fetch_datasets.py sms_spam
"""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
CHECKSUMS = ROOT / "data" / "checksums.json"

DATASETS = {
    "sms_spam": "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip",
    "phiusiil": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
}


def fetch(name: str) -> str:
    url = DATASETS[name]
    out = RAW / name
    out.mkdir(parents=True, exist_ok=True)
    archive = out / "archive.zip"
    req = urllib.request.Request(url, headers={"User-Agent": "chargeguard-dataset-fetch/1.0"})
    with urllib.request.urlopen(req, timeout=300) as r, open(archive, "wb") as f:
        while chunk := r.read(1 << 20):
            f.write(chunk)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    with zipfile.ZipFile(archive) as z:
        for member in z.namelist():                 # refuse path traversal
            target = (out / member).resolve()
            if not str(target).startswith(str(out.resolve())):
                raise RuntimeError(f"unsafe path in archive: {member}")
        z.extractall(out)
    (out / "SHA256").write_text(digest + "\n")
    known = json.loads(CHECKSUMS.read_text()) if CHECKSUMS.exists() else {}
    if name in known and known[name] != digest:
        raise RuntimeError(f"{name}: checksum {digest} does not match recorded {known[name]}")
    print(f"{name}: {archive.stat().st_size:,} bytes, sha256 {digest}")
    return digest


if __name__ == "__main__":
    names = sys.argv[1:] or list(DATASETS)
    for n in names:
        fetch(n)
