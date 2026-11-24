"""
Fetch the external dependencies listed in submodules.lock at their pinned commits.

The vendored snapshots do not include their former git submodules (crypto
libraries, HAL packs, Renode's infrastructure). Run this before building a
component that needs them:

    python third_party/fetch_submodules.py secure-boot/wolfboot
    python third_party/fetch_submodules.py --list
    python third_party/fetch_submodules.py            # everything

Fetched trees land at their original paths and are git-ignored.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOCK = HERE / "submodules.lock"


def entries():
    for line in LOCK.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            component, path, url, commit = line.split("\t")
            yield component, path, url, commit


def fetch(component: str, path: str, url: str, commit: str) -> None:
    dest = HERE / component / path
    if dest.exists() and any(dest.iterdir()):
        print(f"skip  {component}/{path} (exists)")
        return
    dest.mkdir(parents=True, exist_ok=True)
    print(f"fetch {component}/{path} @ {commit[:10]}")
    git = lambda *a: subprocess.run(["git", "-C", str(dest), *a], check=True)  # noqa: E731
    git("init", "-q")
    git("remote", "add", "origin", url)
    git("fetch", "-q", "--depth", "1", "origin", commit)
    git("checkout", "-q", "FETCH_HEAD")
    shutil.rmtree(dest / ".git", ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("components", nargs="*", help="e.g. secure-boot/wolfboot (default: all)")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    rows = [e for e in entries() if not args.components or e[0] in args.components]
    if args.list:
        for c, p, _, sha in rows:
            print(f"{c}/{p}  {sha[:10]}")
        return 0
    for row in rows:
        fetch(*row)
    return 0


if __name__ == "__main__":
    sys.exit(main())
