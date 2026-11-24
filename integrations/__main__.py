"""`python -m integrations` – report which external tools are available."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from integrations import doctor  # noqa: E402

if __name__ == "__main__":
    report = doctor()
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        for name, info in report.items():
            mark = "OK " if info["available"] else "-- "
            print(f"{mark} {info['feature']:<8} {name:<26} {info.get('command') or info.get('hint')}")
