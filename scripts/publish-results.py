"""Copy independently verified local benchmark artifacts into the static site."""

import argparse
import gzip
import hashlib
import json
import shutil
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "runs", type=Path, nargs="+", help="Completed run directories, largest last"
)
parser.add_argument("--destination", type=Path, default=Path("web/data"))
args = parser.parse_args()
reports = []
for run in args.runs:
    report = json.loads((run / "report.json").read_text())
    if not all(
        report.get(flag)
        for flag in ("verified", "bind_verified", "byte_identical_zones")
    ):
        raise SystemExit(f"Unverified result: {run}")
    if (
        hashlib.sha256((run / "gpu.zone").read_bytes()).hexdigest()
        != report["zone_sha256"]
    ):
        raise SystemExit(f"Zone checksum mismatch: {run}")
    reports.append(report)
args.destination.mkdir(parents=True, exist_ok=True)
for name in ("report.json", "sample.json", "bind-verification.txt"):
    shutil.copyfile(args.runs[-1] / name, args.destination / name)
(args.destination / "series.json").write_text(json.dumps(reports, indent=2) + "\n")
(args.destination / "gpu.zone.gz").write_bytes(
    gzip.compress((args.runs[-1] / "gpu.zone").read_bytes(), mtime=0)
)
print(f"Published {len(reports)} verified runs to {args.destination}")
