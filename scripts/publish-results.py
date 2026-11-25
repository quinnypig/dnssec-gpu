"""Copy independently verified local benchmark artifacts into the static site."""

import argparse
import gzip
import hashlib
import json
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
# Read and prepare the entire bundle before touching previously published files.
# A missing sample or verification log must not leave a new report beside old data.
artifacts = {
    name: (args.runs[-1] / name).read_bytes()
    for name in ("report.json", "sample.json", "bind-verification.txt")
}
artifacts["series.json"] = (json.dumps(reports, indent=2) + "\n").encode()
artifacts["gpu.zone.gz"] = gzip.compress(
    (args.runs[-1] / "gpu.zone").read_bytes(), mtime=0
)
args.destination.mkdir(parents=True, exist_ok=True)
for name, data in artifacts.items():
    (args.destination / name).write_bytes(data)
print(f"Published {len(reports)} verified runs to {args.destination}")
