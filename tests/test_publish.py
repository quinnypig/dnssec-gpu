import gzip
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PUBLISH = Path(__file__).resolve().parents[1] / "scripts/publish-results.py"


class PublishTests(unittest.TestCase):
    def make_run(self, root):
        run = root / "run"
        run.mkdir()
        zone = b"synthetic zone fixture\n"
        (run / "gpu.zone").write_bytes(zone)
        report = {
            "verified": True,
            "bind_verified": True,
            "byte_identical_zones": True,
            "zone_sha256": hashlib.sha256(zone).hexdigest(),
        }
        (run / "report.json").write_text(json.dumps(report) + "\n")
        (run / "sample.json").write_text('{"fixture": true}\n')
        (run / "bind-verification.txt").write_text("fixture verification log\n")
        return run, report, zone

    def publish(self, run, destination):
        return subprocess.run(
            [sys.executable, str(PUBLISH), str(run), "--destination", str(destination)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_missing_input_leaves_published_bundle_unchanged(self):
        for missing in ("sample.json", "bind-verification.txt"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, _, _ = self.make_run(root)
                (run / missing).unlink()
                destination = root / "published"
                destination.mkdir()
                previous = {
                    name: ("previous " + name).encode()
                    for name in (
                        "report.json", "sample.json", "bind-verification.txt",
                        "series.json", "gpu.zone.gz",
                    )
                }
                for name, data in previous.items():
                    (destination / name).write_bytes(data)
                result = self.publish(run, destination)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(missing, result.stderr)
                self.assertEqual(
                    {path.name: path.read_bytes() for path in destination.iterdir()},
                    previous,
                )

    def test_complete_run_publishes_matching_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, report, zone = self.make_run(root)
            destination = root / "published"
            result = self.publish(run, destination)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("report.json", "sample.json", "bind-verification.txt"):
                self.assertEqual((destination / name).read_bytes(), (run / name).read_bytes())
            self.assertEqual(json.loads((destination / "series.json").read_text()), [report])
            self.assertEqual(gzip.decompress((destination / "gpu.zone.gz").read_bytes()), zone)
