import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from evidence_contract import check_receipt, digest, recorded

spec = importlib.util.spec_from_file_location(
    "experiment_verifier", ROOT / "scripts/verify-evidence.py"
)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class EvidenceContractTests(unittest.TestCase):
    def receipt(self):
        manifest = {
            "schema_version": 1,
            "source_revision": "fixture-source",
            "toolchain": {"python": "fixture"},
            "artifacts": {},
        }
        checks = [
            {"id": id, "result": "passed"}
            for id in (
                "recorded-artifact-integrity",
                "recorded-claims",
                "cpu-correctness",
            )
        ]
        checks.extend(
            {"id": id, "result": "not-observed"} for id in verifier.UNOBSERVED
        )
        release = {
            "schema_version": 1,
            "component_id": verifier.COMPONENT,
            "source_revision": "fixture-source",
            "artifact": {"uri": "local:inputs.json", "digest": "sha256:" + "a" * 64},
            "toolchain": manifest["toolchain"],
            "verification": {
                "policy_version": "experiment-evidence-v1",
                "checks": checks,
            },
            "deployment": {
                "desired_revision": "fixture-source",
                "observed_revision": None,
                "verified_at": None,
                "result": "not-observed",
            },
        }
        return release, manifest

    def check(self, receipt, manifest):
        check_receipt(
            receipt, manifest, verifier.COMPONENT, "fixture-source", verifier.UNOBSERVED
        )

    def test_unknown_version_and_missing_required_checks_rejected(self):
        receipt, manifest = self.receipt()
        self.check(receipt, manifest)
        bad = copy.deepcopy(receipt)
        bad["schema_version"] = 2
        with self.assertRaises(ValueError):
            self.check(bad, manifest)
        bad = copy.deepcopy(receipt)
        bad["verification"]["checks"].pop(0)
        with self.assertRaisesRegex(ValueError, "required checks"):
            self.check(bad, manifest)

    def test_cpu_success_cannot_promote_runtime_or_deployment(self):
        receipt, manifest = self.receipt()
        receipt["verification"]["checks"][-1]["result"] = "passed"
        with self.assertRaisesRegex(ValueError, "unsupported result"):
            self.check(receipt, manifest)
        receipt, manifest = self.receipt()
        receipt["deployment"]["result"] = "verified"
        with self.assertRaisesRegex(ValueError, "deployment"):
            self.check(receipt, manifest)

    def test_wrong_source_and_toolchain_rejected(self):
        receipt, manifest = self.receipt()
        manifest["source_revision"] = "different"
        with self.assertRaisesRegex(ValueError, "binding"):
            self.check(receipt, manifest)
        receipt, manifest = self.receipt()
        manifest["toolchain"] = {"python": "different"}
        with self.assertRaisesRegex(ValueError, "binding"):
            self.check(receipt, manifest)

    def test_corrupted_and_missing_retained_artifact_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".fleet").mkdir()
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"correct")
            record = {
                "schema_version": 1,
                "historical_source_revision": None,
                "provenance": "historical-run-source-not-recorded",
                "artifacts": {"artifact.bin": digest(artifact)},
                "claims": {},
            }
            (root / ".fleet/recorded-results.json").write_text(json.dumps(record))
            recorded(root)
            artifact.write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError, "checksum"):
                recorded(root)
            artifact.unlink()
            with self.assertRaisesRegex(ValueError, "missing"):
                recorded(root)

    def test_claims_require_exact_supported_fields_and_retained_values(self):
        record = recorded(ROOT)
        record["claims"]["unsupported-performance"] = 999
        with self.assertRaisesRegex(ValueError, "unsupported claim"):
            verifier.validate(ROOT, record)
        record = recorded(ROOT)
        record["artifacts"].pop(next(iter(record["artifacts"])))
        with self.assertRaisesRegex(ValueError, "missing historical"):
            verifier.validate(ROOT, record)


class RecordedDNSSECTests(unittest.TestCase):
    def test_incorrect_timing_summary_and_missing_trials_rejected(self):
        report = json.loads((ROOT / "web/data/report.json").read_text())
        report["speedup_total"] += 1
        with self.assertRaisesRegex(ValueError, "speedup claim"):
            verifier.check_report(report)
        report = json.loads((ROOT / "web/data/report.json").read_text())
        report["runs"]["gpu"]["sign"]["samples_seconds"].pop()
        with self.assertRaisesRegex(ValueError, "timing trials"):
            verifier.check_report(report)

    def test_independent_signature_and_canonicalization_reject_disagreement(self):
        import base64

        from cryptography.exceptions import InvalidSignature

        report = json.loads((ROOT / "web/data/report.json").read_text())
        sample = json.loads((ROOT / "web/data/sample.json").read_text())
        bad = copy.deepcopy(sample)
        signature = base64.b64decode(bad["signature_base64"])
        bad["signature_base64"] = base64.b64encode(
            bytes([signature[0] ^ 1]) + signature[1:]
        ).decode()
        with self.assertRaises(InvalidSignature):
            verifier.check_sample(bad, report)
        sample["rrset"] = sample["rrset"].replace("ns.gpu.test.", "wrong.gpu.test.")
        with self.assertRaisesRegex(ValueError, "canonicalization disagreement"):
            verifier.check_sample(sample, report)
