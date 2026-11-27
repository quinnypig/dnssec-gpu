import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature

from dnssec_gpu import (
    assemble,
    benchmark,
    hashes,
    make_zone,
    padding,
    prepare,
    rsa,
    utils,
    verify,
)


class ZoneTests(unittest.TestCase):
    def test_signed_zone_and_tamper(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        zone, dnskey = make_zone(8, key)
        now = int(time.time())
        jobs, digests = prepare(zone, dnskey, now - 60, now + 3600)
        signatures = b"".join(
            key.sign(
                digests[i : i + 32],
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )
            for i in range(0, len(digests), 32)
        )
        assemble(zone, jobs, signatures)
        verify(zone, dnskey, jobs, signatures, digests, key, now)
        changed = bytes([signatures[0] ^ 1]) + signatures[1:]
        with self.assertRaises(InvalidSignature):
            verify(zone, dnskey, jobs, changed, digests, key, now)
        self.assertEqual(len(jobs), 22)

    def test_reject_empty_zone(self):
        with self.assertRaises(ValueError):
            make_zone(0, None)

    def test_existing_run_survives_failed_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            output.mkdir()
            previous = {
                "unsigned.zone": b"previous unsigned zone\n",
                "gpu.zone": b"previous signed zone\n",
                "report.json": b'{"verified": true}\n',
            }
            for name, data in previous.items():
                (output / name).write_bytes(data)
            args = SimpleNamespace(output=output, records=1, library="unused")
            with (
                patch("dnssec_gpu.Signer", side_effect=RuntimeError("CUDA unavailable")) as signer,
                self.assertRaises(FileExistsError),
            ):
                benchmark(args)
            signer.assert_not_called()
            self.assertEqual(
                {name: (output / name).read_bytes() for name in previous}, previous
            )
