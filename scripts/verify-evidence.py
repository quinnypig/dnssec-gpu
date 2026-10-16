"""Check retained GPU results on CPU, without asserting a new CUDA run."""

import argparse
import base64
import gzip
import hashlib
import json
import math
import re
import statistics
import subprocess
import sys
from pathlib import Path

import dns.dnssec
import dns.rdata
import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.zone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from evidence_contract import emit, recorded, require, verify_release

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = "dnssec-gpu"
UNOBSERVED = ("gpu-runtime", "bind-rerun")
FILES = {
    "web/data/report.json",
    "web/data/series.json",
    "web/data/sample.json",
    "web/data/gpu.zone.gz",
    "web/data/bind-verification.txt",
    "web/data/environment.txt",
}


def check_report(report):
    require(
        report["algorithm"] == "RSASHA256 (DNSSEC algorithm 8)"
        and report["key_bits"] == 2048,
        "unsupported algorithm claim",
    )
    require(
        all(
            report.get(key) is True
            for key in ("verified", "bind_verified", "byte_identical_zones")
        ),
        "missing recorded verification checks",
    )
    require(
        type(report["repeats"]) is int and report["repeats"] > 0, "invalid trial count"
    )
    for backend in ("cpu", "gpu"):
        for phase in ("total", "prepare", "sign", "write"):
            summary = report["runs"][backend][phase]
            samples = summary["samples_seconds"]
            require(
                len(samples) == report["repeats"]
                and all(
                    type(v) in (int, float) and math.isfinite(v) and v > 0
                    for v in samples
                ),
                "missing or invalid timing trials",
            )
            require(
                math.isclose(
                    statistics.median(samples), summary["median_seconds"], rel_tol=1e-12
                )
                and min(samples) == summary["min_seconds"],
                "timing summary disagrees with recorded samples",
            )
    for phase in ("total", "sign"):
        ratio = (
            report["runs"]["cpu"][phase]["median_seconds"]
            / report["runs"]["gpu"][phase]["median_seconds"]
        )
        require(
            math.isclose(report["speedup_" + phase], ratio, rel_tol=1e-12),
            "unsupported speedup claim",
        )
    require(
        report["inception"] <= report["verification_time"] <= report["expiration"],
        "recorded verification time outside signature validity",
    )


def check_sample(sample, report):
    key = serialization.load_der_public_key(
        base64.b64decode(sample["public_key_spki_base64"], validate=True)
    )
    data = base64.b64decode(sample["canonical_base64"], validate=True)
    signature = base64.b64decode(sample["signature_base64"], validate=True)
    key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    name, ttl, rdclass, kind, value = sample["rrset"].split(maxsplit=4)
    rrset = dns.rrset.from_text(name, int(ttl), rdclass, kind, value)
    rrsig = dns.rdata.from_text("IN", "RRSIG", sample["rrsig"])
    require(signature == rrsig.signature, "sample signature disagrees with RRSIG")
    canonical = dns.dnssec._make_rrsig_signature_data(
        rrset, rrsig, dns.name.from_text("gpu.test.")
    )
    require(canonical == data, "independent canonicalization disagreement")
    dnskey = dns.rdata.from_text("IN", "DNSKEY", report["public_dnskey"])
    require(
        dns.dnssec.make_dnskey(key, "RSASHA256", flags=257).to_wire()
        == dnskey.to_wire(),
        "sample key disagrees with report",
    )


def check_zone(data, report):
    require(
        hashlib.sha256(data).hexdigest() == report["zone_sha256"],
        "signed zone checksum mismatch",
    )
    origin = dns.name.from_text("gpu.test.")
    zone = dns.zone.from_text(data.decode(), origin=origin, relativize=False)
    dnskey = dns.rdata.from_text("IN", "DNSKEY", report["public_dnskey"])
    require(
        dnskey in zone.get_rdataset(origin, "DNSKEY"),
        "zone DNSKEY disagrees with report",
    )
    keys = {origin: dns.rrset.from_rdata(origin, 300, dnskey)}
    count = 0
    for name, node in zone.nodes.items():
        for rdataset in node.rdatasets:
            if rdataset.rdtype == dns.rdatatype.RRSIG:
                continue
            rrset = dns.rrset.RRset(name, rdataset.rdclass, rdataset.rdtype)
            rrset.update(rdataset)
            signatures = zone.get_rdataset(name, "RRSIG", rdataset.rdtype)
            require(signatures is not None, "missing signed RRset")
            dns.dnssec.validate(
                rrset, (name, signatures), keys, now=report["verification_time"]
            )
            count += 1
    require(
        count == report["rrsets_signed"] == 2 * report["input_a_records"] + 6,
        "RRset count disagrees with signed output",
    )


def validate(root, record):
    require(
        set(record["artifacts"]) == FILES, "unsupported or missing historical evidence"
    )
    report = json.loads((root / "web/data/report.json").read_text())
    series = json.loads((root / "web/data/series.json").read_text())
    require(
        series and series[-1] == report,
        "headline report disagrees with recorded series",
    )
    for item in series:
        check_report(item)
    sample = json.loads((root / "web/data/sample.json").read_text())
    check_sample(sample, report)
    check_zone(gzip.decompress((root / "web/data/gpu.zone.gz").read_bytes()), report)
    require(
        "Zone fully signed:" in (root / "web/data/bind-verification.txt").read_text(),
        "missing historical BIND record",
    )
    claims = {
        "rrsets_signed": report["rrsets_signed"],
        "cpu_seconds": round(report["runs"]["cpu"]["total"]["median_seconds"], 2),
        "gpu_seconds": round(report["runs"]["gpu"]["total"]["median_seconds"], 2),
        "speedup_total": round(report["speedup_total"], 2),
        "speedup_sign": round(report["speedup_sign"], 2),
    }
    require(
        record["claims"] == claims,
        "unsupported claim or claim disagrees with retained result",
    )
    headline = re.search(
        r"([\d,]+) RRsets, ([\d.]+) s CPU vs ([\d.]+) s GPU.*?([\d.]+)× end-to-end speedup.*?Signing alone: ([\d.]+)×",
        (root / "README.md").read_text().replace("**", ""),
        re.DOTALL,
    )
    require(
        headline is not None
        and (int(headline[1].replace(",", "")), *map(float, headline.groups()[1:]))
        == tuple(claims.values()),
        "README headline claim is not supported by recorded results",
    )


def cpu_checks():
    subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
        check=True,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--write-release", type=Path)
    actions.add_argument("--verify-release", type=Path)
    args = parser.parse_args()
    if args.write_release:
        emit(ROOT, args.write_release, COMPONENT, UNOBSERVED, validate, cpu_checks)
    elif args.verify_release:
        verify_release(ROOT, args.verify_release, COMPONENT, UNOBSERVED, validate)
    else:
        validate(ROOT, recorded(ROOT))
        print(
            "Retained timing claims and signatures pass CPU checks. GPU and BIND were not rerun; historical source revision is unknown."
        )
