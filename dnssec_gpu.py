"""Reproducible RSA/SHA-256 DNSSEC signing experiment."""

import argparse
import base64
import ctypes
import datetime
import hashlib
import json
import os
import platform
import statistics
import subprocess
import time
from pathlib import Path

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdatatype
import dns.rrset
import dns.zone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

ORIGIN = dns.name.from_text("gpu.test.")


class Signer:
    """Native backends accept identical SHA-256 digests and return wire signatures."""

    def __init__(self, key, library="build/libsigner.so"):
        self.lib = ctypes.CDLL(str(Path(library).resolve()))
        self.lib.signer_open.argtypes = [ctypes.c_char_p]
        self.lib.signer_open.restype = ctypes.c_void_p
        self.lib.signer_close.argtypes = [ctypes.c_void_p]
        self.lib.signer_error.argtypes = [ctypes.c_void_p]
        self.lib.signer_error.restype = ctypes.c_char_p
        for name in ("signer_cpu", "signer_gpu"):
            fn = getattr(self.lib, name)
            fn.argtypes = [
                ctypes.c_void_p,
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.c_void_p,
                ctypes.c_int,
            ]
            fn.restype = ctypes.c_int
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.handle = self.lib.signer_open(pem)
        if not self.handle:
            raise RuntimeError("Cannot load RSA-2048 private key")

    def sign(self, digests, backend, threads):
        if backend not in ("cpu", "gpu") or not digests or len(digests) % 32:
            raise ValueError("Invalid signing input")
        out = ctypes.create_string_buffer(len(digests) // 32 * 256)
        rc = getattr(self.lib, "signer_" + backend)(
            self.handle, digests, len(digests) // 32, out, threads
        )
        if rc:
            raise RuntimeError(self.lib.signer_error(self.handle).decode())
        return out.raw

    def close(self):
        if self.handle:
            self.lib.signer_close(self.handle)
            self.handle = None


def make_zone(records, key):
    if records < 1:
        raise ValueError("records must be positive")
    text = "$ORIGIN gpu.test.\n$TTL 300\n@ IN SOA ns.gpu.test. hostmaster.gpu.test. 1 3600 600 86400 300\n@ IN NS ns.gpu.test.\nns IN A 192.0.2.53\n"
    text += "".join(f"host{i:07d} IN A 192.0.2.{i % 254 + 1}\n" for i in range(records))
    zone = dns.zone.from_text(text, origin=ORIGIN, relativize=False)
    dnskey = dns.dnssec.make_dnskey(key.public_key(), 8, flags=257)
    zone.replace_rdataset(ORIGIN, dns.rrset.from_rdata(ORIGIN, 300, dnskey))
    names = sorted(zone.nodes)
    for i, name in enumerate(names):
        types = {dns.rdatatype.to_text(r.rdtype) for r in zone[name].rdatasets} | {
            "NSEC",
            "RRSIG",
        }
        nsec = dns.rdata.from_text(
            "IN",
            "NSEC",
            str(names[(i + 1) % len(names)]) + " " + " ".join(sorted(types)),
        )
        zone.replace_rdataset(name, dns.rrset.from_rdata(name, 300, nsec))
    return zone, dnskey


def prepare(zone, dnskey, inception, expiration):
    jobs = []
    digests = []
    for name, node in sorted(zone.nodes.items()):
        for rdataset in sorted(node.rdatasets, key=lambda r: r.rdtype):
            if rdataset.rdtype == dns.rdatatype.RRSIG:
                continue
            rrset = dns.rrset.RRset(name, rdataset.rdclass, rdataset.rdtype)
            rrset.update(rdataset)
            sig = dns.rdata.from_text(
                "IN",
                "RRSIG",
                f"{dns.rdatatype.to_text(rrset.rdtype)} 8 {len(name.labels) - 1} {rrset.ttl} {expiration} {inception} {dns.dnssec.key_id(dnskey)} gpu.test. AA==",
            )
            payload = dns.dnssec._make_rrsig_signature_data(rrset, sig, ORIGIN)
            digests.append(hashlib.sha256(payload).digest())
            jobs.append((rrset, sig))
    return jobs, b"".join(digests)


def assemble(zone, jobs, signatures):
    if len(signatures) != 256 * len(jobs):
        raise ValueError("Wrong number of signatures")
    for i, (rrset, template) in enumerate(jobs):
        sig = template.replace(signature=signatures[i * 256 : (i + 1) * 256])
        zone.replace_rdataset(
            rrset.name, dns.rrset.from_rdata(rrset.name, rrset.ttl, sig)
        )
    return zone


def verify(zone, dnskey, jobs, signatures, digests, key, now):
    keys = {ORIGIN: dns.rrset.from_rdata(ORIGIN, 300, dnskey)}
    for i, (rrset, _) in enumerate(jobs):
        key.public_key().verify(
            signatures[i * 256 : (i + 1) * 256],
            digests[i * 32 : (i + 1) * 32],
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256()),
        )
        sigs = zone.get_rdataset(rrset.name, "RRSIG", rrset.rdtype)
        dns.dnssec.validate(rrset, (rrset.name, sigs), keys, now=now)


def summary(samples):
    return {
        "samples_seconds": samples,
        "median_seconds": statistics.median(samples),
        "min_seconds": min(samples),
    }


def benchmark(args):
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    inception = now - 3600
    expiration = now + 30 * 86400
    zone, dnskey = make_zone(args.records, key)
    unsigned = out / "unsigned.zone"
    zone.to_file(str(unsigned), relativize=False)
    signer = Signer(key, args.library)
    report = {
        "created_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "algorithm": "RSASHA256 (DNSSEC algorithm 8)",
        "key_bits": 2048,
        "input_a_records": args.records,
        "threads": args.threads,
        "repeats": args.repeats,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "gpu": subprocess.check_output(
            [
                "nvidia-smi",
                "--query-gpu=name,driver_version,memory.total",
                "--format=csv,noheader",
            ],
            text=True,
        ).strip(),
        "openssl": subprocess.check_output(["openssl", "version"], text=True).strip(),
        "inception": inception,
        "expiration": expiration,
        "verification_time": now,
        "runs": {},
        "timing": "Full pipeline reads unsigned zone, canonicalizes RRsets, hashes, signs and writes signed zone. Key generation, library load, warmup and independent verification excluded. Signing time includes CPU preparation, CUDA allocation when needed, transfers, synchronization and CRT recombination.",
        "security_limit": "GPU prototype uses variable-time CGBN arithmetic without RSA blinding; CPU uses OpenSSL protections. Not a production signer.",
    }
    try:
        t = time.perf_counter()
        signer.sign(hashlib.sha256(b"warmup").digest(), "gpu", args.threads)
        report["cuda_initialization_seconds"] = time.perf_counter() - t
        for backend in ("cpu", "gpu"):
            signer.sign(hashlib.sha256(b"warmup").digest(), backend, args.threads)
        measured = {
            b: {"total": [], "prepare": [], "sign": [], "write": []}
            for b in ("cpu", "gpu")
        }
        signatures_by_backend = {}
        expected_signatures = None
        # Alternate order to reduce systematic warm-cache / clock bias.
        for trial in range(args.repeats):
            for backend in ("cpu", "gpu") if trial % 2 == 0 else ("gpu", "cpu"):
                started = time.perf_counter()
                z = dns.zone.from_file(str(unsigned), origin=ORIGIN, relativize=False)
                jobs, digests = prepare(z, dnskey, inception, expiration)
                prepared = time.perf_counter()
                signatures = signer.sign(digests, backend, args.threads)
                signed = time.perf_counter()
                assemble(z, jobs, signatures)
                z.to_file(str(out / f"{backend}.zone"), relativize=False)
                written = time.perf_counter()
                m = measured[backend]
                for label, value in [
                    ("total", written - started),
                    ("prepare", prepared - started),
                    ("sign", signed - prepared),
                    ("write", written - signed),
                ]:
                    m[label].append(value)
                if expected_signatures is None:
                    expected_signatures = signatures
                if signatures != expected_signatures:
                    raise RuntimeError("Signature mismatch across backends or trials")
                signatures_by_backend[backend] = signatures
                if trial == 0:
                    verify(z, dnskey, jobs, signatures, digests, key, now)
                print(
                    f"{backend} trial {trial + 1}: total={written - started:.3f}s sign={signed - prepared:.3f}s",
                    flush=True,
                )
        if signatures_by_backend["cpu"] != signatures_by_backend["gpu"]:
            raise RuntimeError("Final signature mismatch")
        if (out / "cpu.zone").read_bytes() != (out / "gpu.zone").read_bytes():
            raise RuntimeError("Signed zone files differ")
        report["rrsets_signed"] = len(jobs)
        report["runs"] = {
            b: {k: summary(v) for k, v in phases.items()}
            for b, phases in measured.items()
        }
        report["speedup_total"] = (
            report["runs"]["cpu"]["total"]["median_seconds"]
            / report["runs"]["gpu"]["total"]["median_seconds"]
        )
        report["speedup_sign"] = (
            report["runs"]["cpu"]["sign"]["median_seconds"]
            / report["runs"]["gpu"]["sign"]["median_seconds"]
        )
        report["byte_identical_zones"] = True
        # BIND is a separate implementation and checks the full NSEC chain too.
        check = subprocess.run(
            ["dnssec-verify", "-z", "-o", str(ORIGIN), str(out / "gpu.zone")],
            text=True,
            capture_output=True,
            check=False,
        )
        (out / "bind-verification.txt").write_text(check.stdout + check.stderr)
        if check.returncode:
            raise RuntimeError(check.stdout + check.stderr)
        report["bind_verified"] = True
        report["verified"] = True
        report["zone_sha256"] = hashlib.sha256(
            (out / "gpu.zone").read_bytes()
        ).hexdigest()
        report["public_dnskey"] = dnskey.to_text()
        # One real RRset, for an independent browser WebCrypto check.
        rrset, template = jobs[0]
        sample = {
            "rrset": rrset.to_text(),
            "rrsig": template.replace(signature=signatures[:256]).to_text(),
            "canonical_base64": base64.b64encode(
                dns.dnssec._make_rrsig_signature_data(rrset, template, ORIGIN)
            ).decode(),
            "signature_base64": base64.b64encode(signatures[:256]).decode(),
            "public_key_spki_base64": base64.b64encode(
                key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).decode(),
        }
        (out / "sample.json").write_text(json.dumps(sample, indent=2) + "\n")
        (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(
            json.dumps(
                {
                    "speedup_total": report["speedup_total"],
                    "speedup_sign": report["speedup_sign"],
                    "verified": True,
                },
                indent=2,
            )
        )
    finally:
        signer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, default=16384)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--threads", type=int, default=len(os.sched_getaffinity(0)))
    parser.add_argument("--library", default="build/libsigner.so")
    parser.add_argument("--output", type=Path, default=Path("artifacts/run"))
    args = parser.parse_args()
    if min(args.records, args.repeats, args.threads) < 1:
        parser.error("counts must be positive")
    benchmark(args)


if __name__ == "__main__":
    main()
