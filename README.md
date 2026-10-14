# I fixed DNSSEC by adding an NVIDIA dependency.

A working CUDA RSA/SHA-256 DNSSEC signer and a CPU comparison.

**[The unnecessarily accelerated website](https://dnssec.shitposting.cloud)**

The program generates a test zone, signs every RRset on both backends, compares every signature across every trial, and requires byte-identical signed zone files. Python cryptography, dnspython, and BIND independently check the output. The page also lets your browser verify a real signature from the recorded run.

Recorded on an EC2 g6.xlarge (4 vCPUs + NVIDIA L4): **32,774 RRsets, 19.99 s CPU vs 11.35 s GPU**, a **1.76× end-to-end speedup**. Signing alone: **46.88×**. These are medians of five trials; see the raw [report](web/data/report.json) and [batch series](web/data/series.json). The security caveat below matters.

This is an offline zone-signing experiment. It is not a BIND patch, a recursive resolver, or a faster DNS query path. The website serves recorded results and runs signature verification locally; there is no GPU behind each page view.

## Run it

Requirements: Linux, Python 3.11+, a CUDA-capable NVIDIA GPU, its driver, CUDA toolkit (`nvcc`), OpenSSL 3 development headers, GMP headers, OpenMP, and BIND utilities. Tested on Ubuntu 24.04 with CUDA 13.2 and an NVIDIA L4. The default build targets `sm_89`; set `CUDA_ARCH` for another GPU, e.g. `sm_75` for T4. Set `CUDA_PATH` if the toolkit is not at `/usr/local/cuda`.

```sh
sudo apt-get update
sudo apt-get install -y git build-essential libssl-dev libgmp-dev bind9-utils python3-venv
# Install the NVIDIA driver and CUDA toolkit separately, or use a CUDA image.
git clone https://github.com/pipeline-of-regret/dnssec-gpu
cd dnssec-gpu
./scripts/reproduce.sh --records 16384 --repeats 5 --threads 4
```

The script does not provision cloud resources. It builds the native library, installs the Python package, then runs the benchmark. `uv sync --frozen` can be used instead of pip for the committed Python dependency lock.

Outputs go to `artifacts/run/`: unsigned zone, CPU and GPU signed zones, all timings in `report.json`, BIND verification output, and a browser-verifiable example in `sample.json`. The private key is ephemeral and is never written to these files. Each new run generates a fresh key; output hashes therefore differ between runs.

For the batch-size series used on the website:

```sh
for n in 256 4096 16384; do
  .venv/bin/python dnssec_gpu.py --records "$n" --repeats 5 --threads 4 --output "artifacts/run-$n"
done
```

## What runs where

Both backends receive the same canonical DNSSEC SHA-256 digests and produce standard algorithm 8, RSA-2048 PKCS#1 v1.5 signatures.

* CPU: parallel OpenSSL EVP signing, using every requested CPU thread.
* GPU: host padding and CRT reduction, two 1024-bit modular exponentiations per signature on CUDA, then host CRT recombination. NVIDIA CGBN supplies cooperative big-integer arithmetic. This is actual private-key exponentiation on the GPU.

The generated `gpu.test.` zone includes SOA, NS, A, DNSKEY, and a complete NSEC chain. One combined signing key signs everything. BIND verification uses `dnssec-verify -z -o gpu.test. gpu.zone`; `-z` tells BIND all records are signed by the KSK. The key is not delegated from any public parent. A successful check establishes internal signature/NSEC consistency, not a public chain of trust.

## Measurement

Each backend runs five trials, alternating order. The primary measurement includes reading the unsigned zone, canonicalizing and hashing RRsets, signing, assembling signatures, and writing the signed zone. Both paths use the same Python processing and file output. Signing timings include GPU input preparation, transfers, allocation when needed, synchronization, and host recombination. CUDA startup is measured separately and excluded from steady-state results. Key generation and independent verification are also excluded.

All signatures are checked against the first trial; the first CPU and GPU outputs are also independently verified record by record. The final files must match byte for byte and BIND must accept the completed zone before a report is written. There is no CPU fallback if CUDA fails. CI checks zone construction and rejection of damaged signatures without a GPU; it does not claim to exercise CUDA.

Recorded measurements, the signed zone and verification log are under `web/data/`. The headline compares the CPU and GPU on the same g6.xlarge (4 vCPUs plus one L4), not machines with equal acquisition cost, nor the fastest possible CPU implementation. Only RSA-2048 is implemented; nothing here establishes an ECDSA or Ed25519 speedup. Small batches can have different tradeoffs.

## Security limits

**Do not use this to sign a production zone or with valuable keys.** The GPU implementation uses variable-time CGBN arithmetic and lacks RSA blinding. OpenSSL's CPU path retains its protections. The comparison is not between equally hardened signers, and the prototype has not had a cryptographic security review. There is no HSM, key lifecycle management, fault-hardening, or operational signing service.

Archived DNSSEC signatures expire 30 days after the run. Browser verification checks the saved RSA signature over saved canonical bytes, without asserting current DNSSEC validity. BIND verification was performed at the recorded time. `report.json` includes inception, expiration and verification time.

To refresh the site from completed runs:

```sh
python3 scripts/publish-results.py artifacts/run-256 artifacts/run-4096 artifacts/run-16384
```

## Tests and website

```sh
uv run python -m unittest discover -s tests -v
python3 -m http.server 8080 --directory web
```

WebCrypto requires HTTPS or localhost. The page has no third-party scripts, fonts, analytics, or API calls. Cloudflare Workers Static Assets hosts it. To deploy a fork, change the account/domain in `wrangler.jsonc`, authenticate Wrangler, then `npm ci && npm run deploy`.

## Credits

CUDA modular exponentiation is adapted from NVIDIA's [CGBN sample_03_powm](https://github.com/NVlabs/CGBN/tree/114601b07ae8c3e4d46b250208ea8d9def7a12f0/samples/sample_03_powm), pinned at `114601b07ae8c3e4d46b250208ea8d9def7a12f0`. Its MIT license is retained in `native/powm.cuh` and `native/CGBN-LICENSE`.

The joke followed [this CircleID article](https://circleid.com/posts/common-beliefs-about-dnssec-put-to-the-test-an-invitation-to-fact-check-your-assumptions) and Thomas H. Ptáček's response. Neither endorses this project. [GPU work on DNSSEC existed in 2016](https://ant.isi.edu/events/dinr2016/P/p61.pdf); novelty is not the claim.

Built by Corey Quinn with AI assistance. MIT licensed.
