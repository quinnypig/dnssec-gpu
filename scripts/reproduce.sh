#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Install OS prerequisites first; see README. No cloud resources are created.
command -v dnssec-verify >/dev/null
command -v nvidia-smi >/dev/null
python3 -m venv .venv
.venv/bin/python -m pip install -e .
bash scripts/build.sh
.venv/bin/python dnssec_gpu.py "$@"
