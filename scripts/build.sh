#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
CGBN_REV=114601b07ae8c3e4d46b250208ea8d9def7a12f0
mkdir -p vendor build
if [ ! -d vendor/CGBN/.git ]; then git clone https://github.com/NVlabs/CGBN.git vendor/CGBN; fi
git -C vendor/CGBN checkout --detach "$CGBN_REV"
"${CUDA_PATH:-/usr/local/cuda}/bin/nvcc" -std=c++17 -O3 -arch="${CUDA_ARCH:-sm_89}" \
  -shared -Xcompiler=-fPIC,-fopenmp -Ivendor/CGBN/include native/signer.cu \
  -lcrypto -lgomp -o build/libsigner.so
