#!/usr/bin/env bash
# Compiles and runs the PKCS#11 ABI oracle (abi-probe.c) with this machine's C compiler and writes
# its output to <test-output-dir>/abi-oracle.txt, where AbiOracleTests read it.
#
# Usage: build-abi-probe.sh <test-output-dir>
#
# The probe must be built for the architecture the tests run as. On every Linux/macOS CI leg that
# is the host's native architecture, so the default compiler target is used.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <test-output-dir>" >&2
  exit 2
fi

OUT_DIR="$1"
BUILD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEADERS="${BUILD_DIR}/../vendor/pkcs11/published/3-02"
CC="${CC:-cc}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

if [[ ! -f "${HEADERS}/pkcs11.h" ]]; then
  echo "OASIS headers missing at ${HEADERS}." >&2
  echo "Run: git submodule update --init vendor/pkcs11" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
"${CC}" -std=c99 -Wall -Wextra -Werror -I "${HEADERS}" "${BUILD_DIR}/abi-probe.c" -o "${WORK}/abi-probe"
"${WORK}/abi-probe" > "${OUT_DIR}/abi-oracle.txt"
echo "Wrote ${OUT_DIR}/abi-oracle.txt ($(wc -l < "${OUT_DIR}/abi-oracle.txt") rows, ${CC} on $(uname -sm))"
