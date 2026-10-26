#!/usr/bin/env bash
# Builds FreeHSM from the vendor/freehsm submodule and copies the built libfreehsm.so into the test
# output directory.
#
# Usage: build-freehsm.sh <test-output-dir>
#
# Outputs (relative to <test-output-dir>):
#   runtimes/<rid>/native/libfreehsm.so
#
# Idempotent: skips the rebuild when the staged output was built from this submodule commit by this
# script (see is_built_from).
#
# Requires OpenSSL 3.5 (OPENSSL_PREFIX, as the OpenSSL 3.5 CI step and the other native backends use):
# the module's power-on known-answer tests include ML-KEM, ML-DSA and SLH-DSA. Linux only for now:
# FreeHSM's Makefile and boot integrity self-test are ELF-specific.

set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_args 1 "<test-output-dir>" "$@"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "build-freehsm.sh: FreeHSM is wired up on Linux only (got $(uname -s)); nothing to do." >&2
  exit 0
fi

OUT_BASE="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/vendor/freehsm"
# Built out of tree: `make generate` rewrites the committed dispatch sources for the chosen profile,
# which would leave the submodule dirty.
BUILD_DIR="${REPO_ROOT}/obj/freehsm"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-/usr/local/ssl}"

require_submodule "${SRC_DIR}/Makefile" freehsm

RID="$(host_rid)"

DEST_DIR="${OUT_BASE}/runtimes/${RID}/native"
DEST_LIB="${DEST_DIR}/libfreehsm.so"

mkdir -p "${DEST_DIR}"

STAMP_FILE="${DEST_LIB}.built-from"
STAMP="$(build_stamp "${SRC_DIR}")"
if is_built_from "${STAMP_FILE}" "${STAMP}" "${DEST_LIB}"; then
  echo "freehsm up to date at ${DEST_LIB}"
  exit 0
fi
rm -f "${STAMP_FILE}"

# The build directory carries its own stamp, so a restored CI cache of it only needs staging.
BUILD_LIB="${BUILD_DIR}/libfreehsm.so"
BUILD_STAMP_FILE="${BUILD_LIB}.built-from"
if ! is_built_from "${BUILD_STAMP_FILE}" "${STAMP}" "${BUILD_LIB}"; then
  echo "Building FreeHSM for ${RID} against ${OPENSSL_PREFIX}..."
  rm -rf "${BUILD_DIR}"
  mkdir -p "${BUILD_DIR}"
  git -C "${SRC_DIR}" archive --format=tar HEAD | tar -x -C "${BUILD_DIR}"

  # all-mechanisms: the non-approved mechanisms (RSA PKCS#1 v1.5, SHA-1, X25519, ...) are dispatched
  # too, so the suite covers them; the fixture runs the module in its permissive mode.
  #
  # `make integrity` is upstream's signing step: scripts/sign_module.sh patches the SHA-384 of the
  # library into its .fhsm_digest section, which the boot integrity self-test verifies.
  (
    cd "${BUILD_DIR}"
    make PROFILE=all-mechanisms generate
    make -j"$(nproc)" PROFILE=all-mechanisms OPENSSL_PREFIX="${OPENSSL_PREFIX}" libfreehsm.so
    make PROFILE=all-mechanisms OPENSSL_PREFIX="${OPENSSL_PREFIX}" integrity
  ) 2>&1

  if [[ ! -f "${BUILD_LIB}" ]]; then
    echo "build succeeded but ${BUILD_LIB} not found" >&2; exit 1
  fi
  record_build "${BUILD_STAMP_FILE}" "${STAMP}"
fi

cp "${BUILD_LIB}" "${DEST_LIB}"
record_build "${STAMP_FILE}" "${STAMP}"
echo "Installed ${DEST_LIB}"
