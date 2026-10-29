#!/usr/bin/env bash
# Builds Craton HSM (craton-hsm-core) from the vendor/craton-hsm-core submodule and copies the built
# libcraton_hsm.so into the test output directory.
#
# Usage: build-craton-hsm.sh <test-output-dir>
#
# Outputs (relative to <test-output-dir>):
#   runtimes/<rid>/native/libcraton_hsm.so
#
# Idempotent: skips the rebuild when the staged output was built from this submodule commit by this
# script (see is_built_from).
#
# Linux only for now, like Kryoptic: Craton HSM is pure Rust and cross-platform, but this backend is
# wired into CI on the ubuntu-latest leg only (see ci.yml).

set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_args 1 "<test-output-dir>" "$@"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "build-craton-hsm.sh: Craton HSM is wired up on Linux only for now (got $(uname -s)); nothing to do." >&2
  exit 0
fi

OUT_BASE="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/vendor/craton-hsm-core"

require_submodule "${SRC_DIR}/Cargo.toml" craton-hsm-core

RID="$(host_rid)"

DEST_DIR="${OUT_BASE}/runtimes/${RID}/native"
DEST_LIB="${DEST_DIR}/libcraton_hsm.so"

mkdir -p "${DEST_DIR}"

STAMP_FILE="${DEST_LIB}.built-from"
STAMP="$(build_stamp "${SRC_DIR}")"
if is_built_from "${STAMP_FILE}" "${STAMP}" "${DEST_LIB}"; then
  echo "craton-hsm up to date at ${DEST_LIB}"
  exit 0
fi
rm -f "${STAMP_FILE}"

echo "Building Craton HSM for ${RID}..."

# Only the library crate (the cdylib), not the daemon or admin tool workspace members. The default
# RustCrypto backend needs no C toolchain or OpenSSL. Its release build refuses RSA private-key
# operations (signing, decryption, key-pair generation) because of the Marvin timing attack in the
# `rsa` crate (RUSTSEC-2023-0071); `insecure-rustcrypto-rsa-private-ops` is the development-only
# switch upstream provides for interoperability tests like these, so the RSA test cases run instead
# of skipping. Never ship this build as an HSM.
(
  cd "${SRC_DIR}"
  cargo build --release --lib --features insecure-rustcrypto-rsa-private-ops
) 2>&1

SRC_LIB="${SRC_DIR}/target/release/libcraton_hsm.so"
if [[ ! -f "${SRC_LIB}" ]]; then
  echo "build succeeded but ${SRC_LIB} not found" >&2; exit 1
fi

cp "${SRC_LIB}" "${DEST_LIB}"
record_build "${STAMP_FILE}" "${STAMP}"
echo "Installed ${DEST_LIB}"
