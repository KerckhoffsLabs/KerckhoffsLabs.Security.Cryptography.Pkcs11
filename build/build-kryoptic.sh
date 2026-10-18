#!/usr/bin/env bash
# Builds Kryoptic from the vendor/kryoptic submodule and copies the built
# libkryoptic_pkcs11.so into the test output directory.
#
# Usage: build-kryoptic.sh <test-output-dir>
#
# Outputs (relative to <test-output-dir>):
#   runtimes/<rid>/native/libkryoptic_pkcs11.so
#
# Idempotent: skips the rebuild when the staged output was built from this submodule commit by this
# script (see is_built_from).
#
# Linux only for now: Kryoptic (Rust/cargo) is cross-platform in principle, but this
# backend is wired into CI on the ubuntu-latest leg only (see ci.yml) — matching how
# opencryptoki and NSS were introduced as additional real backends one leg at a time.

set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_args 1 "<test-output-dir>" "$@"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "build-kryoptic.sh: Kryoptic is wired up on Linux only for now (got $(uname -s)); nothing to do." >&2
  exit 0
fi

OUT_BASE="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/vendor/kryoptic"

require_submodule "${SRC_DIR}/Cargo.toml" kryoptic

RID="$(host_rid)"

DEST_DIR="${OUT_BASE}/runtimes/${RID}/native"
DEST_LIB="${DEST_DIR}/libkryoptic_pkcs11.so"

mkdir -p "${DEST_DIR}"

STAMP_FILE="${DEST_LIB}.built-from"
STAMP="$(build_stamp "${SRC_DIR}")"
if is_built_from "${STAMP_FILE}" "${STAMP}" "${DEST_LIB}"; then
  echo "kryoptic up to date at ${DEST_LIB}"
  exit 0
fi
rm -f "${STAMP_FILE}"

echo "Building Kryoptic for ${RID}..."

# Kryoptic's "standard" feature set requires OpenSSL >= 3.2.0 (EdDSA needs ossl/ossl320);
# "pqc" (ML-KEM/ML-DSA/SLH-DSA — the whole reason this backend exists) further
# requires OpenSSL >= 3.5.0 (ossl/ossl350). ubuntu-latest ships OpenSSL 3.0, so — exactly like
# SoftHSM and opencryptoki above — this needs OPENSSL_PREFIX pointed at a locally built OpenSSL
# 3.5+. The `ossl-sys` build script locates it via pkg-config, so PKG_CONFIG_PATH must include
# its pkgconfig dir; the produced cdylib links libcrypto.so.3 dynamically and resolves it at
# runtime via LD_LIBRARY_PATH (set once, process-wide, by the same CI step that builds SoftHSM).
if [[ -n "${OPENSSL_PREFIX:-}" && -d "${OPENSSL_PREFIX}" ]]; then
  for libdir in "${OPENSSL_PREFIX}/lib64" "${OPENSSL_PREFIX}/lib"; do
    if [[ -d "${libdir}" ]]; then
      export PKG_CONFIG_PATH="${libdir}/pkgconfig:${PKG_CONFIG_PATH:-}"
    fi
  done
  echo "Using OpenSSL from ${OPENSSL_PREFIX}"
fi

# Build only the cdylib crate (workspace member `kryoptic`, in cdylib/) and its dependencies —
# not the `tools` workspace member, which isn't needed to load the module. Its default features
# ("standard" + "dynamic": AES [incl. CCM]/RSA/ECC/EdDSA/KDFs [incl. SP800-108]/SQLite storage,
# linked dynamically against system libcrypto) are kept; "pqc" is added on top for ML-KEM, ML-DSA,
# and SLH-DSA. Together this closes the AES-CCM and SLH-DSA real-backend coverage gap
# (verified against C_GetMechanismList: CKM_AES_CCM and CKM_SLH_DSA are both advertised).
# Kryoptic 1.5.2 has no ChaCha20 support at all, so ChaCha20-Poly1305 coverage remains NSS-only.
# Note: cdylib/Cargo.toml
# does not re-expose "dynamic" as a selectable feature of the `kryoptic` package itself (only of
# its kryoptic-lib/ossl/ossl-sys dependencies) — it only reaches the build via `default`, so
# `--no-default-features` here would silently drop it. Add features; never disable defaults.
CARGO=(cargo build --release -p kryoptic --features pqc)
OUT_DIR="${SRC_DIR}/target/release"
# NATIVE_SANITIZE=address: Rust's sanitizers are nightly-only (-Zsanitizer). An explicit --target
# keeps the build scripts and proc macros, which run during the build, uninstrumented, and puts the
# sanitized build in its own target directory. The cdylib does not carry the ASan runtime: the
# process loading it preloads one, as for the C modules.
if [[ -n "$(sanitizer_flags)" ]]; then
  TARGET="$(rustc -vV | sed -n 's/^host: //p')"
  export RUSTFLAGS="-Zsanitizer=${NATIVE_SANITIZE} ${RUSTFLAGS:-}"
  CARGO=(cargo +nightly build --release --target "${TARGET}" -p kryoptic --features pqc)
  OUT_DIR="${SRC_DIR}/target/${TARGET}/release"
  echo "Sanitizer: ${NATIVE_SANITIZE} (nightly, ${TARGET})"
fi

(
  cd "${SRC_DIR}"
  "${CARGO[@]}"
) 2>&1

SRC_LIB="${OUT_DIR}/libkryoptic_pkcs11.so"
if [[ ! -f "${SRC_LIB}" ]]; then
  echo "build succeeded but ${SRC_LIB} not found" >&2; exit 1
fi

cp "${SRC_LIB}" "${DEST_LIB}"
record_build "${STAMP_FILE}" "${STAMP}"
echo "Installed ${DEST_LIB}"
