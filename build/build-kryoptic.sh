#!/usr/bin/env bash
# Builds Kryoptic from the vendor/kryoptic submodule and copies the built
# libkryoptic_pkcs11.so into the test output directory.
#
# Usage: build-kryoptic.sh <test-output-dir>
#
# Outputs (relative to <test-output-dir>):
#   runtimes/<rid>/native/libkryoptic_pkcs11.so
#
# Idempotent: skips rebuild when the output is newer than the submodule HEAD.
#
# Linux only for now: Kryoptic (Rust/cargo) is cross-platform in principle, but this
# backend is wired into CI on the ubuntu-latest leg only (see ci.yml) — matching how
# opencryptoki and NSS were introduced as additional real backends one leg at a time.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <test-output-dir>" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "build-kryoptic.sh: Kryoptic is wired up on Linux only for now (got $(uname -s)); nothing to do." >&2
  exit 0
fi

OUT_BASE="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/vendor/kryoptic"

if [[ ! -f "${SRC_DIR}/Cargo.toml" ]]; then
  echo "kryoptic submodule missing at ${SRC_DIR}." >&2
  echo "Run: git submodule update --init --recursive" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64)  RID="linux-x64"   ;;
  aarch64) RID="linux-arm64" ;;
  *) echo "unsupported Linux arch: $(uname -m)" >&2; exit 1 ;;
esac

DEST_DIR="${OUT_BASE}/runtimes/${RID}/native"
DEST_LIB="${DEST_DIR}/libkryoptic_pkcs11.so"

mkdir -p "${DEST_DIR}"

# Skip rebuild if the output is newer than the submodule HEAD commit.
HEAD_TS="$(git -C "${SRC_DIR}" log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
LIB_TS="$( { [[ -f "${DEST_LIB}" ]] && stat -c %Y "${DEST_LIB}" 2>/dev/null; } || echo 0)"
if (( LIB_TS > HEAD_TS )); then
  echo "kryoptic up to date at ${DEST_LIB}"
  exit 0
fi

echo "Building Kryoptic for ${RID}..."

# Kryoptic's "standard" feature set requires OpenSSL >= 3.2.0 (EdDSA needs ossl/ossl320);
# "pqc" (ML-KEM/ML-DSA/SLH-DSA — the whole reason this backend exists, see BL-028) further
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
# and SLH-DSA. Together this closes the AES-CCM and SLH-DSA real-backend coverage gap from BL-028
# (verified against C_GetMechanismList: CKM_AES_CCM and CKM_SLH_DSA are both advertised).
# Kryoptic 1.5.2 has no ChaCha20 support at all, so ChaCha20-Poly1305 coverage remains NSS-only.
# Note: cdylib/Cargo.toml
# does not re-expose "dynamic" as a selectable feature of the `kryoptic` package itself (only of
# its kryoptic-lib/ossl/ossl-sys dependencies) — it only reaches the build via `default`, so
# `--no-default-features` here would silently drop it. Add features; never disable defaults.
(
  cd "${SRC_DIR}"
  cargo build --release -p kryoptic --features pqc
) 2>&1

SRC_LIB="${SRC_DIR}/target/release/libkryoptic_pkcs11.so"
if [[ ! -f "${SRC_LIB}" ]]; then
  echo "build succeeded but ${SRC_LIB} not found" >&2; exit 1
fi

cp "${SRC_LIB}" "${DEST_LIB}"
echo "Installed ${DEST_LIB}"
