#!/usr/bin/env bash
# Builds SoftHSMv2 from the third-party/softhsmv2 submodule and copies
# libsofthsm2.so (or .dylib) and softhsm2-util into the test output directory.
#
# Usage: build-softhsmv2.sh <test-output-dir>
#
# Outputs (relative to <test-output-dir>):
#   runtimes/<rid>/native/libsofthsm2.<ext>
#   runtimes/<rid>/native/softhsm2-util
#
# Idempotent: skips rebuild when outputs are newer than the submodule HEAD.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <test-output-dir>" >&2
  exit 2
fi

OUT_BASE="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/vendor/softhsmv2"

if [[ ! -d "${SRC_DIR}" ]]; then
  echo "softhsmv2 submodule missing at ${SRC_DIR}." >&2
  echo "Run: git submodule update --init --recursive" >&2
  exit 1
fi

UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"

case "${UNAME_S}" in
  Linux)
    case "${UNAME_M}" in
      x86_64)  RID="linux-x64"   ;;
      aarch64) RID="linux-arm64" ;;
      *) echo "unsupported Linux arch: ${UNAME_M}" >&2; exit 1 ;;
    esac
    LIB_NAME="libsofthsm2.so"
    ;;
  Darwin)
    case "${UNAME_M}" in
      x86_64) RID="osx-x64"   ;;
      arm64)  RID="osx-arm64" ;;
      *) echo "unsupported macOS arch: ${UNAME_M}" >&2; exit 1 ;;
    esac
    LIB_NAME="libsofthsm2.dylib"
    ;;
  *)
    echo "unsupported OS: ${UNAME_S}" >&2; exit 1 ;;
esac

DEST_DIR="${OUT_BASE}/runtimes/${RID}/native"
DEST_LIB="${DEST_DIR}/${LIB_NAME}"
DEST_UTIL="${DEST_DIR}/softhsm2-util"

mkdir -p "${DEST_DIR}"

# Skip rebuild if both outputs are newer than the submodule HEAD commit.
HEAD_TS="$(git -C "${SRC_DIR}" log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
_ts() { [[ -f "$1" ]] && (stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0) || echo 0; }
LIB_TS="$(_ts "${DEST_LIB}")"
UTIL_TS="$(_ts "${DEST_UTIL}")"
if (( LIB_TS > HEAD_TS && UTIL_TS > HEAD_TS )); then
  echo "softhsmv2 up to date at ${DEST_DIR}"
  exit 0
fi

echo "Building SoftHSMv2 for ${RID}..."

# We build with autotools (not CMake): only the autotools path wires up ML-DSA
# (CKM_ML_DSA), via `--enable-mldsa` defaulting to "detect" — it auto-enables when the
# OpenSSL backend exposes ML-DSA (OpenSSL 3.5+). The CMake build's ENABLE_MLDSA option is a
# no-op (it never sets WITH_ML_DSA), so it can never produce an ML-DSA-capable token.
#
# To build against a non-system OpenSSL (e.g. 3.5+ for ML-DSA), set OPENSSL_PREFIX to its
# install dir; we point configure at it and bake an rpath so libsofthsm2 loads that OpenSSL
# at runtime. When unset, the system OpenSSL is used (ML-DSA simply detects off).
NPROC="$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)"

OPENSSL_CONFIGURE_ARGS=()
if [[ -n "${OPENSSL_PREFIX:-}" && -d "${OPENSSL_PREFIX}" ]]; then
  OPENSSL_CONFIGURE_ARGS+=("--with-openssl=${OPENSSL_PREFIX}")
  # OpenSSL built from source installs to lib64 (with a lib -> lib64 symlink); cover both.
  for libdir in "${OPENSSL_PREFIX}/lib64" "${OPENSSL_PREFIX}/lib"; do
    if [[ -d "${libdir}" ]]; then
      export LDFLAGS="-Wl,-rpath,${libdir} -L${libdir} ${LDFLAGS:-}"
      export PKG_CONFIG_PATH="${libdir}/pkgconfig:${PKG_CONFIG_PATH:-}"
    fi
  done
  echo "Using OpenSSL from ${OPENSSL_PREFIX}"
fi

# autogen.sh generates ./configure in the source tree; build out-of-tree (VPATH) to keep it clean.
( cd "${SRC_DIR}" && sh ./autogen.sh ) 2>&1

BUILD_DIR="${SRC_DIR}/_at_build"
INSTALL_DIR="${BUILD_DIR}/install"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

(
  cd "${BUILD_DIR}"
  "${SRC_DIR}/configure" \
    --prefix="${INSTALL_DIR}" \
    --with-crypto-backend=openssl \
    --enable-ecc \
    --enable-eddsa \
    --disable-non-paged-memory \
    --disable-p11-kit \
    "${OPENSSL_CONFIGURE_ARGS[@]}"
  make -j"${NPROC}"
  make install
) 2>&1

# Locate installed outputs (autotools: lib/softhsm/libsofthsm2.so, bin/softhsm2-util).
SRC_LIB="$(find "${INSTALL_DIR}" -name "${LIB_NAME}" ! -name '*-static*' | head -1)"
SRC_UTIL="$(find "${INSTALL_DIR}" -name "softhsm2-util" -type f | head -1)"

if [[ -z "${SRC_LIB}" ]]; then
  echo "build succeeded but ${LIB_NAME} not found under ${BUILD_DIR}" >&2; exit 1
fi
if [[ -z "${SRC_UTIL}" ]]; then
  echo "build succeeded but softhsm2-util not found under ${BUILD_DIR}" >&2; exit 1
fi

cp "${SRC_LIB}"  "${DEST_LIB}"
cp "${SRC_UTIL}" "${DEST_UTIL}"
chmod +x "${DEST_UTIL}"
echo "Installed ${DEST_LIB}"
echo "Installed ${DEST_UTIL}"

# Record whether ML-DSA was actually compiled in (depends on OpenSSL 3.5+), so the test suite
# can gate its ML-DSA cases on a cheap file check instead of probing the token at discovery time.
MLDSA_MARKER="${DEST_DIR}/softhsm-mldsa.enabled"
if grep -q '^#define WITH_ML_DSA' "${BUILD_DIR}/config.h" 2>/dev/null; then
  : > "${MLDSA_MARKER}"
  echo "ML-DSA: enabled (marker written)"
else
  rm -f "${MLDSA_MARKER}"
  echo "ML-DSA: not available in this build (OpenSSL < 3.5)"
fi
