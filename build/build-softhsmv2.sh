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

BUILD_DIR="${SRC_DIR}/_cmake_build"
mkdir -p "${BUILD_DIR}"

cmake -S "${SRC_DIR}" -B "${BUILD_DIR}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTS=OFF \
  -DENABLE_P11_KIT=OFF \
  -DENABLE_STATIC=OFF \
  -DWITH_CRYPTO_BACKEND=openssl \
  -DENABLE_ECC=ON \
  -DENABLE_EDDSA=ON \
  -DDISABLE_NON_PAGED_MEMORY=ON \
  -DDEFAULT_SOFTHSM2_CONF="${DEST_DIR}/softhsm2.conf" \
  -DDEFAULT_TOKENDIR="${DEST_DIR}/tokens/" \
  -DDEFAULT_PKCS11_LIB="${DEST_DIR}/${LIB_NAME}" \
  -DCMAKE_INSTALL_PREFIX="${BUILD_DIR}/install" \
  -DENABLE_STRICT=OFF \
  -Wno-dev \
  2>&1

cmake --build "${BUILD_DIR}" --parallel "$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)" 2>&1

# Locate outputs.
SRC_LIB="$(find "${BUILD_DIR}" -name "${LIB_NAME}" ! -name '*-static*' | head -1)"
SRC_UTIL="$(find "${BUILD_DIR}" -name "softhsm2-util" -type f | head -1)"

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
