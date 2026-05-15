#!/usr/bin/env bash
# Builds pkcs11-mock and copies the resulting shared library into the
# Pkcs11.Tests output directory under the appropriate runtime identifier.
#
# Usage: build-pkcs11-mock.sh <test-output-dir>
#   <test-output-dir> e.g. src/.../Pkcs11.Tests/bin/Debug/net9.0
#
# Idempotent: if the target binary already exists and is newer than the
# submodule HEAD commit, it is reused.
#
# NOTE on upstream Makefile quirks:
#   Linux:  The default Makefile only builds a 32-bit (-m32) library.
#           We patch it in-memory with sed to build the 64-bit variant
#           matching the host arch.
#   macOS:  build.sh produces a universal (arm64 + x86_64) pkcs11-mock.dylib
#           via lipo; we copy that single file for both osx-x64 and osx-arm64.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <test-output-dir>" >&2
  exit 2
fi

OUT_BASE="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOCK_DIR="${REPO_ROOT}/vendor/pkcs11-mock"

if [[ ! -d "${MOCK_DIR}" ]]; then
  echo "pkcs11-mock submodule missing at ${MOCK_DIR}." >&2
  echo "Run: git submodule update --init --recursive" >&2
  exit 1
fi

UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"

case "${UNAME_S}" in
  Linux)
    case "${UNAME_M}" in
      x86_64)  RID="linux-x64";   ARCH_FLAGS="-m64"; LIB_SUFFIX="x64"  ;;
      aarch64) RID="linux-arm64"; ARCH_FLAGS="-march=armv8-a"; LIB_SUFFIX="arm64" ;;
      *) echo "unsupported Linux arch: ${UNAME_M}" >&2; exit 1 ;;
    esac
    LIB_EXT="so"
    BUILD_SUBDIR="build/linux"
    ;;
  Darwin)
    case "${UNAME_M}" in
      x86_64) RID="osx-x64"   ;;
      arm64)  RID="osx-arm64" ;;
      *) echo "unsupported macOS arch: ${UNAME_M}" >&2; exit 1 ;;
    esac
    LIB_EXT="dylib"
    BUILD_SUBDIR="build/macos"
    ;;
  *)
    echo "unsupported OS: ${UNAME_S}" >&2
    exit 1
    ;;
esac

DEST_DIR="${OUT_BASE}/runtimes/${RID}/native"
DEST_FILE="${DEST_DIR}/pkcs11-mock.${LIB_EXT}"

mkdir -p "${DEST_DIR}"

# Skip rebuild if dest is newer than the mock submodule HEAD.
MOCK_HEAD_TS="$(git -C "${MOCK_DIR}" log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
DEST_TS=0
if [[ -f "${DEST_FILE}" ]]; then
  DEST_TS=$(stat -c %Y "${DEST_FILE}" 2>/dev/null || stat -f %m "${DEST_FILE}" 2>/dev/null || echo 0)
fi
if (( DEST_TS > MOCK_HEAD_TS )); then
  echo "pkcs11-mock up to date at ${DEST_FILE}"
  exit 0
fi

echo "Building pkcs11-mock for ${RID}..."

pushd "${MOCK_DIR}/${BUILD_SUBDIR}" >/dev/null

case "${UNAME_S}" in
  Linux)
    # The default Makefile only targets -m32; patch ARCH_FLAGS and LIBNAME
    # in-memory so we build the host-architecture 64-bit library.
    LIBNAME="pkcs11-mock-${LIB_SUFFIX}.${LIB_EXT}"
    make distclean 2>/dev/null || true

    cat Makefile \
      | sed "s|^ARCH_FLAGS=.*|ARCH_FLAGS= ${ARCH_FLAGS}|" \
      | sed "s|^LIBNAME=.*|LIBNAME=${LIBNAME}|" \
      > Makefile.host
    make -f Makefile.host
    rm -f Makefile.host
    ;;
  Darwin)
    # build.sh produces a universal pkcs11-mock.dylib via lipo.
    bash build.sh
    ;;
esac

popd >/dev/null

# Locate the produced library.
case "${UNAME_S}" in
  Linux)
    SRC_LIB="${MOCK_DIR}/${BUILD_SUBDIR}/pkcs11-mock-${LIB_SUFFIX}.${LIB_EXT}"
    ;;
  Darwin)
    SRC_LIB="${MOCK_DIR}/${BUILD_SUBDIR}/pkcs11-mock.${LIB_EXT}"
    ;;
esac

if [[ ! -f "${SRC_LIB}" ]]; then
  echo "build succeeded but expected library not found: ${SRC_LIB}" >&2
  echo "Files present in ${MOCK_DIR}/${BUILD_SUBDIR}:" >&2
  find "${MOCK_DIR}/${BUILD_SUBDIR}" -maxdepth 2 -name "*.${LIB_EXT}" >&2 || true
  exit 1
fi

cp "${SRC_LIB}" "${DEST_FILE}"
echo "Installed ${DEST_FILE}"
