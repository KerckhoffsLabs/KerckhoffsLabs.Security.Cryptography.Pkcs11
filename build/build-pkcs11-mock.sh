#!/usr/bin/env bash
# Builds pkcs11-mock and copies the resulting shared library into the
# Pkcs11.Tests output directory under the appropriate runtime identifier.
#
# Usage: build-pkcs11-mock.sh <test-output-dir>
#   <test-output-dir> e.g. tests/.../Pkcs11.Tests/bin/Debug/net9.0
#
# Idempotent: the target binary is reused when it was built from this submodule
# commit by this script (see is_built_from).
#
# NOTE on upstream Makefile quirks:
#   Linux:  The default Makefile only builds a 32-bit (-m32) library.
#           We patch it in-memory with sed to build the 64-bit variant
#           matching the host arch.
#   macOS:  build.sh produces a universal (arm64 + x86_64) pkcs11-mock.dylib
#           via lipo; we copy that single file for both osx-x64 and osx-arm64.

set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_args 1 "<test-output-dir>" "$@"

OUT_BASE="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOCK_DIR="${REPO_ROOT}/vendor/pkcs11-mock"

require_submodule "${MOCK_DIR}" pkcs11-mock

RID="$(host_rid)"
case "${RID}" in
  linux-x64)   ARCH_FLAGS="-m64";           LIB_SUFFIX="x64";   LIB_EXT="so";    BUILD_SUBDIR="build/linux" ;;
  linux-arm64) ARCH_FLAGS="-march=armv8-a"; LIB_SUFFIX="arm64"; LIB_EXT="so";    BUILD_SUBDIR="build/linux" ;;
  osx-*)                                                          LIB_EXT="dylib"; BUILD_SUBDIR="build/macos" ;;
  *) echo "no pkcs11-mock build for ${RID}" >&2; exit 1 ;;
esac

SANITIZE="$(sanitizer_flags)"
if [[ -n "${SANITIZE}" && "${RID}" != linux-* ]]; then
  echo "NATIVE_SANITIZE is supported for the Linux build only" >&2; exit 1
fi

DEST_DIR="${OUT_BASE}/runtimes/${RID}/native"
DEST_FILE="${DEST_DIR}/pkcs11-mock.${LIB_EXT}"

mkdir -p "${DEST_DIR}"

STAMP_FILE="${DEST_FILE}.built-from"
STAMP="$(build_stamp "${MOCK_DIR}")"
if is_built_from "${STAMP_FILE}" "${STAMP}" "${DEST_FILE}"; then
  echo "pkcs11-mock up to date at ${DEST_FILE}"
  exit 0
fi
rm -f "${STAMP_FILE}"

echo "Building pkcs11-mock for ${RID}..."

pushd "${MOCK_DIR}/${BUILD_SUBDIR}" >/dev/null

case "${RID}" in
  linux-*)
    # The default Makefile only targets -m32; patch ARCH_FLAGS and LIBNAME
    # in-memory so we build the host-architecture 64-bit library.
    LIBNAME="pkcs11-mock-${LIB_SUFFIX}.${LIB_EXT}"
    make distclean 2>/dev/null || true

    # ARCH_FLAGS reaches both the compile and the link, which is where a sanitizer must be; a
    # sanitized build keeps its symbols, so its reports name the mock's own functions and lines.
    cat Makefile \
      | sed "s|^ARCH_FLAGS=.*|ARCH_FLAGS= ${ARCH_FLAGS} ${SANITIZE}|" \
      | sed "s|^LIBNAME=.*|LIBNAME=${LIBNAME}|" \
      | if [[ -n "${SANITIZE}" ]]; then sed "/strip --strip-all/d"; else cat; fi \
      > Makefile.host
    make -f Makefile.host
    rm -f Makefile.host
    ;;
  *)
    # osx-*, the only other RID the first case accepts: build.sh produces a universal
    # pkcs11-mock.dylib via lipo.
    bash build.sh
    ;;
esac

popd >/dev/null

# Locate the produced library.
case "${RID}" in
  linux-*) SRC_LIB="${MOCK_DIR}/${BUILD_SUBDIR}/pkcs11-mock-${LIB_SUFFIX}.${LIB_EXT}" ;;
  *)       SRC_LIB="${MOCK_DIR}/${BUILD_SUBDIR}/pkcs11-mock.${LIB_EXT}" ;; # osx-*
esac

if [[ ! -f "${SRC_LIB}" ]]; then
  echo "build succeeded but expected library not found: ${SRC_LIB}" >&2
  echo "Files present in ${MOCK_DIR}/${BUILD_SUBDIR}:" >&2
  find "${MOCK_DIR}/${BUILD_SUBDIR}" -maxdepth 2 -name "*.${LIB_EXT}" >&2 || true
  exit 1
fi

cp "${SRC_LIB}" "${DEST_FILE}"
record_build "${STAMP_FILE}" "${STAMP}"
echo "Installed ${DEST_FILE}"
