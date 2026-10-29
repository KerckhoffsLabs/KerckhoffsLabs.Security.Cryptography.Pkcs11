#!/usr/bin/env bash
# Builds wolfPKCS11 from the vendor/wolfpkcs11 submodule, linked against a static wolfSSL built from
# vendor/wolfssl, and copies the built libwolfpkcs11.so into the test output directory.
#
# Usage: build-wolfpkcs11.sh <test-output-dir>
#
# Outputs (relative to <test-output-dir>):
#   runtimes/<rid>/native/libwolfpkcs11.so
#
# Idempotent: skips the rebuild when the staged output was built from these two submodule commits by
# this script (see is_built_from). NATIVE_SANITIZE=address builds both with AddressSanitizer.
#
# wolfSSL is private to the module: a static, position-independent libwolfssl.a linked in with
# --with-static-wolfssl, so the staged library is self-contained, exports no wolfSSL symbols and
# cannot pick up another wolfSSL loaded in the same process. Linux only for now, like FreeHSM and
# Craton HSM: the backend is wired into CI on the ubuntu-latest leg only (see ci.yml).

set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_args 1 "<test-output-dir>" "$@"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "build-wolfpkcs11.sh: wolfPKCS11 is wired up on Linux only (got $(uname -s)); nothing to do." >&2
  exit 0
fi

OUT_BASE="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/vendor/wolfpkcs11"
WOLFSSL_SRC_DIR="${REPO_ROOT}/vendor/wolfssl"
# Built out of tree: autogen.sh and configure write into the source tree, which would leave the
# submodules dirty.
BUILD_DIR="${REPO_ROOT}/obj/wolfpkcs11"
WOLFSSL_BUILD_DIR="${REPO_ROOT}/obj/wolfssl"
WOLFSSL_PREFIX="${WOLFSSL_BUILD_DIR}/install"

require_submodule "${SRC_DIR}/configure.ac" wolfpkcs11
require_submodule "${WOLFSSL_SRC_DIR}/configure.ac" wolfssl

RID="$(host_rid)"

DEST_DIR="${OUT_BASE}/runtimes/${RID}/native"
DEST_LIB="${DEST_DIR}/libwolfpkcs11.so"

mkdir -p "${DEST_DIR}"

# build_stamp covers one source tree; the wolfSSL commit is added so that moving either submodule
# rebuilds.
STAMP_FILE="${DEST_LIB}.built-from"
STAMP="$(build_stamp "${SRC_DIR}") wolfssl=$(git -C "${WOLFSSL_SRC_DIR}" rev-parse HEAD)"
if is_built_from "${STAMP_FILE}" "${STAMP}" "${DEST_LIB}"; then
  echo "wolfpkcs11 up to date at ${DEST_LIB}"
  exit 0
fi
rm -f "${STAMP_FILE}"

SAN="$(sanitizer_flags)"
[[ -n "${SAN}" ]] && echo "Sanitizer: ${NATIVE_SANITIZE}"

# The build directory carries its own stamp, so a restored CI cache of it only needs staging.
BUILD_LIB="${BUILD_DIR}/src/.libs/libwolfpkcs11.so"
BUILD_STAMP_FILE="${BUILD_DIR}/libwolfpkcs11.so.built-from"
if ! is_built_from "${BUILD_STAMP_FILE}" "${STAMP}" "${BUILD_LIB}"; then
  echo "Building wolfSSL and wolfPKCS11 for ${RID}..."
  rm -rf "${BUILD_DIR}" "${WOLFSSL_BUILD_DIR}"
  mkdir -p "${BUILD_DIR}" "${WOLFSSL_BUILD_DIR}/src"
  git -C "${WOLFSSL_SRC_DIR}" archive --format=tar HEAD | tar -x -C "${WOLFSSL_BUILD_DIR}/src"
  git -C "${SRC_DIR}" archive --format=tar HEAD | tar -x -C "${BUILD_DIR}"

  # The options wolfPKCS11's README requires, plus the ones its optional mechanisms need: AES
  # CTR/CCM/CTS/CMAC/key wrap, HKDF, SHA-3, ML-DSA and ML-KEM. Crypto only, static and PIC for
  # --with-static-wolfssl.
  (
    cd "${WOLFSSL_BUILD_DIR}/src"
    ./autogen.sh
    ./configure --prefix="${WOLFSSL_PREFIX}" \
      --enable-static --disable-shared --with-pic --enable-cryptonly \
      --enable-cryptocb --enable-aescfb --enable-rsapss --enable-keygen --enable-pwdbased --enable-scrypt \
      --enable-md5 --enable-aesctr --enable-aesccm --enable-aescts --enable-cmac --enable-aeskeywrap \
      --enable-hkdf --enable-sha3 --enable-sha224 --enable-mldsa --enable-mlkem \
      C_EXTRA_FLAGS="-DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT -DHAVE_AES_ECB -DHAVE_AES_KEYWRAP ${SAN}"
    make -j"$(nproc)"
    make install
  ) 2>&1

  # PKCS#11 v3.2 and every mechanism family it has except the ones the spec leaves out: no
  # NSS-compatibility mode (it relaxes spec checks), no wolfTPM store, no LMS/XMSS (this library has
  # no API for them). Multi-threaded, for the suite's thread-safety cases.
  (
    cd "${BUILD_DIR}"
    ./autogen.sh
    ./configure --enable-pkcs11v32 --enable-mldsa --enable-mlkem --enable-aesccm --enable-aesecb \
      --enable-aescts --enable-aescmac --enable-hkdf --enable-pbkdf2 --enable-sha3 \
      --with-static-wolfssl="${WOLFSSL_PREFIX}/lib/libwolfssl.a" \
      CPPFLAGS="-I${WOLFSSL_PREFIX}/include" CFLAGS="${SAN}" LDFLAGS="${SAN}"
    make -j"$(nproc)"
  ) 2>&1

  if [[ ! -f "${BUILD_LIB}" ]]; then
    echo "build succeeded but ${BUILD_LIB} not found" >&2; exit 1
  fi
  record_build "${BUILD_STAMP_FILE}" "${STAMP}"
fi

cp "$(readlink -f "${BUILD_LIB}")" "${DEST_LIB}"
record_build "${STAMP_FILE}" "${STAMP}"
echo "Installed ${DEST_LIB}"
