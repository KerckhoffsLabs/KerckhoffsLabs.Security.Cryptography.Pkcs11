#!/usr/bin/env bash
# Stages SoftHSM 2.5.0 — an authentic PKCS#11 v2.40-only module — into a writable directory, for the
# softhsm-v240 CI leg. SoftHSM 2.5 predates the v3.0 C_GetInterface API, so it exercises the wrapper's
# real v2.40 negotiation path against a real module (the counterpart of the synthetic gate-240 shim).
#
# 2.5.0 does not build against OpenSSL 3.x (that support landed in 2.6.1), so rather than build from
# source against a modern toolchain we reuse the Debian buster binary, which was built against OpenSSL 1.1.
# We fetch three .debs from snapshot.debian.org at pinned, content-addressed URLs and verify their
# SHA-256 before extracting, so the download is reproducible and tamper-evident.
#
# Usage: setup-softhsm25.sh <stage-dir>
# On success prints the staged native directory (containing libsofthsm2.so, softhsm2-util, and the
# OpenSSL 1.1 runtime) to stdout; the caller points PKCS11_TEST_SOFTHSM_LIBRARY and LD_LIBRARY_PATH at it.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <stage-dir>" >&2
  exit 2
fi

STAGE="$1"
SNAP="https://snapshot.debian.org"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# Pinned Debian snapshot URLs + expected SHA-256 (amd64).
# libsofthsm2 / softhsm2: Debian buster 2.5.0-1 (2019-03-02 snapshot).
# libssl1.1: Debian bullseye 1.1.1w-0+deb11u8 — the latest security-patched 1.1.x build.
declare -A DEB_URL DEB_SHA256
DEB_URL[libsofthsm2]="${SNAP}/archive/debian/20190302T210725Z/pool/main/s/softhsm2/libsofthsm2_2.5.0-1_amd64.deb"
DEB_SHA256[libsofthsm2]="d4244c570efa8951a52a1406c0fbd04dd89277ca8d1cd8319a930c34b3ad5015"
DEB_URL[softhsm2]="${SNAP}/archive/debian/20190302T210725Z/pool/main/s/softhsm2/softhsm2_2.5.0-1_amd64.deb"
DEB_SHA256[softhsm2]="38e6730a909ffb001ea4c7da40ebea7255784881ea8a12bf2f76fe9adcd00e41"
DEB_URL[libssl1.1]="${SNAP}/archive/debian-security/20260615T025018Z/pool/updates/main/o/openssl/libssl1.1_1.1.1w-0%2Bdeb11u8_amd64.deb"
DEB_SHA256[libssl1.1]="dcc68a543de6cb955a57077b66dcdb15f61d1e31e072f2c6cc4082c37da1b00d"

for pkg in libsofthsm2 softhsm2 libssl1.1; do
  dest="${WORK}/${pkg}.deb"
  echo "fetching ${pkg}" >&2
  curl --proto '=https' --proto-redir '=https' -fsSL -o "${dest}" "${DEB_URL[$pkg]}"
  echo "${DEB_SHA256[$pkg]}  ${dest}" | sha256sum -c - >&2
  dpkg-deb -x "${dest}" "${WORK}/root"
done

LIB_SRC="$(find "${WORK}/root" -name 'libsofthsm2.so' | head -1)"
UTIL_SRC="$(find "${WORK}/root" -name 'softhsm2-util' -type f | head -1)"

if [[ -z "${LIB_SRC}" || -z "${UTIL_SRC}" ]]; then
  echo "extracted packages are missing libsofthsm2.so or softhsm2-util" >&2
  exit 1
fi

mkdir -p "${STAGE}"
cp "${LIB_SRC}" "${UTIL_SRC}" "${STAGE}/"
find "${WORK}/root" \( -name 'libcrypto.so.1.1' -o -name 'libssl.so.1.1' \) | while read -r so; do
  cp "${so}" "${STAGE}/"
done

VERSION="$(LD_LIBRARY_PATH="${STAGE}" "${STAGE}/softhsm2-util" --version 2>/dev/null || true)"
echo "staged softhsm2-util --version: ${VERSION}" >&2
if [[ "${VERSION}" != 2.5.* ]]; then
  echo "expected SoftHSM 2.5.x, got '${VERSION}' — refusing to proceed." >&2
  exit 1
fi

echo "${STAGE}"
