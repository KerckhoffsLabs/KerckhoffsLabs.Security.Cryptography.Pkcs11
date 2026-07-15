#!/usr/bin/env bash
# Stages SoftHSM 2.5.0 — an authentic PKCS#11 v2.40-only module — into a writable directory, for the
# softhsm-v240 CI leg. SoftHSM 2.5 predates the v3.0 C_GetInterface API, so it exercises the wrapper's
# real v2.40 negotiation path against a real module (the counterpart of the synthetic gate-240 shim).
#
# 2.5.0 does not build against OpenSSL 3.x (that support landed in 2.6.1), so rather than build from
# source against a modern toolchain we reuse the Ubuntu 20.04 (focal) binary, which was built against
# OpenSSL 1.1. We fetch the focal .deb for softhsm2 and libssl1.1 straight from the archive pool,
# resolving the exact filenames from the directory listing so a point-revision bump does not 404, and
# extract them side by side. The library + util end up colocated (what the SoftHSM fixture expects),
# and libcrypto.so.1.1 is placed alongside for the loader to find via LD_LIBRARY_PATH.
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
POOL="https://archive.ubuntu.com/ubuntu/pool"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# Resolve the exact .deb filename for a pinned major.minor from a pool directory listing.
#   $1 = pool subdirectory (e.g. universe/s/softhsm2)
#   $2 = filename regex anchoring the version (e.g. softhsm2_2\.5\.0)
resolve_deb() {
  local subdir="$1" regex="$2" name
  name="$(curl --proto '=https' --proto-redir '=https' -fsSL "${POOL}/${subdir}/" \
    | grep -oE "${regex}[^\"']*_amd64\.deb" \
    | sort -V | tail -1)"
  if [[ -z "${name}" ]]; then
    echo "could not resolve a .deb matching '${regex}' under ${POOL}/${subdir}/" >&2
    return 1
  fi
  echo "${name}"
}

fetch_extract() {
  local subdir="$1" name="$2"
  echo "fetching ${name}" >&2
  curl --proto '=https' --proto-redir '=https' -fsSL -o "${WORK}/${name}" "${POOL}/${subdir}/${name}"
  dpkg-deb -x "${WORK}/${name}" "${WORK}/root"
}

# Debian splits SoftHSM into libsofthsm2 (the module .so) and softhsm2 (softhsm2-util); fetch both.
fetch_extract "universe/s/softhsm2" "$(resolve_deb "universe/s/softhsm2" 'libsofthsm2_2\.5\.0')"
fetch_extract "universe/s/softhsm2" "$(resolve_deb "universe/s/softhsm2" 'softhsm2_2\.5\.0')"
fetch_extract "main/o/openssl" "$(resolve_deb "main/o/openssl" 'libssl1\.1_1\.1\.1')"

ROOT="${WORK}/root"
LIB_SRC="$(find "${ROOT}" -name 'libsofthsm2.so' | head -1)"
UTIL_SRC="$(find "${ROOT}" -name 'softhsm2-util' -type f | head -1)"

if [[ -z "${LIB_SRC}" || -z "${UTIL_SRC}" ]]; then
  echo "extracted packages are missing libsofthsm2.so or softhsm2-util:" >&2
  find "${ROOT}" \( -name 'libsofthsm2.so' -o -name 'softhsm2-util' \) >&2
  exit 1
fi

mkdir -p "${STAGE}"
cp "${LIB_SRC}" "${UTIL_SRC}" "${STAGE}/"
# The OpenSSL 1.1 runtime softhsm2 2.5 links against (libcrypto.so.1.1 is the one it dlopens).
find "${ROOT}" -name 'libcrypto.so.1.1' -o -name 'libssl.so.1.1' | while read -r so; do
  cp "${so}" "${STAGE}/"
done

# Fail loudly if this is not actually SoftHSM 2.5 — the whole point of the leg is a pinned v2.40 module.
VERSION="$(LD_LIBRARY_PATH="${STAGE}" "${STAGE}/softhsm2-util" --version 2>/dev/null || true)"
echo "staged softhsm2-util --version: ${VERSION}" >&2
if [[ "${VERSION}" != 2.5.* ]]; then
  echo "expected SoftHSM 2.5.x, got '${VERSION}' — refusing to proceed." >&2
  exit 1
fi

echo "${STAGE}"
