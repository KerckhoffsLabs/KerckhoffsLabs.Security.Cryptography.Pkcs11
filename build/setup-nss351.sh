#!/usr/bin/env bash
# Stages Mozilla NSS 3.51 softoken — an authentic PKCS#11 v2.40-only module — into a writable
# directory, for the pkcs11-v240 CI leg. NSS 3.51 is the last release before 3.52 added the v3.0
# C_GetInterface API, so it exercises the wrapper's real v2.40 negotiation path against a second,
# independent real module (freebl rather than SoftHSM's OpenSSL).
#
# Rather than build a 2020 NSS against a modern toolchain we reuse the Debian binary. We fetch two
# .debs from snapshot.debian.org at pinned, content-addressed URLs and verify their SHA-256 before
# extracting, so the download is reproducible and tamper-evident.
#
# Usage: setup-nss351.sh <stage-dir>
# On success prints the staged native directory (containing libsoftokn3.so, its NSS siblings and
# the NSPR runtime) to stdout; the caller points PKCS11_TEST_NSS_LIBRARY and LD_LIBRARY_PATH at it.

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
# libnss3: Debian sid 2:3.51-1 (2020-04-08 snapshot) — softoken, freebl, nssutil, nssdbm.
# libnspr4: Debian sid 2:4.25-1 (2020-03-11 snapshot) — the NSPR libnss3 3.51 was built against.
# sqlite3, the remaining DT_NEEDED, comes from the runner.
declare -A DEB_URL DEB_SHA256
DEB_URL[libnss3]="${SNAP}/archive/debian/20200408T082336Z/pool/main/n/nss/libnss3_3.51-1_amd64.deb"
DEB_SHA256[libnss3]="261a1a866c9b53aa18a8b0a620ab8a24bfb1d3641bcbb255ecc79c8e74b837cf"
DEB_URL[libnspr4]="${SNAP}/archive/debian/20200311T090704Z/pool/main/n/nspr/libnspr4_4.25-1_amd64.deb"
DEB_SHA256[libnspr4]="38c9cdc7296cdd0538bd2e405cee7f3366ce482e990151e9ccef0f86d0502660"

for pkg in libnss3 libnspr4; do
  dest="${WORK}/${pkg}.deb"
  echo "fetching ${pkg}" >&2
  curl --proto '=https' --proto-redir '=https' -fsSL -o "${dest}" "${DEB_URL[$pkg]}"
  echo "${DEB_SHA256[$pkg]}  ${dest}" | sha256sum -c - >&2
  dpkg-deb -x "${dest}" "${WORK}/root"
done

# Softoken dlopens freebl from its own directory and links nssutil/NSPR, so everything is staged
# flat into one directory.
mkdir -p "${STAGE}"
for lib in libsoftokn3.so libfreebl3.so libfreeblpriv3.so libnssdbm3.so libnssutil3.so \
           libnspr4.so libplc4.so libplds4.so; do
  src="$(find "${WORK}/root" -name "${lib}" | head -1)"
  if [[ -z "${src}" ]]; then
    echo "extracted packages are missing ${lib}" >&2
    exit 1
  fi
  cp "${src}" "${STAGE}/"
done

# softoken carries no version-reporting tool; its embedded version string is the authoritative check.
VERSION="$(grep -a -o -m1 'Version: NSS [0-9.]*' "${STAGE}/libsoftokn3.so" | head -1 || true)"
echo "staged libsoftokn3.so: ${VERSION}" >&2
if [[ "${VERSION}" != "Version: NSS 3.51" ]]; then
  echo "expected NSS 3.51, got '${VERSION}' — refusing to proceed." >&2
  exit 1
fi

echo "${STAGE}"
