#!/usr/bin/env bash
# Builds Mozilla NSS softoken from the vendor/nss submodule and stages libsoftokn3.so
# together with the runtime libraries it needs into the test output directory.
#
# Usage: build-nss.sh <test-output-dir>
#
# Outputs (relative to <test-output-dir>):
#   runtimes/<rid>/native/nss/libsoftokn3.so     (the PKCS#11 module the tests load)
#   runtimes/<rid>/native/nss/libfreebl*.so       (crypto backend softoken dlopens at runtime)
#   runtimes/<rid>/native/nss/libnssutil3.so      (DT_NEEDED of libsoftokn3)
#   runtimes/<rid>/native/nss/libsoftokn3.so path is echoed on stdout (for $GITHUB_OUTPUT)
#
# NSPR is taken from the system (--system-nspr → libnspr4-dev), so libsoftokn3's NSPR/sqlite
# DT_NEEDED entries resolve against the distro libraries at runtime; only the NSS-family
# libraries are staged. An $ORIGIN runpath is patched onto the staged module (best-effort, when
# patchelf is available) so it finds its NSS siblings without LD_LIBRARY_PATH; CI sets
# LD_LIBRARY_PATH to the staging dir as well.
#
# Idempotent: skips the rebuild when the staged module is newer than the submodule HEAD.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <test-output-dir>" >&2
  exit 2
fi

OUT_BASE="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/vendor/nss"

if [[ ! -d "${SRC_DIR}" ]]; then
  echo "nss submodule missing at ${SRC_DIR}." >&2
  echo "Run: git submodule update --init --recursive" >&2
  exit 1
fi

UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"

# NSS's gyp build produces `.so` shared objects on both Linux and macOS.
case "${UNAME_S}" in
  Linux)
    case "${UNAME_M}" in
      x86_64)  RID="linux-x64"   ;;
      aarch64) RID="linux-arm64" ;;
      *) echo "unsupported Linux arch: ${UNAME_M}" >&2; exit 1 ;;
    esac
    ;;
  Darwin)
    case "${UNAME_M}" in
      x86_64) RID="osx-x64"   ;;
      arm64)  RID="osx-arm64" ;;
      *) echo "unsupported macOS arch: ${UNAME_M}" >&2; exit 1 ;;
    esac
    ;;
  *)
    echo "unsupported OS: ${UNAME_S}" >&2; exit 1 ;;
esac

DEST_DIR="${OUT_BASE}/runtimes/${RID}/native/nss"
DEST_LIB="${DEST_DIR}/libsoftokn3.so"

mkdir -p "${DEST_DIR}"

# Skip rebuild if the staged module is newer than the submodule HEAD commit.
HEAD_TS="$(git -C "${SRC_DIR}" log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
_ts() { local f="$1"; [[ -f "$f" ]] && (stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo 0) || echo 0; }
if (( "$(_ts "${DEST_LIB}")" > HEAD_TS )); then
  echo "nss up to date at ${DEST_DIR}" >&2
  echo "${DEST_LIB}"
  exit 0
fi

echo "Building NSS softoken for ${RID}..." >&2

# NSS's build.sh drives gyp + ninja. It needs `gyp` on PATH (or GYP set); gyp-next installed via
# pip provides it. --system-nspr uses the distro NSPR (libnspr4-dev) instead of building NSPR from a
# sibling ../nspr checkout, and --disable-tests skips the gtest programs we never run.
export GYP="${GYP:-gyp}"
if ! command -v "${GYP}" >/dev/null 2>&1; then
  echo "gyp not found (looked for '${GYP}'). Install gyp-next (pip install gyp-next)." >&2
  exit 1
fi

(
  cd "${SRC_DIR}"
  ./build.sh --opt --system-nspr --disable-tests
) >&2

# build.sh writes to <nss>/../dist, i.e. vendor/dist.
DIST_LIB_DIR="${REPO_ROOT}/vendor/dist/Release/lib"
if [[ ! -f "${DIST_LIB_DIR}/libsoftokn3.so" ]]; then
  echo "build succeeded but libsoftokn3.so not found under ${DIST_LIB_DIR}" >&2
  exit 1
fi

# Stage libsoftokn3 plus the NSS-family libraries it resolves at runtime: libnssutil3 (a DT_NEEDED)
# and the freebl crypto backend softoken dlopens from its own directory. NSPR/sqlite come from the
# system, so they are intentionally not staged.
cp "${DIST_LIB_DIR}/libsoftokn3.so" "${DEST_LIB}"
for lib in libnssutil3.so libfreebl3.so libfreeblpriv3.so libnssdbm3.so; do
  if [[ -f "${DIST_LIB_DIR}/${lib}" ]]; then
    cp "${DIST_LIB_DIR}/${lib}" "${DEST_DIR}/${lib}"
  fi
done

# Best-effort: bake an $ORIGIN runpath so the staged module finds its NSS siblings without
# LD_LIBRARY_PATH (NSS bakes none). CI additionally sets LD_LIBRARY_PATH to the staging dir.
if command -v patchelf >/dev/null 2>&1; then
  patchelf --set-rpath '$ORIGIN' "${DEST_LIB}" || true
fi

echo "Installed ${DEST_LIB}" >&2
echo "${DEST_LIB}"
