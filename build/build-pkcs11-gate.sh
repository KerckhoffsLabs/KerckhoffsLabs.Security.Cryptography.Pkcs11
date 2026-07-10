#!/usr/bin/env bash
# Builds the pkcs11-gate spec-version-gate shims (see build/pkcs11-gate.c) and copies
# them into the Pkcs11.Tests output directory under the appropriate runtime identifier:
#
#   pkcs11-gate240.so — exports only C_GetFunctionList (a v2.40-only module)
#   pkcs11-gate30.so  — additionally exports a C_GetInterface that serves a
#                       version-rewritten, v3.0-truncated copy of the target's table
#
# Usage: build-pkcs11-gate.sh <test-output-dir>
#
# Idempotent: outputs newer than the source are reused. Skips gracefully (exit 0)
# when the vendored PKCS#11 headers are absent (submodules not initialized) or no
# C compiler is available — the gate-backed tests then skip via their availability
# gate, mirroring how the SoftHSM fixture degrades.
#
# Linux/macOS only: the gate targets the dlopen-based loader path; the Windows legs
# get their spec-version coverage from the hermetic DelegatesLoaderTests.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <test-output-dir>" >&2
  exit 2
fi

OUT_BASE="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${REPO_ROOT}/build/pkcs11-gate.c"
HEADER_DIR="${REPO_ROOT}/vendor/softhsmv2/src/lib/pkcs11"

if [[ ! -f "${HEADER_DIR}/pkcs11.h" ]]; then
  echo "pkcs11-gate: vendored PKCS#11 headers missing (${HEADER_DIR}); skipping gate build." >&2
  exit 0
fi

CC_BIN="${CC:-cc}"
if ! command -v "${CC_BIN}" >/dev/null 2>&1; then
  echo "pkcs11-gate: no C compiler ('${CC_BIN}'); skipping gate build." >&2
  exit 0
fi

UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"
case "${UNAME_S}" in
  Linux)
    case "${UNAME_M}" in
      aarch64|arm64) RID="linux-arm64" ;;
      *)             RID="linux-x64" ;;
    esac
    ;;
  Darwin)
    case "${UNAME_M}" in
      arm64) RID="osx-arm64" ;;
      *)     RID="osx-x64" ;;
    esac
    ;;
  *)
    echo "pkcs11-gate: unsupported platform ${UNAME_S}; skipping gate build." >&2
    exit 0
    ;;
esac

NATIVE_DIR="${OUT_BASE}/runtimes/${RID}/native"
mkdir -p "${NATIVE_DIR}"

build_variant() {
  local out="$1"; shift
  if [[ -f "${out}" && "${out}" -nt "${SRC}" ]]; then
    return 0
  fi
  "${CC_BIN}" -shared -fPIC -O2 -Wall -Wextra -Werror \
    -I "${HEADER_DIR}" "$@" "${SRC}" -o "${out}"
  echo "pkcs11-gate: built ${out}"
}

build_variant "${NATIVE_DIR}/pkcs11-gate240.so" \
  -DGATE_TARGET_ENV='"PKCS11_GATE240_TARGET"'
build_variant "${NATIVE_DIR}/pkcs11-gate30.so" \
  -DGATE_EXPOSE_V30 -DGATE_TARGET_ENV='"PKCS11_GATE30_TARGET"'
