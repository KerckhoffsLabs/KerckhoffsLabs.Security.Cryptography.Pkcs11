#!/usr/bin/env bash
# Builds pkcs11-mock as a *static* archive (libpkcs11-mock.a) for linking directly into a host
# executable — the shape a consumer uses when there is no dynamic loading available, and the only
# way to exercise Pkcs11Library.LoadStaticallyLinked() end to end.
#
# Its sibling build-pkcs11-mock.sh builds the shared library the rest of the suite dlopens; this
# one deliberately stays separate, because the archive is consumed by a Native AOT link step
# rather than copied into a test output directory.
#
# Usage: build-pkcs11-mock-static.sh <out-dir>
#   Writes <out-dir>/libpkcs11-mock.a
#
# The archive must be position-independent (-fPIC): Native AOT links a PIE by default, and a
# non-PIC object would fail the link with a relocation error rather than anything self-explanatory.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <out-dir>" >&2
  exit 2
fi

OUT_DIR="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOCK_SRC="${REPO_ROOT}/vendor/pkcs11-mock/src"

if [[ ! -f "${MOCK_SRC}/pkcs11-mock.c" ]]; then
  echo "pkcs11-mock submodule missing at ${MOCK_SRC}." >&2
  echo "Run: git submodule update --init --depth 1 vendor/pkcs11-mock" >&2
  exit 1
fi

case "$(uname -s)" in
  Linux|Darwin) ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

CC="${CC:-cc}"
mkdir -p "${OUT_DIR}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# Same flags the upstream Makefile uses for the shared build, minus the shared-object linking.
"${CC}" -Wall -Wextra -Werror -O2 -fPIC -I"${MOCK_SRC}" \
  -c "${MOCK_SRC}/pkcs11-mock.c" -o "${WORK}/pkcs11-mock.o"

ar rcs "${OUT_DIR}/libpkcs11-mock.a" "${WORK}/pkcs11-mock.o"

echo "Installed ${OUT_DIR}/libpkcs11-mock.a"
