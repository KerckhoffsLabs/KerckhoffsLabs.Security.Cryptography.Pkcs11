#!/usr/bin/env bash
# Builds BouncyHsm from the vendor/bouncyhsm submodule: the server (portable net10.0) and the native
# PKCS#11 client, staged where BouncyHsmBackendFixture looks for them. Linux x64 only: the BouncyHsm
# backend is supported there and nowhere else.
#
# Usage: build-bouncyhsm.sh <test-output-dir>
#
# Outputs (relative to <test-output-dir>):
#   bouncyhsm/server/BouncyHsm.dll                     (+ the rest of the publish output)
#   bouncyhsm/runtimes/linux-x64/native/BouncyHsm.Pkcs11Lib.so
#
# Idempotent: skips the rebuild when the staged outputs were built from this submodule commit by
# this script (see is_built_from). On any other platform it prints "skipped" and exits 0; the fixture
# then reports the backend unavailable and its tests skip.

set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_args 1 "<test-output-dir>" "$@"

OUT_BASE="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/vendor/bouncyhsm"

require_submodule "${SRC_DIR}/src/Src/BouncyHsm/BouncyHsm.csproj" bouncyhsm

RID="$(host_rid)"
case "${RID}" in
  linux-x64) MAKE_DIR="build_linux"; MAKE_TARGET="build64";                            BUILT="BouncyHsm.Pkcs11Lib-x64.so";         STAGED="BouncyHsm.Pkcs11Lib.so" ;;
  *) echo "build-bouncyhsm.sh: the BouncyHsm backend is supported on linux-x64 only, not ${RID}; skipped." >&2; exit 0 ;;
esac

BH_OUT="${OUT_BASE}/bouncyhsm"
SERVER_DIR="${BH_OUT}/server"
NATIVE_DIR="${BH_OUT}/runtimes/${RID}/native"
DEST_LIB="${NATIVE_DIR}/${STAGED}"

STAMP_FILE="${BH_OUT}/.built-from"
STAMP="$(build_stamp "${SRC_DIR}")"
if is_built_from "${STAMP_FILE}" "${STAMP}" "${SERVER_DIR}/BouncyHsm.dll" "${DEST_LIB}"; then
  echo "bouncyhsm up to date at ${BH_OUT}"
  exit 0
fi
rm -f "${STAMP_FILE}"
mkdir -p "${SERVER_DIR}" "${NATIVE_DIR}"

echo "Publishing BouncyHsm server..."
# This runs inside the test project's `dotnet build` (an MSBuild Exec). The outer build's MSBuild
# variables would otherwise steer the nested SDK at the outer MSBuild; clear them so the vendored
# publish resolves its own SDK through the repo's global.json like a fresh shell would.
(
  unset MSBuildExtensionsPath MSBuildSDKsPath MSBUILD_EXE_PATH MSBuildLoadMicrosoftTargetsReadOnly
  dotnet publish "${SRC_DIR}/src/Src/BouncyHsm/BouncyHsm.csproj" -c Release -o "${SERVER_DIR}" -nologo -v q
) 2>&1

echo "Building BouncyHsm native client for ${RID}..."
# Upstream's Makefile defaults to clang; `cc` is whatever the runner's toolchain provides
# (gcc on ubuntu-latest's build-essential).
make -C "${SRC_DIR}/${MAKE_DIR}" CC=cc "${MAKE_TARGET}" 2>&1

SRC_LIB="${SRC_DIR}/${MAKE_DIR}/${BUILT}"
if [[ ! -f "${SRC_LIB}" ]]; then
  echo "build succeeded but ${SRC_LIB} not found" >&2; exit 1
fi
cp "${SRC_LIB}" "${DEST_LIB}"

record_build "${STAMP_FILE}" "${STAMP}"
echo "Installed ${SERVER_DIR} and ${DEST_LIB}"
