#!/usr/bin/env bash
# Builds opencryptoki from the vendor/opencryptoki submodule and installs it system-wide
# (default prefix /usr/local) so its slot daemon (pkcsslotd) and software token can run.
#
# Usage: build-opencryptoki.sh
#
# Unlike pkcs11-mock / SoftHSM2 (single .so files loaded in-process and copied next to the
# test assembly), opencryptoki is daemon-backed: the library talks to pkcsslotd over shared
# memory and loads its STDLLs from a fixed layout. So this installs a real tree rather than
# copying one file. Runtime provisioning (pkcs11 group, token store, daemon start, token
# init) is provision-opencryptoki.sh's job.
#
# Layout is split so the runtime paths match a distro package:
#   --prefix=/usr/local       libs + binaries (libopencryptoki.so, pkcsslotd, pkcsconf, ...)
#   --sysconfdir=/etc         config           (/etc/opencryptoki/opencryptoki.conf)
#   --localstatedir=/var      token store/locks (/var/lib/opencryptoki, /var/lock/opencryptoki)
#
# Override PREFIX / SYSCONFDIR / LOCALSTATEDIR via the environment if needed.
#
# Requires (Debian/Ubuntu): build-essential autoconf automake libtool flex bison
#                           libssl-dev libcap-dev libldap2-dev pkg-config
# `make install` needs root (sudo); the pkcs11 group must already exist (make install
# chgrp's the token store to it).
#
# Built out of tree in obj/opencryptoki (bootstrap.sh runs autoreconf, which would leave the
# submodule dirty). That directory carries a stamp of what it was built from, so a restored CI cache
# of it skips straight to `make install`; the install carries its own stamp, so a second run skips
# both. Linux only — opencryptoki is not portable to macOS/Windows.

set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "build-opencryptoki.sh: opencryptoki is Linux-only (got $(uname -s)); nothing to do." >&2
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/vendor/opencryptoki"
BUILD_DIR="${REPO_ROOT}/obj/opencryptoki"

if [[ ! -f "${SRC_DIR}/bootstrap.sh" ]]; then
  echo "opencryptoki submodule missing at ${SRC_DIR}." >&2
  echo "Run: git submodule update --init --recursive" >&2
  exit 1
fi

PREFIX="${PREFIX:-/usr/local}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"
LOCALSTATEDIR="${LOCALSTATEDIR:-/var}"

# `make install` writes outside the source tree, so it needs root. Use sudo only when we are
# not already root (e.g. inside a container running as root has no sudo).
SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then SUDO="sudo"; fi

DAEMON="${PREFIX}/sbin/pkcsslotd"

# NATIVE_SANITIZE=address builds the library, the soft-token STDLL, pkcsslotd and pkcsconf with
# AddressSanitizer (see sanitizer_flags). A process loading libopencryptoki.so must then preload the
# ASan runtime; the daemon and tools link it themselves.
SANITIZE="$(sanitizer_flags)"

# The layout and the OpenSSL are configure arguments baked into the build, so they are part of what
# it is built from, along with the commit, this script and the sanitizer (build_stamp).
STAMP="$(build_stamp "${SRC_DIR}")"
if [[ -n "${STAMP}" ]]; then
  STAMP="${STAMP} prefix=${PREFIX} sysconfdir=${SYSCONFDIR} localstatedir=${LOCALSTATEDIR} openssl=${OPENSSL_PREFIX:-system}"
fi
INSTALL_STAMP_FILE="${PREFIX}/lib/opencryptoki/.built-from"
if is_built_from "${INSTALL_STAMP_FILE}" "${STAMP}" "${DAEMON}"; then
  echo "opencryptoki up to date at ${DAEMON}"
  exit 0
fi
BUILD_STAMP_FILE="${BUILD_DIR}/.built-from"

if is_built_from "${BUILD_STAMP_FILE}" "${STAMP}" "${BUILD_DIR}/Makefile"; then
  echo "opencryptoki already built in ${BUILD_DIR}"
else
  rm -rf "${BUILD_DIR}"
  mkdir -p "${BUILD_DIR}"
  git -C "${SRC_DIR}" archive --format=tar HEAD | tar -x -C "${BUILD_DIR}"

  NPROC="$(nproc 2>/dev/null || echo 4)"
  echo "Building opencryptoki ($(git -C "${SRC_DIR}" describe --tags 2>/dev/null || echo HEAD)) -> ${PREFIX}"

  # Build against a specific OpenSSL when OPENSSL_PREFIX is set (else the system OpenSSL). This matters
  # for the soft token's ML-DSA signing: that code path is gated behind `#ifdef EVP_PKEY_OP_SIGNMSG`,
  # a macro that only exists in OpenSSL >= 3.5 headers. Built against OpenSSL 3.0 headers the sign-message
  # path is compiled out, and at runtime OpenSSL 3.5 rejects the legacy EVP_PKEY_sign_init for ML-DSA, so
  # C_Sign returns CKR_FUNCTION_FAILED. Building against 3.5 headers (and baking an rpath so the daemon
  # and tools load that OpenSSL) compiles the sign-message path in and makes ML-DSA signing work.
  OPENSSL_CONFIGURE_ARGS=()
  if [[ -n "${OPENSSL_PREFIX:-}" && -d "${OPENSSL_PREFIX}" ]]; then
    OPENSSL_CONFIGURE_ARGS+=("--with-openssl=${OPENSSL_PREFIX}")
    # OpenSSL installs to lib64 (with a lib -> lib64 symlink); cover both. Bake an rpath so the
    # built libraries load this OpenSSL at runtime without LD_LIBRARY_PATH (needed for the daemon).
    for libdir in "${OPENSSL_PREFIX}/lib64" "${OPENSSL_PREFIX}/lib"; do
      if [[ -d "${libdir}" ]]; then
        export LDFLAGS="-Wl,-rpath,${libdir} -L${libdir} ${LDFLAGS:-}"
        export PKG_CONFIG_PATH="${libdir}/pkgconfig:${PKG_CONFIG_PATH:-}"
      fi
    done
    echo "Using OpenSSL from ${OPENSSL_PREFIX}"
  fi

  if [[ -n "${SANITIZE}" ]]; then
    export CFLAGS="${SANITIZE} ${CFLAGS:-}" LDFLAGS="${SANITIZE} ${LDFLAGS:-}"
    # configure runs the programs it builds, and LeakSanitizer would fail its feature probes.
    export ASAN_OPTIONS="detect_leaks=0${ASAN_OPTIONS:+:${ASAN_OPTIONS}}"
    echo "Sanitizer: ${NATIVE_SANITIZE}"
  fi

  # bootstrap.sh runs autoreconf in-tree to generate ./configure.
  ( cd "${BUILD_DIR}" && sh ./bootstrap.sh ) 2>&1

  (
    cd "${BUILD_DIR}"
    # Build only what the software token needs. The software token (swtok) is enabled by default
    # and is the only token whose prerequisites (OpenSSL) are met on a stock runner; explicitly
    # disabling the hardware tokens and optional tools keeps the dependency surface minimal and
    # the build deterministic. Keep the default pkcsslotd user (not root): `make install` creates
    # that system user, and the shipped systemd unit's CapabilityBoundingSet strips CAP_SETGID, so
    # a root daemon that calls initgroups() itself fails ("Failed to set the group access list");
    # with a dedicated user, systemd (PID 1) performs the uid/gid switch with its own capabilities.
    ./configure \
      --prefix="${PREFIX}" \
      --sysconfdir="${SYSCONFDIR}" \
      --localstatedir="${LOCALSTATEDIR}" \
      --enable-swtok \
      --disable-icatok \
      --disable-ccatok \
      --disable-ep11tok \
      --disable-tpmtok \
      --disable-icsftok \
      --disable-p11sak \
      --disable-p11kmip \
      --disable-pkcsstats \
      --disable-testcases \
      "${OPENSSL_CONFIGURE_ARGS[@]}"
    make -j"${NPROC}"
  ) 2>&1
  record_build "${BUILD_STAMP_FILE}" "${STAMP}"
fi

${SUDO} make -C "${BUILD_DIR}" install 2>&1
${SUDO} ldconfig 2>/dev/null || true

# `make install` puts the library in ${PREFIX}/lib/opencryptoki. Search ${PREFIX}/lib only when it is
# not there: on a CI runner that tree holds whole toolchains, and a cold search of it takes ~20 s.
# libopencryptoki.so is a symlink to libopencryptoki.so.0.0.0, so don't restrict the search to -type f.
LIB="${PREFIX}/lib/opencryptoki/libopencryptoki.so"
[[ -e "${LIB}" ]] || LIB="$(find "${PREFIX}/lib" -name libopencryptoki.so 2>/dev/null | head -1)"
if [[ -z "${LIB}" || ! -x "${DAEMON}" ]]; then
  echo "build succeeded but libopencryptoki.so / pkcsslotd not found under ${PREFIX}" >&2
  exit 1
fi

if [[ -n "${STAMP}" ]]; then
  echo "${STAMP}" | ${SUDO} tee "${INSTALL_STAMP_FILE}" >/dev/null
fi

echo "Installed ${LIB}"
echo "Installed ${DAEMON}"
"${PREFIX}/sbin/pkcsconf" -V 2>/dev/null || true
