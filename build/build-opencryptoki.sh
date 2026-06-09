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
# init) is the caller's job — see the opencryptoki job in .github/workflows/ci.yml.
#
# Layout is split so the runtime paths match a distro package:
#   --prefix=/usr/local       libs + binaries (libopencryptoki.so, pkcsslotd, pkcsconf, ...)
#   --sysconfdir=/etc         config           (/etc/opencryptoki/opencryptoki.conf)
#   --localstatedir=/var      token store/locks (/var/lib/opencryptoki, /var/lock/opencryptoki)
#
# Override PREFIX / SYSCONFDIR / LOCALSTATEDIR via the environment if needed.
#
# Requires (Debian/Ubuntu): build-essential autoconf automake libtool flex bison
#                           libssl-dev libcap-dev pkg-config
# `make install` needs root (sudo); the pkcs11 group must already exist (make install
# chgrp's the token store to it).
#
# Linux only — opencryptoki is not portable to macOS/Windows. Idempotent: skips the rebuild
# when the installed pkcsslotd is newer than the submodule HEAD commit.

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "build-opencryptoki.sh: opencryptoki is Linux-only (got $(uname -s)); nothing to do." >&2
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/vendor/opencryptoki"

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

# Skip the rebuild when the installed daemon is newer than the submodule HEAD commit.
HEAD_TS="$(git -C "${SRC_DIR}" log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
_ts() { local f="$1"; [[ -f "$f" ]] && stat -c %Y "$f" 2>/dev/null || echo 0; }
if (( "$(_ts "${DAEMON}")" > HEAD_TS )); then
  echo "opencryptoki up to date at ${DAEMON}"
  exit 0
fi

NPROC="$(nproc 2>/dev/null || echo 4)"
echo "Building opencryptoki ($(git -C "${SRC_DIR}" describe --tags 2>/dev/null || echo HEAD)) -> ${PREFIX}"

# bootstrap.sh runs autoreconf in-tree to generate ./configure.
( cd "${SRC_DIR}" && sh ./bootstrap.sh ) 2>&1

(
  cd "${SRC_DIR}"
  # Build only what the software token needs. The software token (swtok) is enabled by default
  # and is the only token whose prerequisites (OpenSSL) are met on a stock runner; explicitly
  # disabling the hardware tokens and optional tools keeps the dependency surface minimal and
  # the build deterministic. Run the daemon as root (no separate pkcsslotd system user to
  # provision on an ephemeral CI host).
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
    --with-pkcsslotd-user=root
  make -j"${NPROC}"
) 2>&1

${SUDO} make -C "${SRC_DIR}" install 2>&1
${SUDO} ldconfig 2>/dev/null || true

LIB="$(find "${PREFIX}" -name libopencryptoki.so -type f 2>/dev/null | head -1)"
if [[ -z "${LIB}" || ! -x "${DAEMON}" ]]; then
  echo "build succeeded but libopencryptoki.so / pkcsslotd not found under ${PREFIX}" >&2
  exit 1
fi

echo "Installed ${LIB}"
echo "Installed ${DAEMON}"
"${PREFIX}/sbin/pkcsconf" -V 2>/dev/null || true
