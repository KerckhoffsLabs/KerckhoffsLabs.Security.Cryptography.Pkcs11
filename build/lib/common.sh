# Helpers shared by the build/*.sh scripts. Sourced, never run:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# Each function reports to stderr and exits the calling script on failure, which runs with
# `set -euo pipefail`.

# require_args <count> <usage> "$@": exits 2 with "usage: <script> <usage>" unless exactly <count>
# arguments were given.
require_args() {
  local count="$1" usage="$2"
  shift 2
  if [[ $# -ne ${count} ]]; then
    echo "usage: $0 ${usage}" >&2
    exit 2
  fi
}

# require_submodule <path> <name>: exits 1 with how to fetch it unless <path> (a directory, or a
# file that only a checked-out submodule has) exists.
require_submodule() {
  local path="$1" name="$2"
  if [[ ! -e "${path}" ]]; then
    echo "${name} submodule missing at ${path}." >&2
    echo "Run: git submodule update --init --recursive" >&2
    exit 1
  fi
}

# host_rid: prints the .NET runtime identifier of this machine (linux-x64, linux-arm64, osx-x64,
# osx-arm64), the runtimes/<rid>/native directory the test fixtures look in. Fails on any other
# platform; use it as RID="$(host_rid)" so `set -e` stops the script.
host_rid() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}/${arch}" in
    Linux/x86_64)          echo "linux-x64" ;;
    Linux/aarch64)         echo "linux-arm64" ;;
    Darwin/x86_64)         echo "osx-x64" ;;
    Darwin/arm64)          echo "osx-arm64" ;;
    *) echo "unsupported platform: ${os} ${arch}" >&2; return 1 ;;
  esac
}

# fetch_deb <url> <sha256> <work-dir>: downloads a .deb into <work-dir> over HTTPS only, refuses it
# unless its SHA-256 matches, and extracts it under <work-dir>/root. The caller owns <work-dir> and
# removes it.
fetch_deb() {
  local url="$1" sha256="$2" work="$3"
  local deb="${work}/${url##*/}"
  echo "fetching ${url##*/}" >&2
  curl --proto '=https' --proto-redir '=https' -fsSL -o "${deb}" "${url}"
  echo "${sha256}  ${deb}" | sha256sum -c - >&2
  dpkg-deb -x "${deb}" "${work}/root"
  return 0
}

# build_stamp <source-dir>: prints what a build is made from, the source's HEAD commit and the
# calling script's own git blob hash, so a different submodule commit or a changed build script
# both count as a different build. Prints nothing when either cannot be read.
build_stamp() {
  local head script
  head="$(git -C "$1" rev-parse HEAD 2>/dev/null)" || return 0
  script="$(git hash-object "$0" 2>/dev/null)" || return 0
  echo "${head} ${script}"
}

# is_built_from <stamp-file> <stamp> <output>...: succeeds when every <output> exists and
# <stamp-file> records <stamp>, the build_stamp written by record_build after the outputs were
# staged. A file's age is no evidence of what it was built from: a cache can restore an older
# build with a newer timestamp than the commit it was not built from.
is_built_from() {
  local file="$1" stamp="$2"
  shift 2
  [[ -n "${stamp}" && -f "${file}" && "$(cat "${file}")" == "${stamp}" ]] || return 1
  local output
  for output in "$@"; do
    [[ -f "${output}" ]] || return 1
  done
  return 0
}

# record_build <stamp-file> <stamp>: records that the staged outputs were built from <stamp>. Call
# it last, once every output is in place, so an interrupted build is not taken as complete.
record_build() {
  echo "$2" > "$1"
}
