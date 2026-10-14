#!/usr/bin/env bash
# Provisions the opencryptoki software token that build-opencryptoki.sh installed: one soft-token
# slot, its object store, the pkcsslotd daemon, and an initialized token with a user PIN. Prints the
# path of libopencryptoki.so on stdout; everything else goes to stderr.
#
# Usage: provision-opencryptoki.sh
#
# The token label and user PIN come from the same variables, with the same defaults, as the tests'
# Settings: PKCS11_TEST_OPENCRYPTOKI_TOKEN (kl-octk) and PKCS11_TEST_OPENCRYPTOKI_USER_PIN
# (12345678). The SO PIN stays opencryptoki's pre-initialization default, 87654321, which is what
# Settings.OpenCryptokiSoPin expects. These are throwaway values for a CI token, not secrets.
#
# Needs sudo and systemd, and the pkcs11 group (created before build-opencryptoki.sh). Adds the
# current user to that group; a process started afterwards reaches the token store only under
# `sg pkcs11`, since group membership is read at login. Linux only.

set -euxo pipefail

PREFIX="${PREFIX:-/usr/local}"
LABEL="${PKCS11_TEST_OPENCRYPTOKI_TOKEN:-kl-octk}"
USER_PIN="${PKCS11_TEST_OPENCRYPTOKI_USER_PIN:-12345678}"
SO_PIN=87654321
SLOT=0
PKCSCONF="${PREFIX}/sbin/pkcsconf"
export LABEL USER_PIN SO_PIN SLOT PKCSCONF

sudo usermod -a -G pkcs11 "$(id -un)"

# Our minimal build installs only the software-token STDLL (libpkcs11_sw.so). The default config
# declares five slots (TPM/ICA/CCA/SW/EP11); pkcsslotd then spins trying to load the four STDLLs that
# don't exist and never creates its socket, so clients fail C_Initialize with CKR_FUNCTION_FAILED.
# Replace it with a single soft-token slot.
printf 'version opencryptoki-3.27\n\nslot 0\n{\n    stdll = libpkcs11_sw.so\n    tokversion = 3.12\n}\n' \
  | sudo tee /etc/opencryptoki/opencryptoki.conf >/dev/null
{
  echo "=== opencryptoki.conf ==="; cat /etc/opencryptoki/opencryptoki.conf
  echo "=== stdll ==="; ls -la "${PREFIX}/lib/opencryptoki/stdll/" 2>/dev/null || true
} >&2

# The software token's object store must exist and be writable by the pkcs11 group, else the
# soft-token STDLL fails to initialize and C_GetSlotList reports zero tokens.
sudo mkdir -p /var/lib/opencryptoki/swtok/TOK_OBJ
sudo chgrp -R pkcs11 /var/lib/opencryptoki || true
sudo chmod -R g+rwx /var/lib/opencryptoki || true

# Start pkcsslotd via the shipped systemd unit (the same mechanism the distro package uses): it runs
# the daemon as the dedicated pkcsslotd user / pkcs11 group — systemd performs the uid/gid switch with
# its own capabilities, and creates the runtime dirs.
sudo cp "${PREFIX}/lib/systemd/system/pkcsslotd.service" /etc/systemd/system/pkcsslotd.service
sudo systemd-tmpfiles --create 2>/dev/null || true
sudo systemctl daemon-reload
sudo systemctl start pkcsslotd
sleep 2
{
  sudo systemctl --no-pager -l status pkcsslotd || true
  echo "=== pkcsslotd journal ==="; sudo journalctl -u pkcsslotd --no-pager | tail -30 || true
  echo "=== pkcsconf -s ==="; sg pkcs11 -c '"$PKCSCONF" -s'
  echo "=== pkcsconf -t ==="; sg pkcs11 -c '"$PKCSCONF" -t'
} >&2

# pkcsconf -I prompts for the SO PIN, then a token label; -u prompts for the SO PIN, then the new
# user PIN twice. The values reach the commands through the environment, not the command string.
{
  sg pkcs11 -c 'printf "%s\n%s\n" "$SO_PIN" "$LABEL" | "$PKCSCONF" -c "$SLOT" -I'
  sg pkcs11 -c 'printf "%s\n%s\n%s\n" "$SO_PIN" "$USER_PIN" "$USER_PIN" | "$PKCSCONF" -c "$SLOT" -u'
  sg pkcs11 -c '"$PKCSCONF" -t'
  echo "=== mechanisms (pkcsconf -m) ==="; sg pkcs11 -c '"$PKCSCONF" -m -c "$SLOT"' || true
} >&2

LIB="$(find "${PREFIX}/lib" -name libopencryptoki.so 2>/dev/null | head -1)"
if [[ -z "${LIB}" ]]; then
  echo "libopencryptoki.so not found under ${PREFIX}/lib" >&2
  exit 1
fi
echo "${LIB}"
