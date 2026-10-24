#!/usr/bin/env bash
# Builds the tpm2-pkcs11 backend image (build/tpm2-pkcs11/Dockerfile) from the vendored submodules.
#
# Usage: build/build-tpm2-pkcs11-image.sh [image tag]   (default: kerckhoffslabs/tpm2-pkcs11:local)
#
# Each source is passed as a named build context, so the image is built from exactly the submodule
# commits and the build context is only build/tpm2-pkcs11. The tpm2-pkcs11 and tpm2-abrmd versions come from the
# submodules, since the bootstraps of tpm2-pkcs11 and tpm2-abrmd can't run git describe inside the build.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tag="${1:-kerckhoffslabs/tpm2-pkcs11:local}"

for module in json-glib libtpms swtpm tpm2-abrmd tpm2-pkcs11; do
    if [[ ! -e "$repo/vendor/$module/.git" ]]; then
        echo "vendor/$module is not checked out: git submodule update --init vendor/$module" >&2
        exit 1
    fi
done

docker build \
    --build-context json-glib="$repo/vendor/json-glib" \
    --build-context libtpms="$repo/vendor/libtpms" \
    --build-context swtpm="$repo/vendor/swtpm" \
    --build-context tpm2-abrmd="$repo/vendor/tpm2-abrmd" \
    --build-context tpm2-pkcs11="$repo/vendor/tpm2-pkcs11" \
    --build-arg TPM2_ABRMD_VERSION="$(git -C "$repo/vendor/tpm2-abrmd" describe --tags --always)" \
    --build-arg TPM2_PKCS11_VERSION="$(git -C "$repo/vendor/tpm2-pkcs11" describe --tags --always)" \
    --tag "$tag" \
    "$repo/build/tpm2-pkcs11"
