# syntax=docker/dockerfile:1
#
# The tpm2-pkcs11 backend: tpm2-pkcs11 over a software TPM (swtpm), with the .NET runtime to run the
# test assembly. Built by build/build-tpm2-pkcs11-image.sh, which passes each vendored source as a
# named build context (--build-context json-glib=vendor/json-glib, ...), so the image is built from
# the submodule commits and the build context stays small.
#
# Wolfi packages tpm2-tss and .NET, but not swtpm, its libtpms and json-glib dependencies,
# tpm2-abrmd, tpm2-pkcs11, wolfTPM (with its wolfSSL), the TCG reference TPM or IBM's simulator, so those are built in
# the first stage and installed under /opt/tpm2.
# The second stage takes their libraries and the programs the fixture runs only. wolfi-base:latest is both stages' base: it has apk
# and a shell, and Chainguard publishes no latest-dev tag of it.

ARG WOLFI=cgr.dev/chainguard/wolfi-base:latest

FROM ${WOLFI} AS build

RUN apk add --no-cache \
        autoconf autoconf-archive automake bash build-base gawk libtool meson ninja-build patch pkgconf pkgconf-dev \
        dbus-dev glib-dev gmp-dev libtasn1-dev openssl-dev sqlite-dev tpm2-tss-dev yaml-dev

ENV PKG_CONFIG_PATH=/opt/tpm2/lib/pkgconfig
WORKDIR /src

# json-glib, for swtpm. Only the library: no introspection data, documentation, tools or tests.
COPY --from=json-glib . json-glib
RUN cd json-glib \
    && meson setup _build --prefix=/opt/tpm2 --libdir=lib --buildtype=release \
        -Dintrospection=disabled -Ddocumentation=disabled -Dman=false -Dtests=false -Dnls=disabled \
    && ninja -C _build install

# libtpms: the TPM 2.0 implementation swtpm runs.
COPY --from=libtpms . libtpms
RUN cd libtpms \
    && NOCONFIGURE=1 ./autogen.sh \
    && ./configure --prefix=/opt/tpm2 --with-openssl --with-tpm2 --disable-static \
    && make -j"$(nproc)" \
    && make install

# swtpm: the fixture runs only its socket TPM. No CUSE device, no swtpm_setup certificates (GnuTLS),
# no seccomp profile and no test suite; swtpm_localca still builds, and needs GMP.
COPY --from=swtpm . swtpm
RUN cd swtpm \
    && NOCONFIGURE=1 ./autogen.sh \
    && ./configure --prefix=/opt/tpm2 --with-openssl --without-cuse --without-gnutls --without-seccomp \
        --without-selinux --disable-tests --disable-static \
    && make -j"$(nproc)" \
    && make install

# tpm2-abrmd, the resource manager between tpm2-pkcs11 and the TPM. A TPM holds only three transient
# objects and a few sessions at a time, and tpm2-pkcs11 keeps one connection open for the process and
# relies on a resource manager to swap them in and out (on a real machine, the kernel's /dev/tpmrm0);
# without one the TPM soon runs out of object memory. Its bootstrap names the version as
# tpm2-pkcs11's does. No systemd unit; the fixture starts it on a private session bus.
ARG TPM2_ABRMD_VERSION=unknown
COPY --from=tpm2-abrmd . tpm2-abrmd
RUN cd tpm2-abrmd \
    && printf '%s\n' "${TPM2_ABRMD_VERSION}" > VERSION \
    && sed -i '/git describe/d' bootstrap \
    && ./bootstrap \
    && ./configure --prefix=/opt/tpm2 --with-dbuspolicydir=/opt/tpm2/share/dbus-1/system.d \
        --with-systemdsystemunitdir=no --with-systemdpresetdir=no --disable-static \
    && make -j"$(nproc)" \
    && make install

# wolfSSL, the cryptography under wolfTPM's firmware TPM: the second TPM the fixture can run, so the
# backend is exercised against two independent TPM 2.0 implementations (libtpms in swtpm, and this).
# The options are the ones wolfTPM's own fwTPM CI builds it with. Library only. wolfSSL builds with
# -Werror, and Wolfi's GCC 16 takes SetObjectId's guarded write (asn.c, `if (output) output[idx] = ...`)
# for a write through a null pointer once inlined into wc_EncodeRsaPssAlgoId; that one warning is
# kept a warning. WC_RSA_NO_PADDING gives fwTPM's TPM2_RSA_Decrypt its TPM_ALG_NULL (raw RSA) scheme,
# which tpm2-pkcs11 pads PKCS#1 v1.5 over. ML-KEM and ML-DSA are for the fwTPM builds with TPM 2.0 v1.85
# (below).
COPY --from=wolfssl . wolfssl
RUN cd wolfssl \
    && ./autogen.sh \
    && ./configure --prefix=/opt/tpm2 --enable-wolftpm --enable-pkcallbacks --enable-keygen --enable-mlkem --enable-mldsa \
        CFLAGS="-O2 -Wno-error=stringop-overflow -DWC_RSA_NO_PADDING" \
        --disable-examples --disable-crypttests --disable-benchmark --disable-static \
    && make -j"$(nproc)" \
    && make install

# wolfTPM's fwTPM, as a server speaking the swtpm/mssim socket protocol (fwtpm_server). Only the
# server: no client library, examples or tests. Its TPM2_ContextSave of an object keeps only a reference
# to it, which TPM2_ContextLoad can't load once the object is flushed, so it can't sit behind a resource
# manager (tpm2-abrmd, or the kernel's /dev/tpmrm0), which saves and flushes objects between commands.
# The fixture therefore connects tpm2-pkcs11 to it directly, and it is built to hold 128 transient
# objects at a time, not 3, for tpm2-pkcs11's one connection.
#
# wolftpm-param-enc-authvalue.patch: fwTPM left the authorized entity's authValue out of the
# parameter-encryption key unless the session was bound to that entity, where tpm2-tss (and TPM 2.0
# Part 1) include it. A response encrypted in a session bound to one object and authorizing another (as
# tpm2-pkcs11 unseals its wrapping key) then decrypted to garbage on the client.
#
# wolftpm-objectchangeauth.patch: fwTPM's TPM2_ObjectChangeAuth also gave the loaded object the new
# authValue, where Part 3 only returns it in outPrivate. The response HMAC was then computed with the new
# authValue, which the client rejects (as tpm2-pkcs11's C_SetPIN does), and the loaded object no longer
# took the old one.
#
# wolftpm-crypto-conformance.patch: where fwTPM departs from Part 1 and Part 3 in ways tpm2-pkcs11
# meets: TPM2_RSA_Decrypt ignored the OAEP label and had no SHA-512 hash or SHA-1 MGF for OAEP;
# ECDSA r and s came back at their minimal length, not padded to the curve size (so most P-521
# signatures were short); and TPM2_EncryptDecrypt(2) refused every mode for a key whose mode is
# TPM_ALG_NULL, where Part 3 lets such a key take any mode; and TPM2_GetCapability(TPM2_CAP_ALGS) left out
# SHA-1 and SHA-512, which it implements, so tpm2-pkcs11 took them for missing.
#
# Reported upstream as wolfSSL/wolfTPM#648 to #653 where master still has them.
#
# Two servers: fwtpm_server, the TPM 2.0 v1.84 one (v1.85 explicitly off: wolfTPM turns it on by
# itself when wolfSSL has ML-KEM and ML-DSA, as this one does); and fwtpm_server-v185 (--enable-v185:
# the v1.85 Library Specification, ML-KEM and ML-DSA with its new commands, response codes and capability
# properties). --enable-pqc, the lean ML-KEM/ML-DSA subset, builds the same fwTPM: configure promotes
# it to --enable-v185 ("fwTPM requires full v1.85"). The fixture runs whichever PKCS11_TEST_FWTPM names. tpm2-tss has no v1.85 support yet, so tpm2-pkcs11
# uses only what the earlier versions have on each.
COPY --from=wolftpm . wolftpm
COPY wolftpm-param-enc-authvalue.patch wolftpm-objectchangeauth.patch wolftpm-crypto-conformance.patch /src/
RUN cd wolftpm \
    && patch -p1 < /src/wolftpm-param-enc-authvalue.patch \
    && patch -p1 < /src/wolftpm-objectchangeauth.patch \
    && patch -p1 < /src/wolftpm-crypto-conformance.patch \
    && ./autogen.sh \
    && for build in classic v185; do \
        case "$build" in \
            classic) spec="--disable-v185 --disable-pqc"; name=fwtpm_server ;; \
            v185) spec="--enable-v185"; name=fwtpm_server-v185 ;; \
        esac; \
        ./configure --prefix=/opt/tpm2 --with-wolfcrypt=/opt/tpm2 --enable-fwtpm-only --enable-swtpm --disable-static $spec \
            CFLAGS="-O2 -DFWTPM_MAX_OBJECTS=128" \
        && make -j"$(nproc)" \
        && install -D -m 0755 src/fwtpm/fwtpm_server /opt/tpm2/bin/$name \
        && make distclean \
        || exit 1; \
    done

# The TCG's TPM 2.0 reference implementation, as its simulator (tpm2-simulator, speaking the mssim
# protocol): the third TPM the fixture can run, the one the specification itself describes. Built with
# its autotools files, which upstream keeps for the move to CMake but no longer supports (CMake on Linux
# is experimental and installs in stages); two patches make them build here:
#
# tcg-tpm-openssl-4.patch: the reference code reaches into OpenSSL's private struct bignum_st, so it
# refuses an OpenSSL newer than the ones checked (up to 3.5). Wolfi has 4.0; the struct is unchanged
# in 4.0.3's crypto/bn/bn_local.h, so the check is moved past 4.0.
#
# tcg-tpm-autotools-vendor-command.patch: the autotools build leaves out the vendor command handler
# (Vendor_TCG_Test.c) the CMake build links, so the simulator didn't link.
#
# Neither is reported upstream. OpenSSL 3.0 deprecated some of what it calls; those warnings stay warnings.
COPY --from=tcg-tpm . tcg-tpm
COPY tcg-tpm-openssl-4.patch tcg-tpm-autotools-vendor-command.patch /src/
RUN cd tcg-tpm \
    && patch -p1 < /src/tcg-tpm-openssl-4.patch \
    && patch -p1 < /src/tcg-tpm-autotools-vendor-command.patch \
    && cd TPMCmd \
    && ./bootstrap \
    && ./configure \
    && make -j"$(nproc)" \
    && install -D -m 0755 Simulator/src/tpm2-simulator /opt/tpm2/bin/tpm2-simulator

# IBM's TPM 2.0 simulator (ibmswtpm2's tpm_server, speaking the mssim protocol), the fourth TPM the
# fixture can run: separately maintained from the TCG code, and the one tpm2-tss's own CI uses. Built
# with its makefile, optimised (it builds with -O0 for debugging, which more than doubles the suite's
# run); the submodule is past its last tag (2022) for the OpenSSL 4 support.
COPY --from=ibmswtpm2 . ibmswtpm2
RUN cd ibmswtpm2/src \
    && sed -i 's/-O0/-O2/' makefile \
    && make -j"$(nproc)" \
    && install -D -m 0755 tpm_server /opt/tpm2/bin/tpm_server

# tpm2-pkcs11. Its bootstrap names the version with git describe, which needs the repository the
# submodule lives in; the build script passes it instead. Both store backends are built: the SQLite one
# (esysdb), the fixture's default, and FAPI (PKCS11_TEST_TPM2_BACKEND=fapi), which the fixture provisions. The fixture provisions its token with C_InitToken, so
# tpm2_ptool and its Python modules aren't needed.
ARG TPM2_PKCS11_VERSION=unknown
COPY --from=tpm2-pkcs11 . tpm2-pkcs11
RUN cd tpm2-pkcs11 \
    && printf '%s\n' "${TPM2_PKCS11_VERSION}" > VERSION \
    && sed -i '/git describe/d' bootstrap \
    && ./bootstrap \
    && ./configure --prefix=/opt/tpm2 --with-fapi=yes --disable-ptool-checks --disable-static \
    && make -j"$(nproc)" \
    && make install

FROM ${WOLFI}

RUN apk add --no-cache dbus dotnet-10-runtime glib libtasn1 openssl sqlite-libs tpm2-tss yaml

# Of the programs, only the ones the fixture runs: no certificate or setup tools.
COPY --from=build /opt/tpm2/bin/swtpm /opt/tpm2/bin/swtpm
COPY --from=build /opt/tpm2/bin/fwtpm_server /opt/tpm2/bin/fwtpm_server-v185 /opt/tpm2/bin/
COPY --from=build /opt/tpm2/bin/tpm2-simulator /opt/tpm2/bin/tpm2-simulator
COPY --from=build /opt/tpm2/bin/tpm_server /opt/tpm2/bin/tpm_server
COPY --from=build /opt/tpm2/sbin/tpm2-abrmd /opt/tpm2/bin/tpm2-abrmd
COPY --from=build /opt/tpm2/lib /opt/tpm2/lib

# The fixture starts the TPM (swtpm, fwtpm_server, tpm2-simulator or tpm_server), a D-Bus session bus and tpm2-abrmd itself, and loads tpm2-pkcs11 from
# here (see Tpm2Pkcs11BackendFixture).
ENV PATH=/opt/tpm2/bin:$PATH \
    LD_LIBRARY_PATH=/opt/tpm2/lib \
    PKCS11_TEST_TPM2_PKCS11_LIBRARY=/opt/tpm2/lib/libtpm2_pkcs11.so \
    PKCS11_TEST_SWTPM=/opt/tpm2/bin/swtpm \
    PKCS11_TEST_FWTPM=/opt/tpm2/bin/fwtpm_server \
    PKCS11_TEST_TCGTPM=/opt/tpm2/bin/tpm2-simulator \
    PKCS11_TEST_IBMTPM=/opt/tpm2/bin/tpm_server \
    PKCS11_TEST_FAPI_PROFILES=/usr/etc/tpm2-tss/fapi-profiles/ \
    PKCS11_TEST_TPM2_ABRMD=/opt/tpm2/bin/tpm2-abrmd \
    PKCS11_TEST_DBUS_DAEMON=/usr/bin/dbus-daemon \
    DOTNET_CLI_TELEMETRY_OPTOUT=1

# Wolfi's images run as the unprivileged nonroot user (65532); so do the tests.
USER 65532
WORKDIR /work
