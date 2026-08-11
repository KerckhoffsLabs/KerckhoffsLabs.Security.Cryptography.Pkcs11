# KerckhoffsLabs.Security.Cryptography.Pkcs11

**Modern, secure-by-default PKCS#11 v3.2 interop for .NET.**

[![NuGet](https://img.shields.io/nuget/v/KerckhoffsLabs.Security.Cryptography.Pkcs11)](https://www.nuget.org/packages/KerckhoffsLabs.Security.Cryptography.Pkcs11)
[![Docs](https://img.shields.io/badge/docs-online-2ea44f)](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/download/dotnet/10.0)
[![codecov](https://codecov.io/gh/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/graph/badge.svg?token=4IJFAX88L9)](https://codecov.io/gh/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=KerckhoffsLabs_KerckhoffsLabs.Security.Cryptography.Pkcs11&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=KerckhoffsLabs_KerckhoffsLabs.Security.Cryptography.Pkcs11)

## Overview

PKCS#11 (Cryptoki) is the standard C API for talking to HSMs, smart cards, and software tokens. Using
it from .NET means marshalling handles, mechanism structs, and fixed-width `CK_ULONG` values across
the managed/unmanaged boundary — where a wrong struct layout is silent memory corruption and a wrong
default is a production vulnerability nobody sees until it is exploited.

This library wraps a native PKCS#11 module in an idiomatic .NET surface that is hard to hold wrong.

- **Secure by default** — insecure mechanisms (unauthenticated cipher modes, broken hashes, PKCS#1
  v1.5 encryption, sub-128-bit curves) are rejected before any call reaches the token, and must be
  opted into explicitly. Compile-time analyzers warn about them where a runtime gate cannot.
- **PKCS#11 v3.2, backward-compatible** — a single managed API over v2.40, v3.0, v3.1, and v3.2
  modules; the right calling convention is negotiated for you, and v3.2-only calls degrade cleanly on
  older tokens.
- **Post-quantum ready** — ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205), alongside
  RSA, ECDSA, EdDSA, and the AEAD suites.
- **BCL-shaped adapters** — `RSAPkcs11 : RSA`, `ECDsaPkcs11 : ECDsa`, `AesGcmPkcs11`, `MLKemPkcs11`,
  and friends drop into code already written against `System.Security.Cryptography`.
- **Token-resident keys** — private keys stay non-extractable and operations run on the token by
  default; you choose deliberately if you ever want otherwise.
- **Safe at the boundary** — `SafeHandle`-backed sessions and objects, deterministic disposal,
  zeroized secret buffers, and correct `CK_ULONG` width on every platform (4 bytes on 64-bit Windows,
  8 bytes on 64-bit Unix). NativeAOT- and trim-compatible.

## Installation

```
dotnet add package KerckhoffsLabs.Security.Cryptography.Pkcs11
```

Requires .NET 10.0 or later, and a PKCS#11 v2.40+ module for your token (e.g. your HSM vendor's
library, or [SoftHSM2](https://github.com/opendnssec/SoftHSMv2) for development).

## Quick start

Load a module, log into a token, generate a key pair, and sign — end to end:

```csharp
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

// 1. Load the native module (initialization and finalization are tied to the object's lifetime).
using var library = new Pkcs11Library("/usr/lib/softhsm/libsofthsm2.so");

// 2. Open a logged-in session on a token, selected by label. The PIN is held in a pinned,
//    zeroized buffer — never a string. Read it from a secret manager, not source.
using var pin = new SecurePin(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("TOKEN_PIN")!));
using var workspace = library.OpenWorkspace(slotLabel: "my-token", CKU.CKU_USER, pin);

// 3. Generate a token-resident RSA key pair. The private key is non-extractable by default.
using var key = workspace.GenerateRsaKeyPair(modulusBits: 3072, label: "signing-key");

// 4. Sign and verify through the familiar System.Security.Cryptography shape (RSA-PSS by default).
using var rsa = new RSAPkcs11(key);
byte[] message = Encoding.UTF8.GetBytes("hello, token");
byte[] signature = rsa.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
bool ok = rsa.VerifyData(message, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
```

Reach for an existing key by label instead of generating one with `workspace.OpenKey("signing-key")`,
and see the [documentation](#documentation) for encryption, wrapping, key derivation, and the
post-quantum mechanisms.

### Error handling

Every exception this library raises derives from `System.Security.Cryptography.CryptographicException`,
so code written against the BCL shapes above — including generic wrappers that have never heard of
PKCS#11 — catches token failures where it already catches everything else:

```csharp
try { rsa.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pss); }
catch (Pkcs11Exception ex) { logger.LogError("{Method} returned {Ckr}", ex.Method, ex.ReturnValue); }
catch (CryptographicException ex) { /* everything else, including a plain BCL failure */ }
```

Narrow to `Pkcs11Exception` when you want the raw `CKR` and the failing PKCS#11 method, or to one of
its typed subclasses (`Pkcs11AuthenticationException`, `Pkcs11SessionException`, …) to catch by
category.

## Security model

The high-level API is **secure by default**. A cryptographic operation whose mechanism is considered
insecure is rejected with an `InsecureOperationException` before any call reaches the token. To use
one for legacy interop you opt in explicitly, per workspace:

```csharp
workspace.AllowInsecure = true;               // latched for the workspace lifetime, or
using (workspace.AllowInsecureScope()) { … }  // scoped to a single operation (preferred)
```

The gate is mechanism-level and direction-agnostic — it fires the same way for sign, verify, encrypt,
decrypt, derive, digest, and key generation. Gated families include unauthenticated symmetric modes
(ECB, CBC, CTR, …), broken/legacy ciphers (DES/3DES, RC2, RC4, SEED, CAST, Blowfish, SKIPJACK),
broken hashes (MD2/MD5/SHA-1/RIPEMD), PKCS#1 v1.5 *encryption* and raw RSA (`CKM_RSA_PKCS`,
`CKM_RSA_X_509`), and sub-128-bit EC curves. Where the insecure choice is visible at compile time,
[analyzers](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html)
(`KLPKCS11001`–`KLPKCS11010`) surface it as a build warning too.

**RSA PKCS#1 v1.5 signatures are a deliberate exception.** Strong-hash v1.5 *signatures*
(`CKM_SHA256_RSA_PKCS` and up) are allowed by default: RSASSA-PKCS1-v1_5 with a strong hash is
FIPS 186-5-approved and mandated by ubiquitous interop — JWT `RS256`, TLS 1.2 `CertificateVerify`,
X.509 chains, code signing — and because the gate also governs verification, blocking them would
break verifying third-party signatures. Only v1.5 over a *broken hash*, and v1.5 *encryption* / raw
RSA (Bleichenbacher / ROBOT territory), are gated. Prefer RSA-PSS for new code all the same.

### Wrap hardening

Keys are non-extractable by default, which closes the direct exfiltration path. For a key
deliberately made wrappable, PKCS#11 offers four defence-in-depth controls, all available as
builder helpers:

```csharp
using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
    .ValueLen(32)
    .Wrap()
    .WrapWithTrusted()                      // only a CKA_TRUSTED key may wrap this one
    .WrapTemplate(t => t                    // ...and only keys matching this may be wrapped
        .Class(CKO.CKO_SECRET_KEY)
        .Sensitive()
        .NonExtractable())
    .UnwrapTemplate(t => t                  // keys arriving through this one are born hardened
        .Sensitive()
        .NonExtractable())
    .Build();
```

The two nested templates look alike and mean opposite things — this is the part worth reading
twice:

- **`WrapTemplate` is a filter.** Keys that do not match it *cannot be wrapped* by this key. It
  narrows what this key can be used to exfiltrate.
- **`UnwrapTemplate` is an imposition.** Its attributes are applied to every key unwrapped with
  this key, as if the object already carried them, before any caller-supplied template. It
  constrains what can be smuggled *in* — for example, forcing an arriving key to be
  non-extractable so it cannot be immediately re-exported in the clear.

`DeriveTemplate` works like `UnwrapTemplate`, for keys produced by derivation.

Nested templates carry no secure defaults, deliberately: an attribute you did not write must never
silently change which keys a wrapping key will accept.

**`Trusted()` is SO-only.** PKCS#11 allows `CKA_TRUSTED` to be set to true only by the security
officer. Setting it from a normal user session is rejected by a conformant token with
`CKR_ATTRIBUTE_READ_ONLY`. The library does not gate this locally — it cannot know which user type
opened the session, and refusing at build time would be wrong for SO sessions.

## Documentation

- [**API reference**](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/api/) — the full generated surface.
- [**Diagnostics**](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html) — the obsoletion and analyzer diagnostic ids, and how to suppress one precisely.

## Building from source

The repository vendors its test backends (`pkcs11-mock`, SoftHSMv2, opencryptoki) as git submodules,
so clone recursively:

```bash
git clone --recurse-submodules https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11.git
cd KerckhoffsLabs.Security.Cryptography.Pkcs11
dotnet build src/KerckhoffsLabs.sln
```

If you already cloned without submodules, run `git submodule update --init --recursive` first.

```bash
dotnet test src/KerckhoffsLabs.sln
```

Tests build `pkcs11-mock` from the vendored submodule automatically via an MSBuild target — this
needs `make` and `gcc` on Linux/macOS, or `pwsh` and the MSVC build tools on Windows.

## License

MIT — see [LICENSE](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/blob/main/LICENSE).

## Support

Bug reports and feature requests belong in
[GitHub issues](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/issues).

## About

Built and maintained by [KerckhoffsLabs](https://github.com/KerckhoffsLabs) and contributors.
