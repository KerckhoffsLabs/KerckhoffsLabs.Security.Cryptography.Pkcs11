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
using var library = Pkcs11Library.Load("/usr/lib/softhsm/libsofthsm2.so");

// 2. Open a logged-in session on a token, selected by label. SecurePin keeps the PIN in a pinned
//    buffer that is zeroed on dispose. Read it from a secret manager, not source — and if you can
//    get it as a char[] rather than a string, pass that: new SecurePin(chars) never makes a string.
using var pin = new SecurePin(Environment.GetEnvironmentVariable("TOKEN_PIN")!);
using var workspace = library.OpenWorkspaceWithPin(slotLabel: "my-token", CKU.CKU_USER, pin);

// 3. Generate a token-resident RSA signing key pair. The private key is non-extractable by default.
using var key = workspace.GenerateRsaSigningKeyPair(modulusBits: 3072, label: "signing-key");

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

The API is **secure by default**. Every workspace enforces a crypto policy — `Recommended` unless you choose
otherwise — that refuses broken algorithms, weak parameters and keys, and reading secrets off the token,
before any call reaches the token:

```csharp
// Default: Recommended.
using var workspace = library.OpenWorkspaceWithPin(slotLabel, CKU.CKU_USER, pin);

// Only NIST-approved functions; overrides refused for the workspace's lifetime.
using var fips = library.OpenWorkspaceWithPin(slotLabel, CKU.CKU_USER, pin, CryptoPolicy.NistApproved);

// Exactly one more thing, reviewed, under your own policy name.
ComposedCryptoPolicy policy = CryptoPolicy.Recommended.ToBuilder("MyApp")
    .AllowSecretExport(SecretExportKind.EcdhSharedSecret, "Z feeds our protocol's key schedule; reviewed.")
    .Build();
```

A refusal throws `CryptoPolicyViolationException` naming the policy and the reason. Keys are generated
non-extractable, with one role each, and legacy algorithms are `[Obsolete]` with their own diagnostic ids.

- [**Security model**](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/security-model.html) — what the library guarantees, its known limits, key role
  separation and wrap hardening.
- [**Using crypto policies**](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/crypto-policies.html) — choosing, widening and tightening a policy,
  reading a secret back, and writing your own.
- [**Legacy algorithms**](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/legacy-algorithms.html) — enabling MD5, SHA-1, DES, 3DES, RC2, DSA, weak
  curves and other legacy mechanisms for interop.
- [**Recommended**](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/policies/recommended.html) and [**NistApproved**](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/policies/nist-approved.html) — exactly
  what each built-in policy allows, and why.

## Documentation

- [**API reference**](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/api/) — the full generated surface.
- [**Security model**](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/security-model.html), [**Using crypto policies**](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/crypto-policies.html) and
  [**Legacy algorithms**](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/legacy-algorithms.html).
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
dotnet test --solution src/KerckhoffsLabs.sln
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
