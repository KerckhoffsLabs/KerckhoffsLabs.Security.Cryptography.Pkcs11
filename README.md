# KerckhoffsLabs.Security.Cryptography.Pkcs11

**Modern, secure-by-default PKCS#11 v3.2 interop for .NET.**

[![NuGet](https://img.shields.io/nuget/v/KerckhoffsLabs.Security.Cryptography.Pkcs11)](https://www.nuget.org/packages/KerckhoffsLabs.Security.Cryptography.Pkcs11)
[![Docs](https://img.shields.io/badge/docs-online-2ea44f)](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/download/dotnet/10.0)
[![codecov](https://codecov.io/gh/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/graph/badge.svg?token=4IJFAX88L9)](https://codecov.io/gh/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=KerckhoffsLabs_KerckhoffsLabs.Security.Cryptography.Pkcs11&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=KerckhoffsLabs_KerckhoffsLabs.Security.Cryptography.Pkcs11)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/badge)](https://scorecard.dev/viewer/?uri=github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11)

PKCS#11 is the standard C API for HSMs, smart cards and software tokens. This library wraps a native
PKCS#11 module in an idiomatic .NET API that is hard to hold wrong: keys stay on the token, weak
algorithms are refused, and the adapters drop into code written against `System.Security.Cryptography`.

- **Secure by default.** Unauthenticated cipher modes, broken hashes, PKCS#1 v1.5 encryption and
  sub-128-bit curves are refused before any call reaches the token, and analyzers flag them at compile time.
- **Post-quantum ready.** ML-KEM, ML-DSA and SLH-DSA, alongside RSA, ECDSA, EdDSA and the AEAD suites.
- **BCL-shaped adapters.** `RSAPkcs11 : RSA`, `ECDsaPkcs11 : ECDsa`, `AesGcmPkcs11` and friends.
- **Token-resident keys.** Generated keys are sensitive, non-extractable and granted one role each.
- **PKCS#11 v3.2, backward-compatible.** One API over v2.40, v3.0, v3.1 and v3.2 modules.
- **Safe at the boundary.** `SafeHandle`-backed sessions and objects, zeroized secret buffers, the
  correct `CK_ULONG` width on every platform. NativeAOT- and trim-compatible.

## Installation

```
dotnet add package KerckhoffsLabs.Security.Cryptography.Pkcs11
```

Requires .NET 10 or later, and a PKCS#11 v2.40+ module for your token: your HSM vendor's library, or
[SoftHSM2](https://github.com/opendnssec/SoftHSMv2) for development.

## Quick start

Load the module, log in, generate a non-extractable AES-256 key on the token, and use it through an
`AesGcm`-shaped adapter:

```csharp
using var pin = new SecurePin(Environment.GetEnvironmentVariable("TOKEN_PIN")!); // from your secret store

using Pkcs11Library library = Pkcs11Library.Load(modulePath);
using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);
using Pkcs11Key key = session.GenerateAesKey(bitLength: 256, label: "getting-started");

using var aesGcm = new AesGcmPkcs11(key, tagSizeInBytes: 16);
byte[] nonce = session.GenerateRandom(12);
byte[] ciphertext = new byte[plaintext.Length];
byte[] tag = new byte[16];
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
```

[Getting started](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/guide/getting-started.html) walks through this snippet step by step; it is
compiled and run against real tokens in CI.

## Documentation

- **[Guide](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/guide/getting-started.html)**: getting started, the security model, crypto policies and
  the analyzer diagnostics.
- **[Examples](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/examples/index.html)**: every algorithm next to its `System.Security.Cryptography`
  equivalent, compiled and run in CI.
- **[API reference](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/api/)**: every type and member.

## Building from source

The test backends (`pkcs11-mock`, SoftHSMv2, opencryptoki, NSS, Kryoptic, BouncyHsm) are vendored as git
submodules, so clone recursively (or run `git submodule update --init --recursive` in an existing clone):

```bash
git clone --recurse-submodules https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11.git
cd KerckhoffsLabs.Security.Cryptography.Pkcs11
dotnet build KerckhoffsLabs.sln
dotnet test --solution KerckhoffsLabs.sln
```

The tests build `pkcs11-mock` from its submodule automatically, which needs `make` and `gcc` on Linux and
macOS, or `pwsh` and the MSVC build tools on Windows.

## License

KerckhoffsLabs.Security.Cryptography.Pkcs11 is available under the terms of the [MIT License](https://opensource.org/license/mit).  
A [human-friendly license summary](https://www.tldrlegal.com/license/mit-license) is available on tldrlegal.com, but the [full license text](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/blob/main/LICENSE) always prevails.

## Support

Bug reports and feature requests belong in
[GitHub issues](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/issues).
Built and maintained by [KerckhoffsLabs](https://github.com/KerckhoffsLabs) and contributors.
