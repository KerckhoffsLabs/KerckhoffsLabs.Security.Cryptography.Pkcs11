# KerckhoffsLabs.Security.Cryptography.Pkcs11

[![NuGet](https://img.shields.io/nuget/v/KerckhoffsLabs.Security.Cryptography.Pkcs11)](https://www.nuget.org/packages/KerckhoffsLabs.Security.Cryptography.Pkcs11)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/download/dotnet/10.0)
[![codecov](https://codecov.io/gh/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/graph/badge.svg?token=9N30Z15QRA)](https://codecov.io/gh/KerckhoffsLabs.Security.Cryptography.Pkcs11)

Modern, secure-by-default PKCS#11 v3.2 interop for .NET.

## Requirements

- .NET 10.0 or later

## Installation

```
dotnet add package KerckhoffsLabs.Security.Cryptography.Pkcs11
```

## Building

```bash
git clone --recurse-submodules <repo-url>
cd PKCS11.NET
dotnet build src/KerckhoffsLabs.sln
```

If you already cloned without `--recurse-submodules`:

```bash
git submodule update --init --recursive
```

## Running tests

```bash
dotnet test src/KerckhoffsLabs.sln
```

Tests load `pkcs11-mock` (built from `vendor/pkcs11-mock` as a
submodule). The build is triggered automatically by an MSBuild target
in the test project. On Linux/macOS this requires `make` and `gcc`; on
Windows it requires `pwsh` and MSVC build tools.

## Security model

The high-level API is **secure by default**. Cryptographic operations whose mechanism is
considered insecure are rejected with an `InsecureOperationException` before any call reaches the
token. To use such a mechanism for legacy interop you must opt in explicitly, per workspace:

```csharp
workspace.AllowInsecure = true;               // latched for the workspace lifetime, or
using (workspace.AllowInsecureScope()) { … }  // scoped to a single operation (preferred)
```

The gate (`Pkcs11Session.GuardMechanism`) is mechanism-level and direction-agnostic — it fires the
same way for sign, verify, encrypt, decrypt, derive, digest, and key generation. Gated families
include raw/unauthenticated symmetric modes (ECB, CBC, CTR, …), broken/legacy ciphers (DES/3DES,
RC2, RC4, SEED, CAST, Blowfish, SKIPJACK), broken hashes (MD2/MD5/SHA-1/RIPEMD), PKCS#1 v1.5
*encryption* and raw RSA (`CKM_RSA_PKCS`, `CKM_RSA_X_509`), and sub-128-bit EC curves.

### RSA PKCS#1 v1.5 signatures

The split here is deliberate and along two axes — **broken hash** vs. **dangerous padding use** —
not "v1.5 vs. PSS":

- **Gated:** v1.5 signatures over a broken hash (`CKM_MD5_RSA_PKCS`, `CKM_SHA1_RSA_PKCS`, …) and
  PKCS#1 v1.5 *encryption* / raw RSA (where Bleichenbacher / ROBOT padding-oracle attacks apply).
- **Allowed by default:** strong-hash (SHA-2 / SHA-3) v1.5 *signatures* (`CKM_SHA256_RSA_PKCS` and
  up). RSASSA-PKCS1-v1_5 with a strong hash is FIPS 186-5-approved and is mandated by ubiquitous
  interop — JWT `RS256`, TLS 1.2 `CertificateVerify`, X.509 certificate chains, code signing. Since
  the gate also governs **verification**, gating these would block verifying third-party signatures
  and dilute the meaning of `AllowInsecure`.

Prefer RSA-PSS (`RSASignaturePadding.Pss`) for new code, but a strong-hash v1.5 signature does not
require an insecure opt-in.

## License

MIT — see `LICENSE`.
