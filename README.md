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

Tests load `pkcs11-mock` (built from `third-party/pkcs11-mock` as a
submodule). The build is triggered automatically by an MSBuild target
in the test project. On Linux/macOS this requires `make` and `gcc`; on
Windows it requires `pwsh` and MSVC build tools.

## License

MIT — see `LICENSE`.
