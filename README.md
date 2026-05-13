# PKCS11.NET

Modern, secure-by-default PKCS#11 v3.1 interop for .NET.

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
