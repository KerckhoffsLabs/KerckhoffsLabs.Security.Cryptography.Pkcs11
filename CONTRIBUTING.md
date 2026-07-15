# How to contribute

**Please note that according to the [KerckhoffsLabs.Security.Cryptography.Pkcs11 license](LICENSE) all code and content intentionally submitted for inclusion is covered by the [MIT License](https://opensource.org/licenses/MIT).**

## General feedback and feature requests

Please start a discussion in the [KerckhoffsLabs.Security.Cryptography.Pkcs11 issue tracker](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/issues).

## Reporting problems

Before you report a problem please make sure you have tried to find the solution by:

* exploring the [KerckhoffsLabs.Security.Cryptography.Pkcs11 documentation](https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/)
* searching for similar topics in the [KerckhoffsLabs.Security.Cryptography.Pkcs11 issue tracker](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/issues)

If you have already done that and your problem still persists then please register a new issue in the [KerckhoffsLabs.Security.Cryptography.Pkcs11 issue tracker](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/issues). The best way to get your problem fixed is to be as detailed as you can be about it so please make sure that the registered issue includes (if applicable):

* the version of KerckhoffsLabs.Security.Cryptography.Pkcs11 you are using
* the PKCS#11 module you are using — the vendor and product (e.g. SoftHSMv2, opencryptoki, a specific HSM) and its version, and the Cryptoki spec version it reports (v2.40 / v3.0 / v3.1 / v3.2)
* the version and architecture of the operating system you are using (32-bit vs 64-bit matters for native `CK_ULONG` width — 4 bytes on 64-bit Windows, 8 bytes on 64-bit Unix)
* whether you are running on the JIT or NativeAOT
* the mechanism, function, or attribute involved, and — for a `Pkcs11Exception` — the raw `CKR` return code
* the description of the actual result (what is actually happening) and the expected result (what would you expect to happen instead)
* a snippet of the problematic code
* the exception you are getting along with a full stack trace

Please do **not** include secret material — PINs, private keys, or plaintext — in an issue.

If you believe you have found a security vulnerability, do not open a public issue; report it privately through [GitHub security advisories](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/security/advisories/new) instead.

GitHub supports [markdown](https://docs.github.com/en/get-started/writing-on-github), so when filing issues make sure you check the formatting before clicking submit.

## Contributing code and content

Before submitting a [pull request](https://docs.github.com/en/pull-requests) with a feature or substantial code contribution please discuss it with the project members in the [KerckhoffsLabs.Security.Cryptography.Pkcs11 issue tracker](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/issues). You might also read these two blog posts on contributing code: [Open Source Contribution Etiquette](https://tirania.org/blog/archive/2010/Dec-31.html) by Miguel de Icaza and [Don't "Push" Your Pull Requests](https://www.igvita.com/2011/12/19/dont-push-your-pull-requests/) by Ilya Grigorik. Note that all code submissions will be rigorously reviewed and tested by project members, and only those that maintain the existing coding style and meet both quality and design appropriateness will be merged into the source.

See [Building from source](README.md#building-from-source) for how to clone the repository (it vendors its test backends as git submodules), build, and run the tests. Before opening a pull request, make sure the solution builds warning-free and the tests pass:

```bash
dotnet build src/KerckhoffsLabs.sln
dotnet test src/KerckhoffsLabs.sln
```

Warnings are treated as errors and code style is enforced on build, so a green local build is the same bar CI applies.
