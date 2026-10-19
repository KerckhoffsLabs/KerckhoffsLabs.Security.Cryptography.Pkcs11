# Security policy

## Scope

In scope:

- the `KerckhoffsLabs.Security.Cryptography.Pkcs11` package: the library, and the security analyzers
  and source generators it ships;
- its secure defaults: a mechanism, key attribute or parameter that the `SecureOnly` or `FipsOnly`
  policy should reject but lets through, or a private key that becomes extractable without the caller
  opting in;
- memory safety at the native boundary: marshalling, buffer sizing, handle lifetime and the zeroizing
  of secret buffers;
- the workflows that build and publish the package.

Out of scope:

- vulnerabilities in a PKCS#11 module, HSM or token, including the ones vendored under `vendor/` for
  testing (SoftHSM, openCryptoki, Kryoptic, NSS, BouncyHsm, pkcs11-mock): report those to their
  maintainers;
- findings that require an already-compromised host, a malicious PKCS#11 module chosen by the
  application, or physical access to the token;
- code under `tests/` and `build/` that does not ship, unless it compromises the release pipeline.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/security/advisories/new)
(Security → Advisories → *Report a vulnerability*). It is the only channel: reports by email are not
accepted.

Please include:

- the affected package version, .NET version, operating system and architecture;
- the PKCS#11 module and version involved, if any;
- a description and, where possible, a minimal reproduction;
- the impact you foresee.

Never include real PINs, keys or plaintext in a report: use placeholders or test tokens.

## What to expect

- **Acknowledgement** within 10 working days.
- An initial assessment and a severity (CVSS) within 15 working days.
- Coordinated disclosure: the fix and the advisory are published together, with a CVE requested through
  GitHub when one is warranted. You are credited unless you prefer to remain anonymous.

## Supported versions

Only the latest release receives security fixes, as a new release. Until the first release, fixes land
on `main`.
