# Getting started

This page takes you from a PKCS#11 module on disk to an operation on a key that never leaves the token.
Every snippet on this page, and on the example pages, is compiled and run in CI against real tokens.

## What you need

- **.NET 10** or later, and the package:

  ```
  dotnet add package KerckhoffsLabs.Security.Cryptography.Pkcs11
  ```

- **A PKCS#11 module** for your token: your HSM vendor's library (`.so`, `.dylib` or `.dll`), or
  [SoftHSM2](https://github.com/opendnssec/SoftHSMv2) for development.
- **An initialized token**, its **label**, and the **user PIN**.

The examples use the namespaces `KerckhoffsLabs.Security.Cryptography.Pkcs11`, `.Algorithms` and
`.Common`.

## Keep the PIN out of your code

Read the PIN from your secret store at run time. Here it comes from an environment variable that the
deployment sets:

[!code-csharp[](../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/GettingStartedExamples.cs#ReadPinFromEnvironment)]

`SecurePin` holds the PIN in a buffer the garbage collector cannot move, and zeroes it when you dispose
it. A string cannot be zeroed, so when your secret store can hand you the PIN as characters
(`char[]` or `Span<char>`), use the `SecurePin(ReadOnlySpan<char>)` constructor instead: no string ever
holds the PIN. See [Secrets in memory](security-model.md#secrets-in-memory).

## From module to operation

[!code-csharp[](../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/GettingStartedExamples.cs#EncryptAndDecryptWithTokenKey)]

What each step does:

1. **`Pkcs11Library.Load`** maps the module and initializes it. Dispose it last: the library calls
   `C_Finalize` when it is disposed, if it was the one that initialized the module.
2. **`OpenSessionWithPin`** finds the token by label, opens a session and logs in. (A token that takes
   no login, such as a software crypto token, is opened with `OpenSessionWithoutLogin` instead.) The session enforces
   the default [`Recommended`](policies/recommended.md) crypto policy: an insecure request throws
   `CryptoPolicyViolationException` before it reaches the token. To choose another policy, pass it as
   the last argument; see [Using crypto policies](crypto-policies.md).
3. **`GenerateAesKey`** creates the key on the token, sensitive and non-extractable, and allowed only to
   encrypt and decrypt. Each key-generation helper grants exactly one role; see
   [Key role separation](security-model.md#key-role-separation). The key is a **session object** and
   disappears when the session closes. Pass `persistOnToken: true` to keep it, and find it again later
   with `session.OpenKey(label)`.
4. **`AesGcmPkcs11`** gives the key the shape of `System.Security.Cryptography.AesGcm`: the same
   constructor arguments (with a `Pkcs11Key` instead of key bytes) and the same `Encrypt` and `Decrypt`.
   The token does the work.
5. **Disposal** releases everything in reverse order. Dispose sessions and keys deterministically
   (`using`), rather than leaving them to the garbage collector.

## Next steps

- The example pages show every algorithm the library offers, each next to its
  `System.Security.Cryptography` equivalent: [authenticated encryption](examples/aead.md),
  [AES block modes](examples/aes.md), [RSA](examples/rsa.md), [elliptic curves](examples/elliptic-curves.md),
  [post-quantum](examples/post-quantum.md), [hashes and HMAC](examples/hashes.md),
  [key derivation](examples/key-derivation.md), [certificates](examples/certificates.md) and
  [legacy algorithms](examples/legacy.md).
- The [security model](security-model.md) explains what the library protects, from whom, and where its
  protection ends.
- The [API reference](api/index.md) documents every type and member.
