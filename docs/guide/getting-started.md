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

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/GettingStarted/GettingStartedExamples.cs#ReadPinFromEnvironment)]

`SecurePin` holds the PIN in a buffer the garbage collector cannot move, and zeroes it when you dispose
it. A string cannot be zeroed, so when your secret store can hand you the PIN as characters
(`char[]` or `Span<char>`), use the `SecurePin(ReadOnlySpan<char>)` constructor instead: no string ever
holds the PIN. See [Secrets in memory](security-model.md#secrets-in-memory).

## From module to operation

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/GettingStarted/GettingStartedExamples.cs#EncryptAndDecryptWithTokenKey)]

What each step does:

1. **`Pkcs11Library.Load`** maps the module and initializes it. Dispose it last: the library calls
   `C_Finalize` when it is disposed, if it was the one that initialized the module.
2. **`GetSlotByTokenLabel`** finds the slot holding the token with that label. It throws
   `Pkcs11TokenException` (`CKR_TOKEN_NOT_PRESENT`) when no token has the label, and refuses with
   `InvalidOperationException`, naming the slots, when more than one does: select the slot from
   `GetSlotList` by its ID then. **`slot.Login(TokenUser.User, pin)`** logs the normal user in and returns a
   `Pkcs11Login`, and **`login.OpenSession()`** opens a read/write session of that login. (A token that takes
   no login, such as a software crypto token, is used through `slot.OpenSession()` instead, which opens a
   read-only session by default. A read-only session creates session objects, such as the key below; pass
   `SessionAccess.ReadWrite` to create or change token objects.) The session enforces the
   default [`Recommended`](policies/recommended.md) crypto policy: an insecure request throws
   `CryptoPolicyViolationException` before it reaches the token. To choose another policy, pass it to
   `OpenSession`; see [Using crypto policies](crypto-policies.md).
3. **`GenerateAesKey`** creates the key on the token, sensitive and non-extractable, and allowed only to
   encrypt and decrypt. Each key-generation helper grants exactly one role; see
   [Key role separation](security-model.md#key-role-separation). The key is a **session object** and
   disappears when the session closes. Pass `persistOnToken: true` to keep it, and find it again later
   with `session.OpenKey(label)`.
4. **`AesGcmPkcs11`** gives the key the shape of `System.Security.Cryptography.AesGcm`: the same
   constructor arguments (with a `Pkcs11Key` instead of key bytes) and the same `Encrypt` and `Decrypt`.
   The token does the work.
5. **Disposal** releases everything in reverse order. Dispose sessions, logins and keys deterministically
   (`using`), rather than leaving them to the garbage collector. The token is logged out when the login and
   every session opened from it have been disposed, in whatever order: disposing one of them logs out only
   when it is the last.

### In an application: load and log in once

The example runs the whole flow in one method so you can read it in one place. An application doesn't
load the module and log in for every operation. In PKCS#11 the login belongs to the application, not to
the session: once the user is logged in, every session the application has on the token sees the login.
Load the module and log in once at startup, keep the library and the `Pkcs11Login` for the application's
lifetime, and open sessions from the login (`login.OpenSession()`) for the code that opens keys and uses
them. A second `slot.Login` of the same user while the login is held shares it rather than failing, but it
is not a second authentication: a token is not required to check the PIN of a user who is already logged
in. Logging in as another user (the security officer, say) while one is held is refused with
`Pkcs11AuthenticationException`. The example pages show the same full flow per method, for the same
reason.

## Handling errors

Every exception the library throws derives from `System.Security.Cryptography.CryptographicException`, so
code written against the BCL shapes, including generic code that has never heard of PKCS#11, catches token
failures where it already catches everything else. Catch something narrower when you need more:

- **`Pkcs11Exception`** is a failed PKCS#11 call. `ReturnValue` is the raw `CKR` code, and `Method` names
  the function that returned it. Its subclasses group the codes by cause, such as
  `Pkcs11AuthenticationException`, `Pkcs11SessionException` and `Pkcs11MechanismException`.
- **`CryptoPolicyViolationException`** is a request the session's crypto policy refused, before any call
  reached the token.

The exception types are in the `KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions` namespace.

## Next steps

- The example pages show every algorithm the library offers, each next to its
  `System.Security.Cryptography` equivalent: [authenticated encryption](../examples/aead.md),
  [AES block modes](../examples/aes.md), [RSA](../examples/rsa.md), [elliptic curves](../examples/elliptic-curves.md),
  [post-quantum](../examples/post-quantum.md), [hashes and HMAC](../examples/hashes.md),
  [key derivation](../examples/key-derivation.md), [certificates](../examples/certificates.md) and
  [legacy algorithms](../examples/legacy.md).
- The [security model](security-model.md) explains what the library protects, from whom, and where its
  protection ends.
- The [API reference](../api/index.md) documents every type and member.
