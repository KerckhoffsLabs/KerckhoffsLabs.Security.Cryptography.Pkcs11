# Security model

This page explains what the library protects, from whom, how, and where its protection ends. For how to
choose, adjust or write a crypto policy, see [Using crypto policies](crypto-policies.md); for the
diagnostics the analyzers raise, see [Diagnostics](../diagnostics.md).

## Overview

The high-level API is **secure by default**:

- Every session enforces a **crypto policy**. A request the policy refuses — a mechanism, a hash, a curve,
  a key size, a parameter, a key template — throws `CryptoPolicyViolationException` (a
  `CryptographicException`) **before any call reaches the token**.
- Keys the library generates are **sensitive and non-extractable**, and each is granted **one role**.
- Insecure choices visible at compile time are reported by `[Obsolete]` attributes and analyzers
  (`KLPKCS11001`–`KLPKCS11012`), so most mistakes surface in the build, not in production.
- Secrets that pass through the library — PINs, passwords, key bytes, plaintext — are held in buffers
  that are zeroed when released.

<a id="threat-model"></a>
## Threat model

### Assets

- **Key material on the token**: private keys and secret keys. The library's purpose is that these stay
  on the token, are used only for the role they were created for, and never leave in the clear unless the
  caller chose that explicitly.
- **The integrity of the policy decision**: what the caller asked for is what the policy judged, and
  nothing reaches the token that the policy did not allow.
- **Secrets in process memory**: PINs, passwords, imported key bytes, plaintext and derived secrets that
  transit the library on their way to or from the token.
- **The correctness of results**: a signature, a decryption or a derived value returned to the caller is
  what the token produced, of the length it reported, and never silently padded or truncated.

### Actors

| Actor | What they can do | How the library responds |
|---|---|---|
| **The application developer** (the main audience of the defaults) | Choose a weak mechanism, a short tag, a small key, a key template that grants too much, or forget to dispose a secret. | Policy refusals before the token is called; `[Obsolete]` and analyzer diagnostics at build time; single-role key helpers; capability attributes that default to `false`; secret buffers zeroed on release, with finalizers as a safety net. |
| **A remote party supplying inputs** | Submit chosen ciphertexts, forged tags or signatures, malformed public keys, or wrapped-key blobs, and observe the outcome. | Inputs are length- and range-checked before they reach the token (an RSA ciphertext must be the modulus's length and below the modulus); AEAD adapters fix the tag size at construction so a short forged tag is refused; tag mismatches surface as `AuthenticationTagMismatchException`. Padding-oracle exposure depends on the caller: see [PKCS#1 v1.5 decryption](../diagnostics.md#pkcs1-implicit-rejection). |
| **A PKCS#11 module that deviates from the specification** | Report a length larger than the buffer it was given, return an unexpected code, or implement a mechanism differently from another vendor. | Lengths and counts the module reports are checked against what was allocated before anything is sized, sliced or read; a wrong answer is a `Pkcs11Exception`, not memory corruption or silently zero-padded output. Return codes map to typed exceptions that keep the raw `CKR`. |

### Trust boundaries

1. **Application → library** (the public API). The library assumes the caller is the party authorised to
   use the session it opened, and protects the caller from *mistakes*, not from itself: a caller can
   always lift the policy with `UsePolicy(CryptoPolicy.AllowInsecure)` unless the library was loaded under
   a policy that forbids overrides (`CryptoPolicy.NistApproved`, `CryptoPolicy.Cnsa20`).
2. **Library → PKCS#11 module** (P/Invoke and native memory). Everything the module writes or reports is
   validated before use; everything the library hands it is marshalled with the layouts and `CK_ULONG`
   width of the platform, and released deterministically.
3. **Module → token**. Opaque to the library: whatever the module does with the token, the library sees
   only the PKCS#11 interface.

**The library relies on the token to enforce `CKA_SENSITIVE`, `CKA_EXTRACTABLE` and `CKA_PRIVATE`, and the
wrap and unwrap templates.** The library sets these attributes securely when it creates keys and builds
templates, but enforcing them — refusing to reveal a sensitive key's value, to wrap a non-extractable key,
or to show a private object without login — is the token's job, and the library cannot verify after the
fact that the token did so. Choose a token whose enforcement you trust for the keys you protect.

### Controls

| Control | Where it is enforced |
|---|---|
| Crypto policy check before every operation | `Pkcs11Session` (the library's policy, `Pkcs11LibraryOptions.Policy`, or a scoped `Pkcs11Session.UsePolicy` lease); `CryptoPolicy.Recommended`, `CryptoPolicy.NistApproved`, `CryptoPolicy.Cnsa20` |
| Build-time warnings for insecure choices | `[Obsolete]` on legacy adapters, weak curves and the PBKDF2 constructors with weak defaults (`KLPKCS11001`–`KLPKCS11007`, `KLPKCS11011`); analyzers for insecure values (`KLPKCS11008`–`KLPKCS11010`); a warning at every key-material export opt-in (`KLPKCS11012`) |
| Sensitive, non-extractable keys by default | `Pkcs11Session.GenerateAesKey`, `GenerateRsaSigningKeyPair`, … ; `SecretKeyTemplateBuilder` and `PrivateKeyTemplateBuilder` defaults |
| One role per generated key | the `Pkcs11Session` key-generation helpers ([Key role separation](#key-role-separation)) |
| Capability attributes default to `false` | `SecretKeyTemplateBuilder`, `PublicKeyTemplateBuilder`, `PrivateKeyTemplateBuilder` |
| Wrap and unwrap hardening | `WrapWithTrusted`, `WrapTemplate`, `UnwrapTemplate`, `DeriveTemplate` on the template builders ([Wrap hardening](#wrap-hardening)) |
| Ciphertext length and range checks | `Pkcs11Key.Decrypt` and `Pkcs11Key.Unwrap` with RSA PKCS#1 v1.5 or OAEP |
| Fixed AEAD tag size | `AesGcmPkcs11`, `AesCcmPkcs11` constructors |
| Module-reported lengths validated | every call site that sizes or reads a buffer from a length the module reports |
| Secrets zeroed on release | `SecurePin`, `SecurePassword`, attribute and parameter buffers ([Secrets in memory](#secrets-in-memory)) |
| A login ends only with its last holder; private handles refused after it | `Pkcs11Login`, `Pkcs11Session`, `Pkcs11Key`, `Pkcs11Object` ([Logins and sessions](#logins-and-sessions)) |
| Session access stated where no login is needed | `Pkcs11Slot.OpenSession` ([Logins and sessions](#logins-and-sessions)) |

### Out of scope

These are outside what the library can defend against, and outside the scope of
[security reports](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/blob/main/SECURITY.md):

- a **malicious PKCS#11 module** chosen by the application: the module runs in the process and can do
  anything the process can;
- a **compromised host or process**: an attacker who can read process memory can read secrets while they
  are in use, whatever the library zeroes afterwards;
- **physical access** to the token, and side channels in the token or module itself;
- vulnerabilities in a PKCS#11 module, HSM or token: report those to their vendor.

<a id="known-limits"></a>
### Known limits

- **Policies judge the keys they use by what the token reports.** Each time an existing RSA or EC key is used,
  the session reads its modulus or curve from the token and the policy judges it, at two extra
  `C_GetAttributeValue` calls per keyed operation on such a key (`Cnsa20` reads every key's type and size). A token that reports
  a value it does not hold defeats the check, as it can defeat every other.
- **Raw-digest mechanisms** (`CKM_ECDSA`, `CKM_RSA_PKCS`, `CKM_RSA_PKCS_PSS`) sign a caller-computed
  digest; the policy cannot see which hash produced it.
- **`CKM_AES_KEY_WRAP_PAD` is vendor-dependent**: wrapped keys may not move between tokens.
- **PKCS#1 v1.5 decryption may not fail on bad padding**: some tokens return a synthetic plaintext
  instead ([details](../diagnostics.md#pkcs1-implicit-rejection)).
- **`CKA_TRUSTED` is not gated locally**: only the security officer may set it, and the token, not the
  library, enforces that.
- **`NistApproved` is not FIPS certification**: it restricts what this library sends; FIPS 140-3 also
  requires a validated module operating in its approved mode.
- **Logins made outside the library are not seen.** Another component of the process calling the module
  directly, or another process, can log in or out without the library knowing; the module's answer then
  decides.

<a id="logins-and-sessions"></a>
## Logins and sessions

In PKCS#11 a login belongs to the application and the token, not to a session: once the user is logged in,
every session the application has with the token is logged in too, and logging out logs all of them out
(PKCS#11 v3.2, "Session management functions"). The library models it that way, so that one component
cannot log out another's sessions by accident.

```csharp
// The PIN comes from your secret store (a secret manager, or an environment variable the deployment sets),
// never from source code. ReadPinFromSecretStore stands for that call.
using SecurePin pin = ReadPinFromSecretStore("user-pin");
using Pkcs11Login login = slot.Login(TokenUser.User, pin);   // the library does not keep the PIN

using Pkcs11Session signing = login.OpenSession();   // read/write by default
using Pkcs11Session reading = login.OpenSession(SessionAccess.ReadOnly);
```

- **A login ends with its last holder.** `Pkcs11Slot.Login` and `ShareOrLogin` (each taking a `LoginCredential`: a `SecurePin`, a PIN source, or `LoginCredential.Pinpad`; and an optional username, for `C_LoginUser`) return a
  `Pkcs11Login`, a hold of the token's login; each session opened through `login.OpenSession()` holds it too.
  The token is logged out (`C_Logout`) when the last holder is disposed, in whatever order they go: disposing
  the `Pkcs11Login` before its sessions leaves them working. Every `Pkcs11Library` loaded from the same module
  shares the login, as the module does.
- **A second login is refused; sharing is explicit.** While the application holds a login on the token, a
  `Login` is refused before the module, with no PIN sent: `CKR_USER_ALREADY_LOGGED_IN` for the same user,
  `CKR_USER_ANOTHER_ALREADY_LOGGED_IN` for anyone else (the security officer, or another username).
  PKCS#11 has no way to check a PIN against a login already made, so a second login that "shared" the first
  would succeed with any PIN, and resending the PIN could only cost retries on a token that does check it. Code
  that should use the login takes a share without a PIN: `Pkcs11Login.Share()` on a login it was handed, or
  `Pkcs11Slot.TryShareLogin` for the login held on the slot; `Pkcs11Slot.ShareOrLogin` shares or logs in in one
  step, asking for the PIN only when it logs in. A share is not an authentication: it hands out what the
  application already has. For that reason the security officer's login is never shared from the slot
  (`TryShareLogin` and `ShareOrLogin` take no user: they share the normal user's login): only code handed the
  SO's `Pkcs11Login` can share it, and only it can set the user's PIN (`InitUserPinWithPin`). That is the one
  thing kept behind the `Pkcs11Login`: PKCS#11 puts every session of the application in the login's state, so
  while the SO is logged in, any `slot.OpenSession(SessionAccess.ReadWrite)` is an SO session too, and can
  create or destroy public token objects.
- **None of this is a boundary between components of one process.** `Pkcs11Session.LoginInfo` gives a
  read-only `Pkcs11LoginInfo` (slot, user, whether active) rather than the `Pkcs11Login`, so code handed a
  session cannot dispose the opener's hold or set a PIN through it. But it can reach the slot
  (`session.Slot`, `LoginInfo.Slot`), take its own share of the normal user's login with
  `TryShareLogin` and keep the token logged in after the opener is done, or dispose `session.Library`; and code
  in the process can load the module itself. Keep components that must not use the token out of the process.
- **The token is re-checked before the login.** A slot found by a lookup (`GetSlotByUri`,
  `GetSlotByTokenSerial`, ...) remembers the token it matched, and `Login` refuses with
  `CKR_TOKEN_NOT_RECOGNIZED` if the slot now holds another token. This narrows a swap between lookup and login;
  it cannot stop a lookalike, since a token reports its own label and serial number.
- **A login made outside the library is never taken over.** When the token answers a first login with
  `CKR_USER_ALREADY_LOGGED_IN` (or `CKR_USER_ANOTHER_ALREADY_LOGGED_IN`), the library checks whether the login is
  one it left behind: a `C_Logout` that failed, or the login's own session lost while other sessions kept the
  token logged in. If so, it logs that login out and sends the login once more, so the PIN is checked. If not
  (another component called the module directly), the login is refused with `Pkcs11ForeignLoginException`
  and nothing is logged out. The library only treats a login as left behind when the loss was its own
  session's, a removed token's or a context login's locked PIN (a module may keep the login then), and when the
  module says the same user is logged in: either its answer to the new login (`CKR_USER_ALREADY_LOGGED_IN` for the same user,
  `CKR_USER_ANOTHER_ALREADY_LOGGED_IN` for the other one) or the new session's state. The answer code alone is
  enough: some modules report an SO login as a user's on a session opened after it (Kryoptic), which would
  otherwise make an SO login left behind look foreign. Where it can, it does not wait for the next login: a login left behind is logged out at once on another
  session of the slot. Login state is per application, so the module's answer cannot tell the library's own login
  left behind from one another component of the process made meanwhile for the same user through the same module:
  such a login is taken for the library's and logged out. A login with nothing left behind, or for another user, is
  never touched.
- **The library keeps a session of its own for each login**, on which it sends `C_Login` and `C_Logout`. It is
  what keeps a login alive while you have no session open. It is read/write for both users where the token
  allows. For the user it falls back to a read-only session where the token refuses a read/write one (a
  write-protected token, or no read/write session left for this application); the security officer has no
  such fallback, as that user has only read/write sessions. On a token that refuses another session
  (`CKR_SESSION_COUNT`, from the module), `login.OpenSession()` lends the login's own session, one at a
  time: a second one, or a `slot.OpenSession(...)` while the login is held, fails with `CKR_SESSION_COUNT` and
  the message says why. A request whose access the login session does not have is refused the same way
  (`CKR_SESSION_COUNT`; the message says which): a read/write one on a read-only login session, a read-only one
  on a read/write login session. `login.OpenSession()` takes the login session as it is. Disposing
  a lent session returns it to the login and destroys the session objects created through that lent session
  (token objects stay, and so does an object whose handle the token has since given to a different object:
  each is checked to still read `CKA_TOKEN` false, with the class and label it was created with). A `Login`
  while a slot session holds the token's only session fails the same way.
- **A lent session ends with its login.** Once the login ends (for instance after `CKR_PIN_LOCKED`, or when the
  login's own session is lost), a lent session refuses every call with `Pkcs11LoginEndedException`: log in
  again and open a new one. An ordinary session from `login.OpenSession()` is not like this: it stays open as
  a public session.
- **Private handles do not outlive their login.** PKCS#11 invalidates every handle to a private object when
  the user logs out, even if the user logs in again. A `Pkcs11Key`, `Pkcs11Object` or `Pkcs11Certificate`
  found under a login that has since ended refuses to send its private handle (`Pkcs11LoginEndedException`):
  log in and open it again. An object whose `CKA_PRIVATE` the token will not report counts as private. A
  logout waits for operations in flight on the token, so none is cut off halfway: when the last holder is
  disposed while operations run (on another thread, or from code the library calls back during one), the
  logout is left pending and sent as the last of them ends. From that moment the login is ending: operations
  already running finish, but no new one starts under it, and it cannot be shared, so a busy application
  cannot put the logout off for ever. Disposing never blocks or throws for it; a `Login` made meanwhile waits
  for that logout, then logs in afresh; `Pkcs11Login.Ended` is a task that completes once the login has
  ended.
- **A forgotten login stays.** A `Pkcs11Login` or session that is never disposed keeps the token logged in
  until the `Pkcs11Library` is disposed. There is no finalizer that logs out: it would run on the finalizer
  thread, at a time nobody chose, against a module that may be in use. Dispose logins and sessions, or the
  library at shutdown.
- **A lost token or HSM session is noticed late; logging in again recovers.** After the token is pulled and
  put back, or a network HSM fails over, the module has dropped the login, but `Pkcs11Login.IsActive` may
  still read `true` and `login.OpenSession()` still succeed until the library next uses the login's own
  session; operations meanwhile fail with `CKR_USER_NOT_LOGGED_IN`. Call `slot.Login(...)` again: before
  refusing a second login it checks that session (`C_GetSessionInfo`), finds it lost, ends the old login and
  logs in afresh in the same call. The old `Pkcs11Login`, its
  sessions and its private handles stay ended; dispose them and use the new login.
- **A session that holds no login says what it may do.** `Pkcs11Slot.OpenSession(SessionAccess.ReadOnly)`
  opens a read-only session that holds no login (it sees the application's login while there is one), the
  least privilege and the only kind a write-protected token accepts; the access has no default there. A read-only session creates and uses session objects; only
  token objects (`persistOnToken: true`) need `SessionAccess.ReadWrite`. A read-only session and a security
  officer login exclude each other, and the library refuses either one before the module when it knows of
  the other.
- **Keys with `CKA_ALWAYS_AUTHENTICATE`** need the PIN again for each use. A key uses its own session's
  `Pkcs11Session.ContextAuthentication`, set to `ContextAuthentication.FromPinSource(...)` (a new PIN each time, disposed once sent), `FromPin(pin)` (a PIN you keep) or
  `ContextAuthentication.Pinpad`. A session from `login.OpenSession()` starts with a copy of
  `Pkcs11Login.ContextAuthentication` taken when it opens, so set the login's **before** opening the sessions
  that need it; setting it later changes only the sessions opened afterwards. To change an open session, set
  its own `ContextAuthentication`. The library asks for the PIN before the operation takes its session (so a
  callback that fails starts nothing, and a slow one holds no lock and delays no logout) and sends
  `C_Login(CKU_CONTEXT_SPECIFIC)` after `C_SignInit` or `C_DecryptInit`, for that one operation. A module that
  answers it `CKR_OPERATION_NOT_INITIALIZED` (the key needs no re-authentication after all) carries on with the
  operation, unless the session no longer shows the user logged in (OpenSC's answer once the card's login is
  gone): the login then ends, and the operation fails with `CKR_USER_NOT_LOGGED_IN`. A session without a source refuses such a key before the operation starts
  (`InvalidOperationException`; through `RSAPkcs11`, `ECDsaPkcs11` and the other BCL-shaped adapters, a
  `CryptographicException` with it inside, which code written against `RSA` or `ECDsa` catches).
  `ContextAuthentication.Pinpad` is refused (`InvalidOperationException`) on a token without a protected
  authentication path, as are `LoginCredential.Pinpad`, `InitUserPinWithPinpad`, `SetPinWithPinpad` and
  `InitTokenWithPinpad`: PKCS#11 gives a call without a PIN no meaning there. `ContextAuthentication.FromPin(pin)`
  takes a `SecurePin` the caller keeps (the library never disposes it, and an operation that finds it disposed throws
  `ObjectDisposedException`, through the adapters too: it is a bug in the calling code, not a cryptographic failure); the callback form takes a new one each time
  and disposes it, as `LoginCredential.FromPinSource(() => ...)` does, while a `SecurePin` passed to `Login` or `ShareOrLogin` stays with the caller. On a v2.40 module (no `C_SessionCancel`), an operation
  whose context login failed is never finished: that could sign data nobody asked for, spending a qualified
  signature's counter or a one-time key leaf, on a module whose context login only re-checks the user's PIN
  (OpenSC). When the token answered this operation's own PIN `CKR_PIN_INCORRECT`, a length query, which produces no
  output, may end it (`CKR_USER_NOT_LOGGED_IN`); otherwise the session is closed, which ends every operation on it
  with no output, and its later calls are refused with a message saying so (open a new session). A session the
  login lent is the login's own and is not closed: the operation stays abandoned, and the session's next operation of
  that kind says what to do. Any other failure leaves the operation abandoned too.
- **A refused PIN is never sent twice.** Each wrong PIN costs one of the PIN's retries, so the library remembers
  the PINs a token refused and refuses a second attempt with the same PIN before the module
  (`Pkcs11AuthenticationException`, `CKR_PIN_INCORRECT`). The purposes are: a login of the SO, the user or a
  username, or a context login, refused with `CKR_PIN_INCORRECT`, `CKR_PIN_INVALID` or `CKR_PIN_LEN_RANGE`; the old
  PIN of `SetPinWithPin`, as that user's, and the SO PIN of `InitTokenWithPin`, refused with `CKR_PIN_INCORRECT` (the
  other codes judge the new PIN there). The normal user's login PIN and the context PINs are checked against each
  other's refusals, since they are usually the same PIN. It does not matter which `Login`, `ShareOrLogin`,
  `ContextAuthentication` object, session or load of the module brings the PIN: the per-request pattern with a stale
  PIN in the secret store spends one retry in all, even when each request loads and unloads the module (a PIN changed
  outside the library while a login made with it is held is the exception: two, below), and sends are
  serialized per slot, so threads that send it at the same moment spend one too. A token whose information cannot be
  read is not sent the PIN at all. A different PIN is sent. A context login's refusal holds for all the token's keys,
  unless it is the PIN the user's login held was made with: it is then that key's own refusal (a key with a PIN of its
  own, such as a qualified signature key), and does not block the user's PIN for the others, until a second key
  refuses it too. That is taken for the PIN changed outside the library while the login held, and the refusal then
  holds for every key and the user's next login: such a change costs two retries at most (one key's, then a second
  key's or the next login's). Two keys with PINs of their own both refusing the user's PIN block it the same way, until
  `ForgetRefusedPins()`, which fails safe. A key is told by its key type, `CKA_ID` and `CKA_LABEL`. Any other PIN refused
  for one key is taken for a stale one: a key's own PIN sent by mistake to another key, or, after a login on the
  pinpad, the user's PIN sent to a key with a PIN of its own. No PIN is kept for this, only an HMAC of the refused
  one under a random key held in memory, and, while a user login made with a PIN is held, of that PIN. A crash dump
  taken meanwhile holds the key with it, enough to find a short PIN by trying them all. A refusal is forgotten when its
  PIN is accepted for the same purpose or set through the library (`SetPinWithPin`, `InitUserPinWithPin`); that user's
  (and, for the normal user, the context logins') when the PIN is set on the pinpad; all of them when the token is
  initialized. Refusals are kept per module and slot, up to 64 per slot (the oldest goes first), until the process
  ends. A PIN changed with another tool is not seen: call `Pkcs11Slot.ForgetRefusedPins()` after it, or set
  `Pkcs11LibraryOptions.RefusedPinLifetime` to have refusals expire (each expiry lets a still-wrong PIN spend one more
  retry). A refusal keeps the lifetime of the library that recorded it, whichever load of the module checks it later. Rotate the token's PIN before the secret store's, or a login in between gets the new PIN refused, and that
  refusal stands until forgotten. `C_UnwrapKey`, `C_DeriveKey` and `C_DecapsulateKey` start and finish in one call, with no
  point at which to re-authenticate, so they are sent as they are, with or without a source, and the token
  decides. A PIN locked during a
  re-authentication ends the token's login, as the specification says it does; a module that keeps the login then
  (OpenSC, whose context PIN may be a signature PIN of its own) has it logged out by the library, as for a login
  left on the token.

  ```csharp
  // Called once per operation with the key about to be used; return a new SecurePin each time.
  ContextAuthentication fromSecretStore = ContextAuthentication.FromPinSource(key => ReadPinFromSecretStore("user-pin"));

  // Set on the login before opening sessions: each session copies it when it opens.
  login.ContextAuthentication = fromSecretStore;
  using Pkcs11Session session = login.OpenSession();

  // Or on a session already open (including one from slot.OpenSession(...)).
  signing.ContextAuthentication = fromSecretStore;
  ```

<a id="crypto-policies"></a>
## Crypto policies

Every session enforces a **crypto policy**: the library's, chosen when it is loaded.

```csharp
// Default: Recommended — refuses broken algorithms, weak keys, and plaintext key export.
using var library = Pkcs11Library.Load(modulePath);

// FIPS: only NIST-approved functions, in every session; overrides are refused.
using var fips = Pkcs11Library.Load(modulePath, new Pkcs11LibraryOptions { Policy = CryptoPolicy.NistApproved });

// Legacy interop for one operation, on a session of the first library (refused under NistApproved):
using (session.UsePolicy(CryptoPolicy.AllowInsecure)) { /* one legacy operation */ }
```

Refusals throw `CryptoPolicyViolationException` (a `CryptographicException`) naming the policy and the
reason. You can supply your own `ICryptoPolicy`; end any `switch` over `PolicyRequest` with a deny arm so
request kinds added in later versions fail closed. A custom policy that allows a `KeyMaterialExportRequest`
must also judge the library's own read-back: the extractable, non-sensitive `KeyTemplateRequest` (and, for
`DeriveRawSecret`, the `CKD_NULL` `KeyAgreementKdfRequest`) it creates carry `ReadBackFor` set to the export's
kind. A policy that ignores `ReadBackFor` judges them like a caller's and refuses them, so the export fails
closed; a caller's own requests never carry it.

The restrictive policies are **allow-lists that deny by default**: every mechanism, hash, curve,
key-agreement KDF and KDF PRF they permit — with its rationale — plus the documented, non-enforcing deny
list (reason and alternative), is generated straight from the policy source into
[Recommended](policies/recommended.md), [NistApproved](policies/nist-approved.md) and
[Cnsa20](policies/cnsa-2.0.md). Anything not listed on those pages is refused.

**Key-strength checks.** A policy can also judge the keys themselves. `CryptoPolicy.Cnsa20` does; `Recommended`
and `NistApproved` don't, and sessions under them read no key attributes for it. Under an inspecting policy the
session reads the key's `CKA_KEY_TYPE` and its `CKA_VALUE_LEN`, `CKA_PARAMETER_SET` or `CKA_HSS_LEVELS` before
every keyed operation (again on every use, with no cache, so a handle that now points at a weaker key is still
caught). It also checks templates before the token creates a key, and reads back each key the token generates,
unwraps, derives, encapsulates, decapsulates or imports: a created key that fails is destroyed before its handle
is returned, and if that destroy fails the exception names the handle and an error is logged. A copy made with
`CopyObject` is not judged when it is created; it is judged when it is used. An attribute the token does not
report is refused, never assumed. Only the key type, its length, parameter-set name or HSS levels, and object
handles appear in refusals and logs; key values never do. See [CNSA 2.0](crypto-policies.md#cnsa-20) for the
policy's known limits.

> **`NistApproved` is not FIPS certification.** It restricts what this library sends to the token. FIPS 140-3
> compliance also requires a validated cryptographic module operating in its approved mode. Under
> `NistApproved`, AES key wrapping is approved only via KW/KWP (`CKM_AES_KEY_WRAP`, `CKM_AES_KEY_WRAP_KWP`)
> or the GCM/CCM modes; other AES modes encrypt and decrypt data but may not wrap or unwrap keys.
> AES-GCM tags must be 96 to 128 bits (SP 800-38D §5.2.1.2) and AES-CCM MACs at least 64 bits
> (SP 800-38C Appendix B.2).
> `CKM_AES_KEY_WRAP_PAD` is refused: its padding is vendor-defined (RFC 5649 on some tokens, KW over
> PKCS#7 — not an SP 800-38F method — on others), so its approval cannot be established.

**Known limits.** `Recommended` and `NistApproved`:

- Judge an existing RSA or EC key by its modulus or curve each time it is used, so an RSA-1024 or P-192 key
  already on the token is refused (and a Brainpool key under `NistApproved`, which does not approve those curves).
  `NistApproved` lets an RSA key of 1024 to 2047 bits, or a P-192 key, still
  verify an old signature (SP 800-131A Rev.2 Table 2 legacy use). For ECDH, the existing key's *type* is checked
  too: `NistApproved` refuses an X25519/X448 key.
- Raw `CKM_ECDSA`, `CKM_RSA_PKCS` and `CKM_RSA_PKCS_PSS` sign a caller-computed digest; the policy cannot
  see which hash produced it.
- `Recommended` allows `CKM_AES_KEY_WRAP_PAD`, but its meaning is vendor-dependent: RFC 5649 (KWP) on some
  tokens, KW over PKCS#7-padded input on others, so wrapped keys may not move between tokens. Prefer
  `CKM_AES_KEY_WRAP_KWP` where the token supports it.

The default `Recommended` policy allows each mechanism only for the operations it is meant for —
`CKM_AES_GCM` encrypts, decrypts, wraps and unwraps but does not sign; `CKM_SHA256` digests but does not
sign — and **denies every vendor-defined or unreviewed mechanism by default**, including ones it has no
specific objection to. Refusals it documents include unauthenticated symmetric modes (ECB, CBC, CTR, …),
broken/legacy ciphers (DES/3DES, RC2, RC4, SEED, CAST, Blowfish, SKIPJACK), broken hashes
(MD2/MD5/SHA-1/RIPEMD), PKCS#1 v1.5 *encryption* and raw RSA (`CKM_RSA_PKCS`, `CKM_RSA_X_509`),
sub-128-bit EC curves, SHA-1 KDF PRFs, and AES-GCM tags under 96 bits or AES-CCM MACs under 64 bits. Where
the insecure choice is visible at compile time, [diagnostics](../diagnostics.md) (`KLPKCS11001`–`KLPKCS11012`)
surface it as a build warning too.

When `Recommended` refuses something you need, there are two remedies:

```csharp
// A mechanism you have reviewed (here a vendor-defined one): your own policy, derived from
// Recommended and named "MyApp". It copies every rule; CryptoPolicy.Recommended itself is unchanged.
ComposedCryptoPolicy reviewed = CryptoPolicy.Recommended.ToBuilder("MyApp")
    .AllowMechanism(
        (CKM)0x8000_1001UL,                           // your vendor's CK_MECHANISM_TYPE
        [CryptoOperation.Sign, CryptoOperation.Verify],
        "Vendor HSM signature scheme, reviewed for our release signing.")
    .Build();
using var library = Pkcs11Library.Load(modulePath, new Pkcs11LibraryOptions { Policy = reviewed });

// One-off legacy interop: lift the policy for a single, scoped operation.
using (session.UsePolicy(CryptoPolicy.AllowInsecure)) { /* decrypt one legacy archive */ }
```

The same builder allows a hash, curve or key-agreement KDF (`AllowHash`, `AllowCurve`,
`AllowKeyAgreementKdf`), tightens a copy (`RemoveMechanism`, `WithRsaKeyGenerationRule`), or starts a policy
from scratch (`new CryptoPolicyBuilder(name)`); see [Using crypto policies](crypto-policies.md). Reading a
shared secret or KDF output off the token is an explicit, per-kind opt-in with a reason
(`WithKeyMaterialExportRule(KeyMaterialExportRule.Allow(kinds, reason, kdfBaseKeys, privateKeys))`): the first
export of each kind under a policy logs a warning (later ones log at Debug), and each `Allow` call site is reported
as `KLPKCS11012`. Every kind is scoped by the key the secret comes from, with no default, so the opt-in says which
keys it may reproduce secrets of. KDF output is scoped by base key (for example only keys the token has not always
protected, so it cannot reproduce keys derived on the token from an agreed secret or a generated master key;
[the base-key scope](crypto-policies.md#kdfoutput-base-key-scope), with its limits). Shared secrets are scoped by
private key (for example only ephemeral session keys, so a long-lived key cannot be turned into an oracle for what
its earlier agreements and decapsulations kept on the token;
[the private-key scope](crypto-policies.md#private-key-scope)). Apply such a policy as a scoped `UsePolicy` lease
or on a dedicated session, not as a session's base policy. The
generated [Recommended](policies/recommended.md) and [NistApproved](policies/nist-approved.md) pages list
exactly what each policy allows, for which operations, and why.

<a id="key-role-separation"></a>
## Key role separation

`Pkcs11Session`'s key-generation helpers each grant exactly one role, deliberately. Mixing
data-processing roles (encrypt/decrypt, sign/verify) with key-management roles (wrap/unwrap) on the
same key turns the key into a self-service oracle: wrap an extractable key, then decrypt the
resulting blob with the same key to read it in the clear; or encrypt a chosen plaintext, then unwrap
it as if it were a wrapped key, injecting a "sensitive" key of known value (Clulow, *On the Security
of PKCS#11*, CHES 2003).

- `GenerateAesKey` → encrypt/decrypt only. `GenerateAesKeyEncryptionKey` → a dedicated wrap/unwrap-only
  KEK, with `CKA_UNWRAP_TEMPLATE` forcing every key it unwraps to be sensitive and non-extractable.
- `GenerateRsaSigningKeyPair` → sign/verify only. `GenerateRsaKeyTransportKeyPair` → encrypt/decrypt
  only (RSA-OAEP key transport). Neither grants `CKA_WRAP`/`CKA_UNWRAP`; a caller who specifically
  needs RSA `C_WrapKey`/`C_UnwrapKey` should build that template explicitly.
- `GenerateEcSigningKeyPair` → sign/verify only (ECDSA). `GenerateEcKeyAgreementKeyPair` → derive only
  (ECDH); its public key is granted no role, since ECDH does not use it on the token. Using one EC key
  for both signatures and key agreement breaks the one-purpose-per-key rule of NIST SP 800-57 Part 1
  §5.2: the two schemes' security arguments assume independent keys.

There is no single "do everything" key-generation helper — pick the one that names the role the key
will actually play.

**Every capability attribute defaults to `false`, deliberately.** PKCS#11's own spec default for an
*omitted* `CKA_ENCRYPT`/`CKA_DECRYPT`/`CKA_SIGN`/`CKA_VERIFY`/`CKA_WRAP`/`CKA_UNWRAP`/`CKA_DERIVE` is
`CK_TRUE`, not `CK_FALSE` (confirmed against real NSS and SoftHSM tokens) — leaving a role out of a
template does not refuse it, it grants it. `SecretKeyTemplateBuilder`, `PublicKeyTemplateBuilder`,
and `PrivateKeyTemplateBuilder` all set every applicable capability attribute to `false` at
construction, the same fail-safe-default pattern used for `CKA_SENSITIVE`/`CKA_EXTRACTABLE`; a
caller opts in to each role explicitly via `.Encrypt()`, `.Sign()`, `.Wrap()`, and so on.

<a id="wrap-hardening"></a>
## Wrap hardening

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

As with every attribute, these controls are enforced by the token ([Trust boundaries](#trust-boundaries)).

<a id="algorithm-notes"></a>
## Algorithm notes

**SHA-224 is refused for a different reason than the broken hashes: it isn't cryptographically
weak.** It's FIPS 180-4-approved — just a truncated SHA-256 with no `HashAlgorithmName` constant in
the BCL and no practical benefit over SHA-256 on equal-cost hardware. RSA PKCS#1/PSS signing,
RSA-OAEP, ECDSA signing, and HMAC all accept it behind a policy that permits it (e.g.
`UsePolicy(CryptoPolicy.AllowInsecure)`), for interop with a token or protocol that specifically
requires it.

**RSA PKCS#1 v1.5 signatures are a deliberate exception.** Strong-hash v1.5 *signatures*
(`CKM_SHA256_RSA_PKCS` and up) are allowed by default: RSASSA-PKCS1-v1_5 with a strong hash is
FIPS 186-5-approved and mandated by ubiquitous interop — JWT `RS256`, TLS 1.2 `CertificateVerify`,
X.509 chains, code signing — and because the gate also governs verification, blocking them would
break verifying third-party signatures. Only v1.5 over a *broken hash*, and v1.5 *encryption* / raw
RSA (Bleichenbacher / ROBOT territory), are gated. Prefer RSA-PSS for new code all the same.

**PKCS#1 v1.5 decryption may succeed on invalid padding.** Tokens that implement implicit rejection
return a synthetic plaintext instead of failing; never treat the outcome of PKCS#1 v1.5 decryption as a
signal. See [PKCS#1 v1.5 decryption and implicit rejection](../diagnostics.md#pkcs1-implicit-rejection).

**AES-GCM and AES-CCM fix the tag size at construction.** `AesGcmPkcs11(key, tagSizeInBytes)` and
`AesCcmPkcs11(key, tagSizeInBytes)` refuse a tag of any other length on `Decrypt`. Taking the size from
each call, as `AesGcm(key)` did before it was made obsolete (SYSLIB0053) and as `AesCcm(key)` still does,
would let an attacker who controls the ciphertext submit a forged tag of the shortest legal length.

<a id="secrets-in-memory"></a>
## Secrets in memory

- **PINs: `SecurePin`.** Holds the PIN in a buffer on the pinned object heap, so the garbage collector
  never moves it and cannot leave stale copies, and zeroes it on disposal (a finalizer is the safety net,
  not a substitute). Prefer the `SecurePin(ReadOnlySpan<char>)` constructor: the characters are encoded
  straight into the pinned buffer, so no string or intermediate array holds the PIN; zero your own buffer
  afterwards. The `SecurePin(string)` constructor works, but the string itself cannot be reliably zeroed.
  No Unicode normalization is applied: tokens compare PIN bytes exactly.
- **Passwords for key derivation: `SecurePassword`.** The same design, for the input of PBKDF2
  (`Rfc2898DeriveBytesPkcs11`).
- **Unmanaged buffers.** The unmanaged buffers the library allocates for attribute values (such as an
  imported key's `CKA_VALUE`), mechanism parameters (IVs, nonces, AAD, contexts) and values read back from
  the token are released through one routine that zeroes them with `CryptographicOperations.ZeroMemory`
  first. Attribute buffers
  are owned by `ObjectTemplate` and `ObjectAttribute`: dispose them; their finalizers zero what a caller
  forgets.
- **Intermediate managed buffers.** Where an adapter receives a plaintext or a secret into a temporary
  array before copying it into your destination (AES-GCM, AES-CCM and ChaCha20-Poly1305 decryption, the
  ECDH shared secret before its KDF, ML-KEM, HKDF, PBKDF2), it zeroes that array afterwards.
- **What the library cannot zero.** Arrays it returns to you are yours: methods that return a secret as a
  `byte[]` (a derived key, a shared secret, a decrypted plaintext) leave it to you to call
  `CryptographicOperations.ZeroMemory` when done. Prefer the overloads that write into a `Span<byte>` you
  own, or that keep the derived key on the token.
