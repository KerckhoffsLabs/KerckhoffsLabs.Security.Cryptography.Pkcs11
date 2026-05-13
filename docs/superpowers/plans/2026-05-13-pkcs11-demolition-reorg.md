# PKCS11 Demolition + Reorg Implementation Plan (Plan 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the project layout to the spec-final shape: providers + core types at root, exceptions in `Exceptions/`, object templates in `Objects/`, high-level mechanism params in `MechanismParams/`, native raw params renamed to `Native/RawMechanismParams/`, `Session` renamed to `Pkcs11Session` and demoted to `Internal/`, `ObjectHandle` demoted to `Internal/`, `SecurePin` lifted to root, `SecureBuffer` moved to `Internal/`, and the corresponding test layout straightened out under `Algorithms/`.

**Architecture:** Pure relocation + visibility demotion. No new functionality. Every task is a focused `git mv` + namespace edit + consumer-using update + build + test + commit cycle. Tests stay green at every step.

**Tech Stack:** C# 12 / .NET 8+9. Multi-targeted production project; tests target `net9.0` only. xUnit 2.9. `InternalsVisibleTo` is already configured for the test assembly (verified via existing internal accessors used in tests).

**Spec:** `docs/superpowers/specs/2026-05-13-pkcs11-bcl-aligned-redesign-design.md`

**Working directory:** `/home/alexandre/dev/PKCS11.NET` (git repo, branch `main`).

---

## Scope

Plan 4 lands the migration plan steps 5 and 6 from the spec:

- Move `Security/SecurePin.cs` → root.
- Move `Security/SecureBuffer.cs` → `Internal/`.
- Move exception classes from `Common/` → `Exceptions/`.
- Move `Common/ExceptionMapper.cs` → `Internal/`.
- Move `HighLevel/MechanismParams/*` → `MechanismParams/` (root namespace `MechanismParams`).
- Rename `Native/MechanismParams/` → `Native/RawMechanismParams/`.
- Move `HighLevel/Object{Template*, Attribute, TemplateBuilder*}.cs` → `Objects/`.
- Move providers (`RSAPkcs11.cs`, `ECDsaPkcs11.cs`, `AesGcmPkcs11.cs`, `AesCcmPkcs11.cs`, `ChaCha20Poly1305Pkcs11.cs`, `HMACPkcs11.cs`, `Pkcs11MechanismMap.cs`, `Pkcs11PublicKeyView.cs`) from `HighLevel/` → root.
- Move core types (`Pkcs11Library.cs`, `Pkcs11Workspace*.cs`, `Pkcs11Key*.cs`, `Mechanism.cs`, `IMechanismParams.cs`) from `HighLevel/` → root.
- Move auxiliary public types from `HighLevel/` → root, renaming `Slot.cs` → `Pkcs11Slot.cs` (`AppType`, `EcCurve`, `InitType`, `LibraryInfo`, `MechanismFlags`, `MechanismInfo`, `MiscSettings`, `SessionFlags`, `SessionInfo`, `SessionType`, `SlotFlags`, `SlotInfo`, `SlotsType`, `TokenFlags`, `TokenInfo`, `WaitType`).
- Rename `HighLevel/Session.cs` (+ all `Session.*.cs` partials) → `Internal/Pkcs11Session.cs` (and `Pkcs11Session.*.cs` partials), and demote the type to `internal`.
- Move `HighLevel/ObjectHandle.cs` → `Internal/ObjectHandle.cs` and demote to `internal`.
- Move `LowLevel/SafeHandles/{Pkcs11ModuleHandle.cs, Pkcs11SessionHandle.cs}` → `Internal/SafeHandles/`.
- Reorganize test files: move all `HighLevel/*Pkcs11Tests.cs` (the new BCL provider tests) → `Algorithms/`, move `HighLevel/{Auth, Decrypt, Derive, Digest, Encrypt, Keys, Sign, Verify}` mechanism-level tests → `Algorithms/{Decrypt,...}/` or keep grouped, move `Security/Secure*Tests.cs` to mirror new prod layout, move `LowLevel/SafeHandles/*Tests.cs` → `Internal/SafeHandles/`.
- Final sanity sweep: zero references to `HighLevel`, `LowLevel`, `Security` namespaces; release build green; full test suite green.

**Not in scope** (deferred to a future plan):
- Introducing `IPkcs11Library` mock seam (spec decision §8).
- Introducing `FakePkcs11Library` and the `Fakes/` test folder.
- `AesPkcs11` (CBC/CTR/ECB) and `ECDiffieHellmanPkcs11` providers (deferred from Plan 3).

---

## Project conventions

- **Build:** `dotnet build src/KerckhoffsLabs.sln -c Debug`.
- **Test (targeted):** `dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj -c Debug --filter "FullyQualifiedName~<Pattern>"`.
- **Test (full):** `dotnet test src/KerckhoffsLabs.sln -c Debug`.
- **Release build:** `dotnet build src/KerckhoffsLabs.sln -c Release`.
- **Git moves:** always `git mv` (preserves history). Never `cp + rm`.
- **Namespace edits:** prefer the implementation file's `namespace X` declaration over a per-file `using` change at the consumer side, *except* when a sub-namespace introduces a new directory — in that case, consumers add `using NewNamespace;`.
- **Commit message style:** `refactor(<area>): <one-line summary>` followed by a short body explaining what moved and why, signed `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.
- **Baseline test count to maintain:** After Plan 3, the full Debug suite reports `Passed: 252 / Skipped: 102 / Total: 354 / Failed: 0`. This MUST stay green (with the same `Passed` count or higher) after every task.

---

## File-by-file move table

This table captures every file move in Plan 4. Each task below executes a slice of it.

| Current path | New path | Namespace change | Visibility change | Task |
|---|---|---|---|---|
| `Security/SecurePin.cs` | `SecurePin.cs` (root) | `.Security` → root | none | 1 |
| `Security/SecureBuffer.cs` | `Internal/SecureBuffer.cs` | `.Security` → `.Internal` | none (already `internal`) | 2 |
| `Common/AttributeValueException.cs` | `Exceptions/AttributeValueException.cs` | `.Common` → `.Exceptions` | none | 3 |
| `Common/InsecureOperationException.cs` | `Exceptions/InsecureOperationException.cs` | `.Common` → `.Exceptions` | none | 3 |
| `Common/InvalidEnumValueException.cs` | `Exceptions/InvalidEnumValueException.cs` | `.Common` → `.Exceptions` | none | 3 |
| `Common/Pkcs11Exception.cs` | `Exceptions/Pkcs11Exception.cs` | `.Common` → `.Exceptions` | none | 3 |
| `Common/Pkcs11ArgumentException.cs` | `Exceptions/Pkcs11ArgumentException.cs` | `.Common` → `.Exceptions` | none | 3 |
| `Common/Pkcs11AuthenticationException.cs` | `Exceptions/Pkcs11AuthenticationException.cs` | `.Common` → `.Exceptions` | none | 3 |
| `Common/Pkcs11MechanismException.cs` | `Exceptions/Pkcs11MechanismException.cs` | `.Common` → `.Exceptions` | none | 3 |
| `Common/Pkcs11ObjectException.cs` | `Exceptions/Pkcs11ObjectException.cs` | `.Common` → `.Exceptions` | none | 3 |
| `Common/Pkcs11SessionException.cs` | `Exceptions/Pkcs11SessionException.cs` | `.Common` → `.Exceptions` | none | 3 |
| `Common/Pkcs11TokenException.cs` | `Exceptions/Pkcs11TokenException.cs` | `.Common` → `.Exceptions` | none | 3 |
| `Common/Pkcs11UnclassifiedException.cs` | `Exceptions/Pkcs11UnclassifiedException.cs` | `.Common` → `.Exceptions` | none | 3 |
| `Common/ExceptionMapper.cs` | `Internal/ExceptionMapper.cs` | `.Common` → `.Internal` | already `internal` | 3 |
| `HighLevel/MechanismParams/CkmAesGcmParams.cs` | `MechanismParams/CkmAesGcmParams.cs` | `.HighLevel.MechanismParams` → `.MechanismParams` | none | 4 |
| `HighLevel/MechanismParams/CkmAesCcmParams.cs` | `MechanismParams/CkmAesCcmParams.cs` | `.HighLevel.MechanismParams` → `.MechanismParams` | none | 4 |
| `HighLevel/MechanismParams/CkmEcdh1DeriveParams.cs` | `MechanismParams/CkmEcdh1DeriveParams.cs` | `.HighLevel.MechanismParams` → `.MechanismParams` | none | 4 |
| `HighLevel/MechanismParams/CkmRsaPkcsOaepParams.cs` | `MechanismParams/CkmRsaPkcsOaepParams.cs` | `.HighLevel.MechanismParams` → `.MechanismParams` | none | 4 |
| `HighLevel/MechanismParams/CkmRsaPkcsPssParams.cs` | `MechanismParams/CkmRsaPkcsPssParams.cs` | `.HighLevel.MechanismParams` → `.MechanismParams` | none | 4 |
| `HighLevel/MechanismParams/CkmSalsa20ChaCha20Poly1305Params.cs` | `MechanismParams/CkmSalsa20ChaCha20Poly1305Params.cs` | `.HighLevel.MechanismParams` → `.MechanismParams` | none | 4 |
| `HighLevel/IMechanismParams.cs` | `MechanismParams/IMechanismParams.cs` | `.HighLevel` → `.MechanismParams` | none | 4 |
| `Native/MechanismParams/*` (~60 files) | `Native/RawMechanismParams/*` | `.Native.MechanismParams` → `.Native.RawMechanismParams` | none | 5 |
| `HighLevel/ObjectAttribute.cs` | `Objects/ObjectAttribute.cs` | `.HighLevel` → `.Objects` | none | 6 |
| `HighLevel/ObjectTemplate.cs` | `Objects/ObjectTemplate.cs` | `.HighLevel` → `.Objects` | none | 6 |
| `HighLevel/ObjectTemplateBuilderBase.cs` | `Objects/ObjectTemplateBuilderBase.cs` | `.HighLevel` → `.Objects` | none | 6 |
| `HighLevel/CertificateTemplateBuilder.cs` | `Objects/CertificateTemplateBuilder.cs` | `.HighLevel` → `.Objects` | none | 6 |
| `HighLevel/DataTemplateBuilder.cs` | `Objects/DataTemplateBuilder.cs` | `.HighLevel` → `.Objects` | none | 6 |
| `HighLevel/GenericTemplateBuilder.cs` | `Objects/GenericTemplateBuilder.cs` | `.HighLevel` → `.Objects` | none | 6 |
| `HighLevel/PublicKeyTemplateBuilder.cs` | `Objects/PublicKeyTemplateBuilder.cs` | `.HighLevel` → `.Objects` | none | 6 |
| `HighLevel/PrivateKeyTemplateBuilder.cs` | `Objects/PrivateKeyTemplateBuilder.cs` | `.HighLevel` → `.Objects` | none | 6 |
| `HighLevel/SecretKeyTemplateBuilder.cs` | `Objects/SecretKeyTemplateBuilder.cs` | `.HighLevel` → `.Objects` | none | 6 |
| `HighLevel/RSAPkcs11.cs` | `RSAPkcs11.cs` (root) | `.HighLevel` → root | none | 7 |
| `HighLevel/ECDsaPkcs11.cs` | `ECDsaPkcs11.cs` (root) | `.HighLevel` → root | none | 7 |
| `HighLevel/AesGcmPkcs11.cs` | `AesGcmPkcs11.cs` (root) | `.HighLevel` → root | none | 7 |
| `HighLevel/AesCcmPkcs11.cs` | `AesCcmPkcs11.cs` (root) | `.HighLevel` → root | none | 7 |
| `HighLevel/ChaCha20Poly1305Pkcs11.cs` | `ChaCha20Poly1305Pkcs11.cs` (root) | `.HighLevel` → root | none | 7 |
| `HighLevel/HMACPkcs11.cs` | `HMACPkcs11.cs` (root) | `.HighLevel` → root | none | 7 |
| `HighLevel/Pkcs11MechanismMap.cs` | `Pkcs11MechanismMap.cs` (root) | `.HighLevel` → root | none (already `internal`) | 7 |
| `HighLevel/Pkcs11PublicKeyView.cs` | `Pkcs11PublicKeyView.cs` (root) | `.HighLevel` → root | none (already `internal`) | 7 |
| `HighLevel/Pkcs11Library.cs` | `Pkcs11Library.cs` (root) | `.HighLevel` → root | none | 8 |
| `HighLevel/Pkcs11Workspace.cs` | `Pkcs11Workspace.cs` (root) | `.HighLevel` → root | none | 8 |
| `HighLevel/Pkcs11Workspace.Keys.cs` | `Pkcs11Workspace.Keys.cs` (root) | `.HighLevel` → root | none | 8 |
| `HighLevel/Pkcs11Workspace.Random.cs` | `Pkcs11Workspace.Random.cs` (root) | `.HighLevel` → root | none | 8 |
| `HighLevel/Pkcs11Key.cs` | `Pkcs11Key.cs` (root) | `.HighLevel` → root | none | 8 |
| `HighLevel/Pkcs11Key.Mechanism.cs` | `Pkcs11Key.Mechanism.cs` (root) | `.HighLevel` → root | none | 8 |
| `HighLevel/Mechanism.cs` | `Mechanism.cs` (root) | `.HighLevel` → root | none | 8 |
| `HighLevel/Slot.cs` | `Pkcs11Slot.cs` (root, RENAMED) | `.HighLevel` → root | none | 9 |
| `HighLevel/AppType.cs` | `AppType.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/EcCurve.cs` | `EcCurve.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/InitType.cs` | `InitType.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/LibraryInfo.cs` | `LibraryInfo.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/MechanismFlags.cs` | `MechanismFlags.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/MechanismInfo.cs` | `MechanismInfo.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/MiscSettings.cs` | `MiscSettings.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/SessionFlags.cs` | `SessionFlags.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/SessionInfo.cs` | `SessionInfo.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/SessionType.cs` | `SessionType.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/SlotFlags.cs` | `SlotFlags.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/SlotInfo.cs` | `SlotInfo.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/SlotsType.cs` | `SlotsType.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/TokenFlags.cs` | `TokenFlags.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/TokenInfo.cs` | `TokenInfo.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/WaitType.cs` | `WaitType.cs` (root) | `.HighLevel` → root | none | 9 |
| `HighLevel/Session.cs` | `Internal/Pkcs11Session.cs` (RENAMED) | `.HighLevel` → `.Internal` | `public` → `internal` | 10 |
| `HighLevel/Session.Decrypt.cs` | `Internal/Pkcs11Session.Decrypt.cs` (RENAMED) | `.HighLevel` → `.Internal` | partial: matches Pkcs11Session | 10 |
| `HighLevel/Session.Derive.cs` | `Internal/Pkcs11Session.Derive.cs` (RENAMED) | `.HighLevel` → `.Internal` | partial: matches Pkcs11Session | 10 |
| `HighLevel/Session.Digest.cs` | `Internal/Pkcs11Session.Digest.cs` (RENAMED) | `.HighLevel` → `.Internal` | partial: matches Pkcs11Session | 10 |
| `HighLevel/Session.Encrypt.cs` | `Internal/Pkcs11Session.Encrypt.cs` (RENAMED) | `.HighLevel` → `.Internal` | partial: matches Pkcs11Session | 10 |
| `HighLevel/Session.Keys.cs` | `Internal/Pkcs11Session.Keys.cs` (RENAMED) | `.HighLevel` → `.Internal` | partial: matches Pkcs11Session | 10 |
| `HighLevel/Session.Objects.cs` | `Internal/Pkcs11Session.Objects.cs` (RENAMED) | `.HighLevel` → `.Internal` | partial: matches Pkcs11Session | 10 |
| `HighLevel/Session.Random.cs` | `Internal/Pkcs11Session.Random.cs` (RENAMED) | `.HighLevel` → `.Internal` | partial: matches Pkcs11Session | 10 |
| `HighLevel/Session.Sign.cs` | `Internal/Pkcs11Session.Sign.cs` (RENAMED) | `.HighLevel` → `.Internal` | partial: matches Pkcs11Session | 10 |
| `HighLevel/Session.Verify.cs` | `Internal/Pkcs11Session.Verify.cs` (RENAMED) | `.HighLevel` → `.Internal` | partial: matches Pkcs11Session | 10 |
| `HighLevel/ObjectHandle.cs` | `Internal/ObjectHandle.cs` | `.HighLevel` → `.Internal` | `public` → `internal` | 11 |
| `LowLevel/SafeHandles/Pkcs11ModuleHandle.cs` | `Internal/SafeHandles/Pkcs11ModuleHandle.cs` | `.LowLevel.SafeHandles` → `.Internal.SafeHandles` | already `internal` | 12 |
| `LowLevel/SafeHandles/Pkcs11SessionHandle.cs` | `Internal/SafeHandles/Pkcs11SessionHandle.cs` | `.LowLevel.SafeHandles` → `.Internal.SafeHandles` | already `internal` | 12 |

Test moves: Task 13.
Final sweep: Task 14.

---

## Task list

### Task 1: Move `SecurePin` to root

**Files:**
- Move: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/SecurePin.cs` → `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/SecurePin.cs`

- [ ] **Step 1: Inspect SecurePin's dependencies**

```bash
grep -n "^namespace\|^using" /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/SecurePin.cs
```

Expected: shows `namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;` and any `using` lines.

Inspect what depends on `SecurePin`:
```bash
grep -rn "KerckhoffsLabs.Security.Cryptography.Pkcs11.Security\|using.*\.Security;" /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs" | grep -v "Security/SecureBuffer\|Security/SecurePin"
```

Note every consumer file path — they'll need their `using` removed (since the new namespace is the root namespace, which is already in scope of any file referencing other root-namespace types).

- [ ] **Step 2: Move the file via git**

```bash
cd /home/alexandre/dev/PKCS11.NET
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/SecurePin.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/SecurePin.cs
```

- [ ] **Step 3: Update the namespace in the moved file**

Change line 1 of `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/SecurePin.cs`:

```csharp
// before:
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;

// after:
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;
```

- [ ] **Step 4: Update consumers**

For every file identified in Step 1 that uses `SecurePin`:
- If the file is in a different namespace, remove the `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;` line **only if** no other `.Security` type (currently only `SecureBuffer`) is also referenced from the same file. If the line is shared with `SecureBuffer`, leave it for Task 2 to remove.
- If the file is in the root `KerckhoffsLabs.Security.Cryptography.Pkcs11` namespace, the `using` is now redundant — remove it.

Use a quick sweep to find affected files:

```bash
grep -rln "using KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.Security" /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs"
```

For each file: open, find the `using`, decide if `SecurePin` is the only `.Security` reference, and act accordingly.

- [ ] **Step 5: Build**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 errors. Warnings may remain (pre-existing).

- [ ] **Step 6: Run full test suite**

```bash
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: `Passed: 252` (or higher), `Failed: 0`.

- [ ] **Step 7: Commit**

```bash
cd /home/alexandre/dev/PKCS11.NET
git add -A
git commit -m "$(cat <<'EOF'
refactor(layout): move SecurePin from Security/ to root

Per spec final layout (decision §5 of migration plan), SecurePin is a
public root-namespace type. Pure relocation: file moved via git mv,
namespace declaration updated, consumer using-statements pruned.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Move `SecureBuffer` to `Internal/`

**Files:**
- Move: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/SecureBuffer.cs` → `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/SecureBuffer.cs`
- Delete: empty `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/` directory after the move.

- [ ] **Step 1: Inspect current state**

```bash
ls /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/
```

Expected: `SecureBuffer.cs` should be the only file remaining (`SecurePin.cs` was moved in Task 1).

```bash
grep -rln "SecureBuffer\|\.Security\.SecureBuffer" /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs"
```

Note all consumers.

- [ ] **Step 2: Create `Internal/` directory and move the file**

```bash
cd /home/alexandre/dev/PKCS11.NET
mkdir -p src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/SecureBuffer.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/SecureBuffer.cs
```

- [ ] **Step 3: Update the namespace in the moved file**

In `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/SecureBuffer.cs`:

```csharp
// before:
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;

// after:
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
```

Verify the type's visibility is `internal` (it should already be — confirm).

- [ ] **Step 4: Update consumers**

For each consumer identified in Step 1:
- Remove `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;`
- Add `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;` if the file is not already in `.Internal`.

Production-side consumers (likely `SecurePin.cs`, `LowLevelPkcs11Library.cs`, any others touching unmanaged-pinned buffers).

Test-side consumers: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Security/SecureBufferTests.cs` will be moved in Task 13 — for now just update its `using` to point to `.Internal`.

- [ ] **Step 5: Delete empty `Security/` directory**

```bash
rmdir src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security
```

Should succeed if no files remain. If it fails, list contents and resolve before proceeding.

- [ ] **Step 6: Build + test**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: 0 errors. `Passed: 252` or higher.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(layout): move SecureBuffer from Security/ to Internal/

Per spec final layout, SecureBuffer is internal plumbing. Moves to
the new Internal/ folder (which is also the future home of
Pkcs11Session, ObjectHandle, and the SafeHandles). The empty
Security/ folder is removed as part of the same task.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Move exception types to `Exceptions/` and `ExceptionMapper` to `Internal/`

**Files moved:**
- 12 exception classes from `Common/` → `Exceptions/`.
- `Common/ExceptionMapper.cs` → `Internal/ExceptionMapper.cs`.

**Files kept in `Common/`:** the CK*.cs enum files only.

- [ ] **Step 1: Inspect current state**

```bash
ls /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/ | sort
```

Expected: 16 CK*.cs files + 13 exception/mapper files.

```bash
grep -rln "using KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.Common" /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs" | wc -l
```

Note the count — this is roughly the number of consumers that may need re-pointing.

- [ ] **Step 2: Create new folders and move files**

```bash
cd /home/alexandre/dev/PKCS11.NET
mkdir -p src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Exceptions

for f in AttributeValueException InsecureOperationException InvalidEnumValueException \
         Pkcs11Exception Pkcs11ArgumentException Pkcs11AuthenticationException \
         Pkcs11MechanismException Pkcs11ObjectException Pkcs11SessionException \
         Pkcs11TokenException Pkcs11UnclassifiedException; do
    git mv "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/${f}.cs" \
           "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Exceptions/${f}.cs"
done

git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/ExceptionMapper.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/ExceptionMapper.cs
```

- [ ] **Step 3: Update namespaces in moved files**

For every `Exceptions/*.cs` file: change `namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;` → `namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;`.

For `Internal/ExceptionMapper.cs`: change `.Common` → `.Internal`.

Quick verification:

```bash
grep -n "^namespace" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Exceptions/*.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/ExceptionMapper.cs
```

Expected: all `Exceptions/*.cs` show `.Exceptions`; `ExceptionMapper.cs` shows `.Internal`.

- [ ] **Step 4: Update consumers**

Strategy: every file that currently does `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;` to reach an exception type now also needs `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;`. If the file only used `Common` for exceptions (not enums), the `.Common` using can be removed; otherwise it must be kept (for CK enums).

The simplest approach: **add `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;` to every file that referenced any exception type, and leave `.Common` alone**. The `.Common` using stays valid for the CK enums; the new `.Exceptions` using picks up the exception types.

Files likely affected (run the grep to confirm):

```bash
grep -rln "Pkcs11Exception\|ExceptionMapper\|InsecureOperationException\|InvalidEnumValueException\|AttributeValueException\|Pkcs11ArgumentException\|Pkcs11AuthenticationException\|Pkcs11MechanismException\|Pkcs11ObjectException\|Pkcs11SessionException\|Pkcs11TokenException\|Pkcs11UnclassifiedException" \
    /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs" | sort -u
```

For each file in that list:
1. If `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;` is not already present, add it.
2. For `ExceptionMapper` references: ensure `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;` is present.
3. Do not delete the existing `.Common` using (CK enums still live there).

- [ ] **Step 5: Build**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 errors. If `CS0246 (type or namespace not found)` appears, identify the file and add the missing `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;` or `.Internal;`.

- [ ] **Step 6: Run tests**

```bash
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: `Passed: 252` or higher, `Failed: 0`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(layout): split exceptions to Exceptions/ and ExceptionMapper to Internal/

Per spec, Common/ keeps only the CK* spec enums. The 11 typed Pkcs11
exception subclasses + InsecureOperationException + InvalidEnumValueException +
AttributeValueException all move to Exceptions/. ExceptionMapper moves
to Internal/ since it's plumbing the public surface shouldn't see.

Consumers gain `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;`
where they reference an exception type; the existing `.Common` using stays
valid for the enums.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Move high-level mechanism params from `HighLevel/MechanismParams/` to `MechanismParams/`

**Files:**
- Move 6 `Ckm*Params.cs` files + `IMechanismParams.cs` from `HighLevel/MechanismParams/` (and `HighLevel/` for `IMechanismParams`) → `MechanismParams/`.
- Delete empty `HighLevel/MechanismParams/` directory.

- [ ] **Step 1: Move the files**

```bash
cd /home/alexandre/dev/PKCS11.NET
mkdir -p src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams

for f in CkmAesGcmParams CkmAesCcmParams CkmEcdh1DeriveParams \
         CkmRsaPkcsOaepParams CkmRsaPkcsPssParams CkmSalsa20ChaCha20Poly1305Params; do
    git mv "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/MechanismParams/${f}.cs" \
           "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/${f}.cs"
done

git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/IMechanismParams.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/IMechanismParams.cs

rmdir src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/MechanismParams
```

- [ ] **Step 2: Update namespaces in moved files**

Each `MechanismParams/Ckm*.cs` and `MechanismParams/IMechanismParams.cs`:

```csharp
// before:
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;
// or
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

// after:
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
```

Verify:

```bash
grep -n "^namespace" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/*.cs
```

Expected: all show `.MechanismParams`.

- [ ] **Step 3: Update consumers**

```bash
grep -rln "KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.HighLevel\.MechanismParams" \
    /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs"
```

For each consumer:
- Replace `using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;` with `using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;`.

Also search for files using `IMechanismParams` reached via just `.HighLevel`:

```bash
grep -rln "IMechanismParams" /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs"
```

Confirm each file has access to the new namespace.

- [ ] **Step 4: Build + test**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: 0 errors. `Passed: 252` or higher.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(layout): lift HighLevel/MechanismParams/ to root MechanismParams/

Per spec, high-level typed mechanism param wrappers (Ckm*Params.cs)
and the IMechanismParams interface live at root namespace
KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams, alongside
the public providers. The HighLevel/ folder is being demolished
incrementally.

Native/MechanismParams/ (raw unmanaged-layout structs) is unaffected
by this task — it gets renamed to Native/RawMechanismParams/ in Task 5.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Rename `Native/MechanismParams/` → `Native/RawMechanismParams/`

**Files:** ~60 `CK_*_PARAMS.cs` files + supporting types in `Native/MechanismParams/`.

- [ ] **Step 1: Move the directory**

```bash
cd /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11
git mv Native/MechanismParams Native/RawMechanismParams
```

- [ ] **Step 2: Update namespaces in moved files**

Bulk update — every file in the new directory:

```bash
cd /home/alexandre/dev/PKCS11.NET
find src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/RawMechanismParams -name "*.cs" -type f | \
  xargs sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.Native\.MechanismParams;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;|'
```

Verify:

```bash
grep -h "^namespace" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/RawMechanismParams/*.cs | sort -u
```

Expected: single line `namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;`.

- [ ] **Step 3: Update consumers**

```bash
grep -rln "KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.Native\.MechanismParams" \
    /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs"
```

For each consumer, replace the using-statement:

```bash
find /home/alexandre/dev/PKCS11.NET/src -name "*.cs" -type f | \
  xargs sed -i 's|KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.Native\.MechanismParams|KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams|g'
```

This is safe: a global find-and-replace of the full namespace path. No collisions possible.

- [ ] **Step 4: Build + test**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: 0 errors. `Passed: 252` or higher.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(layout): rename Native/MechanismParams to Native/RawMechanismParams

Per spec, the unmanaged-layout PKCS#11 mechanism param structs live in
Native/RawMechanismParams/ to disambiguate from the high-level typed
wrappers at root MechanismParams/. Pure rename via git mv + bulk
namespace and using-statement updates across ~60 files.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Move object-template types to `Objects/`

**Files:** 9 files from `HighLevel/` → `Objects/`:
- `ObjectAttribute.cs`
- `ObjectTemplate.cs`
- `ObjectTemplateBuilderBase.cs`
- `CertificateTemplateBuilder.cs`
- `DataTemplateBuilder.cs`
- `GenericTemplateBuilder.cs`
- `PublicKeyTemplateBuilder.cs`
- `PrivateKeyTemplateBuilder.cs`
- `SecretKeyTemplateBuilder.cs`

- [ ] **Step 1: Move the files**

```bash
cd /home/alexandre/dev/PKCS11.NET
mkdir -p src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects

for f in ObjectAttribute ObjectTemplate ObjectTemplateBuilderBase \
         CertificateTemplateBuilder DataTemplateBuilder GenericTemplateBuilder \
         PublicKeyTemplateBuilder PrivateKeyTemplateBuilder SecretKeyTemplateBuilder; do
    git mv "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/${f}.cs" \
           "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/${f}.cs"
done
```

- [ ] **Step 2: Update namespaces**

For each moved file:

```csharp
// before:
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

// after:
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
```

Bulk update:

```bash
cd /home/alexandre/dev/PKCS11.NET
for f in src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/*.cs; do
  sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.HighLevel;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;|' "$f"
done
```

- [ ] **Step 3: Update consumers**

For every file that uses `ObjectTemplate.For*`, `ObjectAttribute`, a template builder, or `ObjectTemplate.Empty`, add `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;`.

Quick sweep:

```bash
grep -rln "ObjectTemplate\|ObjectAttribute\|TemplateBuilder" /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs"
```

For each file: check if it has `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;` or `using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;`. If only the latter, add the former (the `.HighLevel` using can stay for now — it'll be cleaned in Task 14).

- [ ] **Step 4: Build + test**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: 0 errors. `Passed: 252` or higher.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(layout): move ObjectTemplate + ObjectAttribute + builders to Objects/

Per spec, the fluent object-template API lives under Objects/
(ObjectTemplate, ObjectAttribute, ObjectTemplateBuilderBase, and the
five concrete builder subclasses). Pure relocation.

Consumers gain `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;`.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Move BCL providers + helpers from `HighLevel/` to root

**Files:** 8 files from `HighLevel/` → root:
- `RSAPkcs11.cs`
- `ECDsaPkcs11.cs`
- `AesGcmPkcs11.cs`
- `AesCcmPkcs11.cs`
- `ChaCha20Poly1305Pkcs11.cs`
- `HMACPkcs11.cs`
- `Pkcs11MechanismMap.cs` (internal)
- `Pkcs11PublicKeyView.cs` (internal)

- [ ] **Step 1: Move the files**

```bash
cd /home/alexandre/dev/PKCS11.NET
for f in RSAPkcs11 ECDsaPkcs11 AesGcmPkcs11 AesCcmPkcs11 ChaCha20Poly1305Pkcs11 HMACPkcs11 Pkcs11MechanismMap Pkcs11PublicKeyView; do
    git mv "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/${f}.cs" \
           "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/${f}.cs"
done
```

- [ ] **Step 2: Update namespaces**

For each moved file:

```csharp
// before:
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

// after:
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;
```

Bulk:

```bash
for f in RSAPkcs11 ECDsaPkcs11 AesGcmPkcs11 AesCcmPkcs11 ChaCha20Poly1305Pkcs11 HMACPkcs11 Pkcs11MechanismMap Pkcs11PublicKeyView; do
  sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.HighLevel;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;|' \
    "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/${f}.cs"
done
```

- [ ] **Step 3: Update consumers**

These types are now in the **root** namespace. Files in the root namespace don't need any `using` to reach them. Files in subnamespaces (`.Objects`, `.Exceptions`, `.Internal`, `.MechanismParams`, `.Native`, tests in `.Tests.*`) need `using KerckhoffsLabs.Security.Cryptography.Pkcs11;` to reach them.

Most consumers already have this `using` (or are in the root namespace themselves). Check:

```bash
grep -rln "RSAPkcs11\|ECDsaPkcs11\|AesGcmPkcs11\|AesCcmPkcs11\|ChaCha20Poly1305Pkcs11\|HMACPkcs11\|Pkcs11MechanismMap\|Pkcs11PublicKeyView" \
    /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs"
```

For each consumer not in the root namespace: ensure `using KerckhoffsLabs.Security.Cryptography.Pkcs11;` is present. If only `using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;` exists, add the root `using` alongside it (the HighLevel using will be cleaned in Task 14).

- [ ] **Step 4: Build + test**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: 0 errors. `Passed: 252` or higher.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(layout): lift BCL providers + helpers from HighLevel/ to root

Per spec, the BCL-aligned providers (RSAPkcs11, ECDsaPkcs11,
AesGcmPkcs11, AesCcmPkcs11, ChaCha20Poly1305Pkcs11, HMACPkcs11) live
at root namespace KerckhoffsLabs.Security.Cryptography.Pkcs11. The
two internal helpers used only by the providers (Pkcs11MechanismMap
and Pkcs11PublicKeyView) move alongside them.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Move core types (`Pkcs11Library`, `Pkcs11Workspace`, `Pkcs11Key`, `Mechanism`) from `HighLevel/` to root

**Files:** 7 files from `HighLevel/` → root:
- `Pkcs11Library.cs`
- `Pkcs11Workspace.cs`
- `Pkcs11Workspace.Keys.cs`
- `Pkcs11Workspace.Random.cs`
- `Pkcs11Key.cs`
- `Pkcs11Key.Mechanism.cs`
- `Mechanism.cs`

- [ ] **Step 1: Move the files**

```bash
cd /home/alexandre/dev/PKCS11.NET
for f in Pkcs11Library Pkcs11Workspace Pkcs11Workspace.Keys Pkcs11Workspace.Random \
         Pkcs11Key Pkcs11Key.Mechanism Mechanism; do
    git mv "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/${f}.cs" \
           "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/${f}.cs"
done
```

- [ ] **Step 2: Update namespaces**

```bash
for f in Pkcs11Library Pkcs11Workspace Pkcs11Workspace.Keys Pkcs11Workspace.Random \
         Pkcs11Key Pkcs11Key.Mechanism Mechanism; do
  sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.HighLevel;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;|' \
    "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/${f}.cs"
done
```

- [ ] **Step 3: Update consumers**

These types are heavily used. Consumers should reference them via the root namespace.

```bash
grep -rln "Pkcs11Library\|Pkcs11Workspace\|Pkcs11Key\|\bMechanism\b" \
    /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs" | sort -u
```

For each non-root-namespace file: ensure `using KerckhoffsLabs.Security.Cryptography.Pkcs11;` is present.

- [ ] **Step 4: Build + test**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: 0 errors. `Passed: 252` or higher.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(layout): lift core types (Library, Workspace, Key, Mechanism) to root

Per spec, the core public types Pkcs11Library, Pkcs11Workspace
(+ .Keys + .Random partials), Pkcs11Key (+ .Mechanism partial), and
Mechanism all live at root namespace
KerckhoffsLabs.Security.Cryptography.Pkcs11. Pure relocation.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Move auxiliary types + rename `Slot` → `Pkcs11Slot`

**Files:** 16 auxiliary public types from `HighLevel/` → root, with `Slot.cs` renamed to `Pkcs11Slot.cs`:
- `Slot.cs` → `Pkcs11Slot.cs` (with type rename `class Slot` → `class Pkcs11Slot`)
- `AppType.cs`, `EcCurve.cs`, `InitType.cs`, `LibraryInfo.cs`, `MechanismFlags.cs`, `MechanismInfo.cs`, `MiscSettings.cs`, `SessionFlags.cs`, `SessionInfo.cs`, `SessionType.cs`, `SlotFlags.cs`, `SlotInfo.cs`, `SlotsType.cs`, `TokenFlags.cs`, `TokenInfo.cs`, `WaitType.cs` (no rename)

- [ ] **Step 1: Move + rename `Slot` → `Pkcs11Slot`**

```bash
cd /home/alexandre/dev/PKCS11.NET
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Slot.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Slot.cs
```

In `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Slot.cs`:
- Change `namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;` → `namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;`.
- Find every `class Slot` / `Slot(` / `Slot ` declaration that refers to **this type** and rename to `Pkcs11Slot`. Be careful: `SlotsType`, `SlotFlags`, `SlotInfo` are different types that must NOT be renamed.

Most likely just one or two renames: `public sealed class Slot` → `public sealed class Pkcs11Slot`, and the constructor name. Tools that may help:

```bash
sed -i 's|\bpublic\(.*\)class Slot\b|public\1class Pkcs11Slot|g; s|\bSlot(|Pkcs11Slot(|g; s|public Slot\b|public Pkcs11Slot|g' \
  src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Slot.cs
```

Verify by reading the file:

```bash
grep -n "Slot\|Pkcs11Slot" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Slot.cs | head -20
```

Make sure `Slot` does not appear as a standalone identifier any more (except possibly in XML doc comments or `<see cref>` references — update those manually).

- [ ] **Step 2: Update consumers of the renamed `Slot` type**

```bash
grep -rln "\bSlot\b" /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs" | \
  xargs grep -l "Pkcs11Slot\|: Slot\|Slot \|Slot(" 2>/dev/null
```

This is tricky because `Slot` is a common substring. The safe approach: open each candidate file and inspect.

Likely callers:
- `Pkcs11Library.cs` — returns `IReadOnlyList<Slot>` from a `GetSlotList` (or similar) method. Rename `Slot` → `Pkcs11Slot` here.
- `Pkcs11Workspace.cs` — has `public Slot Slot => ...` property. Rename type to `Pkcs11Slot`.
- Test files referring to `Slot` instances or properties.

For each occurrence: confirm it refers to the moved type (not `SlotsType`/`SlotFlags`/`SlotInfo`), and rename.

- [ ] **Step 3: Move the 16 non-renamed auxiliary types**

```bash
cd /home/alexandre/dev/PKCS11.NET
for f in AppType EcCurve InitType LibraryInfo MechanismFlags MechanismInfo MiscSettings \
         SessionFlags SessionInfo SessionType SlotFlags SlotInfo SlotsType \
         TokenFlags TokenInfo WaitType; do
    git mv "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/${f}.cs" \
           "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/${f}.cs"
done
```

- [ ] **Step 4: Update namespaces in moved files**

```bash
for f in AppType EcCurve InitType LibraryInfo MechanismFlags MechanismInfo MiscSettings \
         SessionFlags SessionInfo SessionType SlotFlags SlotInfo SlotsType \
         TokenFlags TokenInfo WaitType; do
  sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.HighLevel;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;|' \
    "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/${f}.cs"
done
```

- [ ] **Step 5: Build**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 errors. If `CS0246` errors appear naming `Slot`, identify the consumer file and decide if it should be `Pkcs11Slot` (the renamed type) or one of `SlotFlags`/`SlotInfo`/`SlotsType` (separate types).

- [ ] **Step 6: Run full test suite**

```bash
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: `Passed: 252` or higher, `Failed: 0`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(layout): lift auxiliary public types to root, rename Slot → Pkcs11Slot

Moves 16 info/flags/enum types (AppType, EcCurve, *Flags, *Info,
*Type, LibraryInfo, etc.) from HighLevel/ to root namespace.

Also renames the public Slot type to Pkcs11Slot for naming consistency
with the rest of the Pkcs11-prefixed public surface (Pkcs11Library,
Pkcs11Workspace, Pkcs11Key). SlotFlags/SlotInfo/SlotsType retain their
names — they're distinct supporting types, not the slot itself.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Rename `Session` → `Pkcs11Session`, demote to internal, move to `Internal/`

**Files:** 10 partial-class files from `HighLevel/Session*.cs` → `Internal/Pkcs11Session*.cs`.

This is the most invasive task. `Session` is referenced by `Pkcs11Workspace`, `Pkcs11Key`, every `Session.*.cs` partial, the existing `HighLevel/` tests, and the new `HighLevel/Provider*Tests.cs` (which already do `workspace.Session.GenerateKey(...)` and `workspace.Session.DestroyObject(...)` via the internal accessor).

Visibility plan:
- Type goes from `public sealed partial class Session` → `internal sealed partial class Pkcs11Session`.
- The `Pkcs11Workspace.Session` accessor stays `internal Pkcs11Session Session => _session;` (already `internal`).
- Tests have `InternalsVisibleTo` access, so `workspace.Session.X(...)` calls remain valid.

- [ ] **Step 1: Verify current visibility of `Pkcs11Workspace.Session`**

```bash
grep -n "Session => \|internal Session\|public Session\|private.*_session" \
  /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.cs
```

Expected: `internal Session Session => _session;` (or similar). If `public`, that's a problem to fix.

- [ ] **Step 2: Move the files**

```bash
cd /home/alexandre/dev/PKCS11.NET
for f in Session Session.Decrypt Session.Derive Session.Digest Session.Encrypt \
         Session.Keys Session.Objects Session.Random Session.Sign Session.Verify; do
    new=$(echo "$f" | sed 's|^Session|Pkcs11Session|')
    git mv "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/${f}.cs" \
           "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/${new}.cs"
done
```

- [ ] **Step 3: Update namespaces + rename type + demote to internal**

```bash
cd /home/alexandre/dev/PKCS11.NET
for f in Pkcs11Session Pkcs11Session.Decrypt Pkcs11Session.Derive Pkcs11Session.Digest \
         Pkcs11Session.Encrypt Pkcs11Session.Keys Pkcs11Session.Objects Pkcs11Session.Random \
         Pkcs11Session.Sign Pkcs11Session.Verify; do
  path="src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/${f}.cs"
  sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.HighLevel;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;|' "$path"
  sed -i 's|public sealed partial class Session\b|internal sealed partial class Pkcs11Session|g' "$path"
  sed -i 's|public partial class Session\b|internal partial class Pkcs11Session|g' "$path"
  sed -i 's|\bpartial class Session\b|partial class Pkcs11Session|g' "$path"
  sed -i 's|public Session(|internal Pkcs11Session(|g' "$path"
done
```

Verify the type rename actually happened on every partial:

```bash
grep -nE "partial class (Session|Pkcs11Session)" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session*.cs
```

Expected: every file shows `internal sealed partial class Pkcs11Session` or `internal partial class Pkcs11Session`. None show `Session` (without the prefix).

Also check no public ctor remains:

```bash
grep -n "public Session\|public Pkcs11Session" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session*.cs
```

Expected: empty. If any `public Pkcs11Session(...)` ctor remains, change to `internal Pkcs11Session(...)`.

- [ ] **Step 4: Update consumers of the `Session` type**

The accessors `Pkcs11Workspace.Session` (returns `Session`/`Pkcs11Session`) and any other internal references all need the type name updated.

```bash
grep -rln "\bSession\b" /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11 --include="*.cs"
```

For each file, find references to the `Session` *type* (not `SessionType`/`SessionFlags`/`SessionInfo`/`session` lowercase field) and rename to `Pkcs11Session`.

Key files to edit:
- `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Workspace.cs` and its partials: change `private readonly Session _session;` → `private readonly Pkcs11Session _session;`, change `internal Session Session => _session;` → `internal Pkcs11Session Session => _session;`, change any `new Session(...)` ctor calls.
- `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs`: rename any `Session` references (e.g., `OpenSession` may return `Session`).
- `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs` and `Pkcs11Key.Mechanism.cs`: rename `Session` field/property references.
- Add `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;` to every file in the root namespace that references `Pkcs11Session` directly (Pkcs11Workspace.cs, Pkcs11Library.cs, Pkcs11Key.cs, Pkcs11Key.Mechanism.cs, RSAPkcs11.cs, ECDsaPkcs11.cs etc. if they touch `_key.Workspace.Session`).

- [ ] **Step 5: Update test consumers**

Tests reach `workspace.Session.GenerateKey(...)` via the internal accessor. After the rename:
- The accessor `Pkcs11Workspace.Session` now returns `Pkcs11Session` instead of `Session`.
- Tests that capture the result in a local need a type update if they did `Session s = workspace.Session;`. Most tests do `workspace.Session.X(...)` chained, so the rename is transparent.

Find any explicit `Session` type references in tests:

```bash
grep -rn "\bSession\b" /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests --include="*.cs" | \
  grep -v "SessionType\|SessionFlags\|SessionInfo\|session\." | head -30
```

Update any `Session` local-variable declarations to `Pkcs11Session` and add `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;` at the top.

If tests don't reference `Session` as a type (just chained calls), they're fine without edits.

- [ ] **Step 6: Build**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 errors. Most likely errors:
- `CS0246: Session not found` → consumer wasn't updated to `Pkcs11Session`. Find and fix.
- `CS0234: namespace doesn't contain Session` → consumer's `using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;` no longer reaches `Session`. Add `using ...Internal;`.

- [ ] **Step 7: Run tests**

```bash
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: `Passed: 252` or higher, `Failed: 0`.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(Session): rename to Pkcs11Session, demote to internal, move to Internal/

The Session type is implementation plumbing — Pkcs11Workspace already
exposes the user-facing functionality. Per spec migration plan §5, the
type:

- renames from Session to Pkcs11Session (naming consistency with the
  Pkcs11-prefixed public surface)
- demotes from public to internal (only Pkcs11Workspace + Pkcs11Key
  consume it; tests reach it via InternalsVisibleTo)
- moves from HighLevel/ to Internal/, along with all 9 algorithm-
  specific partial files (Pkcs11Session.{Decrypt,Derive,Digest,Encrypt,
  Keys,Objects,Random,Sign,Verify}.cs)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: Move `ObjectHandle` to `Internal/`, demote to internal

**Files:** 1 file from `HighLevel/` → `Internal/`.

- [ ] **Step 1: Move the file**

```bash
cd /home/alexandre/dev/PKCS11.NET
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ObjectHandle.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/ObjectHandle.cs
```

- [ ] **Step 2: Update namespace + demote to internal**

In `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/ObjectHandle.cs`:

```csharp
// before:
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public readonly record struct ObjectHandle ...

// after:
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal readonly record struct ObjectHandle ...
```

```bash
sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.HighLevel;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;|; s|public readonly record struct ObjectHandle|internal readonly record struct ObjectHandle|' \
    src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/ObjectHandle.cs
```

If `ObjectHandle` has any `public` constants or `public static readonly Invalid = ...` members, those become `internal` automatically when the struct itself is `internal`. Read the file to confirm there's nothing else that needs an explicit visibility change.

- [ ] **Step 3: Update consumers**

`ObjectHandle` is used in `Pkcs11Key.PublicHandle` / `PrivateHandle` (both already `internal`), `Pkcs11Session.X` method signatures (where `Pkcs11Session` is now also `internal`), and test code (which has IVT access).

The previous demotion of `Session → Pkcs11Session` may already have caused most files that reference `ObjectHandle` to need `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;`. Verify:

```bash
grep -rln "\bObjectHandle\b" /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs" | \
  xargs grep -L "using KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.Internal" 2>/dev/null
```

Each file in that output that's NOT already in the `.Internal` namespace needs the `using` added.

- [ ] **Step 4: Build + test**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: 0 errors. `Passed: 252` or higher.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(ObjectHandle): demote to internal and move to Internal/

ObjectHandle is implementation plumbing: it's surfaced only via
Pkcs11Key.PublicHandle/PrivateHandle (both internal) and Pkcs11Session
method signatures (now internal). Per spec migration plan §5, the
struct moves to Internal/ and switches from public to internal.

External consumers never construct or inspect ObjectHandle — the new
Pkcs11Key + Pkcs11Workspace surface is sufficient.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: Move `LowLevel/SafeHandles/` to `Internal/SafeHandles/`

**Files:** 2 SafeHandle types from `LowLevel/SafeHandles/` → `Internal/SafeHandles/`.

- [ ] **Step 1: Move the directory**

```bash
cd /home/alexandre/dev/PKCS11.NET
mkdir -p src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/SafeHandles
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11/LowLevel/SafeHandles/Pkcs11ModuleHandle.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/SafeHandles/Pkcs11ModuleHandle.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11/LowLevel/SafeHandles/Pkcs11SessionHandle.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/SafeHandles/Pkcs11SessionHandle.cs

rmdir src/KerckhoffsLabs.Security.Cryptography.Pkcs11/LowLevel/SafeHandles
rmdir src/KerckhoffsLabs.Security.Cryptography.Pkcs11/LowLevel
```

If the `rmdir`s fail because of leftover files, list contents and resolve.

- [ ] **Step 2: Update namespaces**

```bash
for f in Pkcs11ModuleHandle Pkcs11SessionHandle; do
  sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.LowLevel\.SafeHandles;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;|' \
    "src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/SafeHandles/${f}.cs"
done
```

- [ ] **Step 3: Update consumers**

```bash
grep -rln "KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.LowLevel\.SafeHandles" \
    /home/alexandre/dev/PKCS11.NET/src/ --include="*.cs"
```

For each consumer: replace the using-statement with the new namespace.

```bash
find /home/alexandre/dev/PKCS11.NET/src -name "*.cs" -type f | \
  xargs sed -i 's|KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.LowLevel\.SafeHandles|KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles|g'
```

- [ ] **Step 4: Build + test**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: 0 errors. `Passed: 252` or higher.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(layout): move SafeHandles from LowLevel/ to Internal/

Pkcs11ModuleHandle and Pkcs11SessionHandle are managed-side SafeHandle
wrappers around C handles, consumed only by Native/LowLevelPkcs11Library
and the higher-level types. They're internal plumbing — per spec, that
makes them Internal/SafeHandles/ rather than the old LowLevel/SafeHandles/.

The LowLevel/ folder is removed entirely since it had no other files.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 13: Reorganize tests to mirror new prod layout

**Goal:** Mirror the spec test layout. This task does not need to be exhaustive (test reorg can be incremental) — focus on the high-impact moves:

1. Move `Tests/HighLevel/*Pkcs11Tests.cs` (the new BCL provider tests from Plan 3) → `Tests/Algorithms/`.
2. Move `Tests/HighLevel/Pkcs11MechanismMapTests.cs` → `Tests/` root.
3. Move `Tests/HighLevel/Pkcs11Workspace*Tests.cs` → `Tests/` root.
4. Move `Tests/HighLevel/Pkcs11Key*Tests.cs` → `Tests/` root.
5. Move `Tests/HighLevel/ObjectTemplateTests.cs` + `Tests/HighLevel/ObjectAttributeTests.cs` → `Tests/Objects/`.
6. Move `Tests/HighLevel/Pkcs11ExceptionTests.cs` + `Tests/HighLevel/ExceptionMapperTests.cs` → `Tests/Exceptions/`.
7. Move `Tests/HighLevel/SmokeTests.cs`, `SpanOverloadSmokeTests.cs`, `TestKeys.cs` → `Tests/` root.
8. Move `Tests/Security/SecureBufferTests.cs` → `Tests/Internal/SecureBufferTests.cs`.
9. Move `Tests/Security/SecurePinTests.cs` → `Tests/SecurePinTests.cs` (root).
10. Move `Tests/LowLevel/SafeHandles/*` → `Tests/Internal/SafeHandles/`.
11. Leave the legacy `Tests/HighLevel/{Auth, Decrypt, Derive, Digest, Encrypt, Keys, MemoryLeaks, Objects, Random, Security, Sign, ThreadSafety, Verify}/` subfolders **in place** for now — they contain pre-redesign tests. Reorganizing them is a separate effort that can run in a follow-up plan.

The spec wants per-algorithm consolidation under `Algorithms/`, but doing that in this plan would double its size. For Plan 4, we move the new (Plan 3-era) provider tests into the expected `Algorithms/` shape, and leave the legacy tests alone.

- [ ] **Step 1: Create new test folders**

```bash
cd /home/alexandre/dev/PKCS11.NET
mkdir -p src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Algorithms
mkdir -p src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Objects
mkdir -p src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Exceptions
mkdir -p src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/SafeHandles
```

- [ ] **Step 2: Move the new provider tests**

```bash
for f in RSAPkcs11Tests ECDsaPkcs11Tests AesGcmPkcs11Tests AesCcmPkcs11Tests \
         ChaCha20Poly1305Pkcs11Tests HMACPkcs11Tests; do
    git mv "src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/${f}.cs" \
           "src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Algorithms/${f}.cs"
done
```

- [ ] **Step 3: Move the new core-type tests**

```bash
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11MechanismMapTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Pkcs11MechanismMapTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Pkcs11WorkspaceTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceFindKeysTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Pkcs11WorkspaceFindKeysTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceGenerateKeyTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Pkcs11WorkspaceGenerateKeyTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceRandomTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Pkcs11WorkspaceRandomTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Pkcs11KeyTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyMechanismTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Pkcs11KeyMechanismTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyPublicSynthesisTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Pkcs11KeyPublicSynthesisTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/SmokeTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/SmokeTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/SpanOverloadSmokeTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/SpanOverloadSmokeTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/TestKeys.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/TestKeys.cs
```

- [ ] **Step 4: Move Objects + Exceptions test files**

```bash
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ObjectTemplateTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Objects/ObjectTemplateTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ObjectAttributeTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Objects/ObjectAttributeTests.cs

git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11ExceptionTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Exceptions/Pkcs11ExceptionTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ExceptionMapperTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Exceptions/ExceptionMapperTests.cs
```

- [ ] **Step 5: Move Security/ tests**

```bash
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Security/SecureBufferTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/SecureBufferTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Security/SecurePinTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/SecurePinTests.cs

rmdir src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Security
```

- [ ] **Step 6: Move LowLevel/ tests**

```bash
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/LowLevel/SafeHandles/Pkcs11ModuleHandleTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/SafeHandles/Pkcs11ModuleHandleTests.cs
git mv src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/LowLevel/SafeHandles/Pkcs11SessionHandleTests.cs \
       src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/SafeHandles/Pkcs11SessionHandleTests.cs

rmdir src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/LowLevel/SafeHandles
rmdir src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/LowLevel
```

- [ ] **Step 7: Update namespaces in moved test files**

Test files use `namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;` (or `.Tests.HighLevel.X`, etc.). Update to the new folder:

```bash
cd /home/alexandre/dev/PKCS11.NET

# Algorithms tests
for f in src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Algorithms/*.cs; do
  sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.Tests\.HighLevel;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;|' "$f"
done

# Root-level test files
for f in src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Pkcs11*.cs \
         src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/SmokeTests.cs \
         src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/SpanOverloadSmokeTests.cs \
         src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/TestKeys.cs \
         src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/SecurePinTests.cs; do
  if [ -f "$f" ]; then
    sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.Tests\.HighLevel;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;|; s|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.Tests\.Security;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;|' "$f"
  fi
done

# Objects tests
for f in src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Objects/*.cs; do
  sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.Tests\.HighLevel;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Objects;|' "$f"
done

# Exceptions tests
for f in src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Exceptions/*.cs; do
  sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.Tests\.HighLevel;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Exceptions;|' "$f"
done

# Internal tests (SecureBuffer + SafeHandles)
sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.Tests\.Security;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Internal;|' \
    src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/SecureBufferTests.cs

for f in src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/SafeHandles/*.cs; do
  sed -i 's|namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.Tests\.LowLevel\.SafeHandles;|namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Internal.SafeHandles;|' "$f"
done
```

- [ ] **Step 8: Update test-side `using` statements**

The relocated test files reach internal types via `using` directives. Update any test file that previously used `using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;` (now invalid for many types). Strategy: keep the `.HighLevel` `using` (legacy tests still reference it via the old namespace) AND add the new namespaces where needed.

The cleanest approach: leave the `.HighLevel` `using` in moved tests if it was there — even if it now resolves to nothing, the code still compiles. The build will tell us if anything is missing.

- [ ] **Step 9: Build + test**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: 0 errors. `Passed: 252` or higher.

For each missing-namespace build error: add the right `using` to the affected file. Most likely needed:
- `using KerckhoffsLabs.Security.Cryptography.Pkcs11;` (root)
- `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;`
- `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;`
- `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;` (for `Pkcs11Session`, `ObjectHandle`, `SecureBuffer`)
- `using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;`

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(tests): mirror new prod layout — Algorithms/, Objects/, Exceptions/, Internal/

Reorganizes the test assembly to match the spec's final layout:
- Provider tests (Plan 3 era) move from Tests/HighLevel/ to Tests/Algorithms/
- Pkcs11Workspace/Pkcs11Key/Pkcs11MechanismMap tests move to Tests/ root
- ObjectTemplate/ObjectAttribute tests move to Tests/Objects/
- Pkcs11Exception/ExceptionMapper tests move to Tests/Exceptions/
- SecureBuffer tests move to Tests/Internal/
- SecurePin tests move to Tests/ root
- SafeHandle tests move from Tests/LowLevel/SafeHandles/ to Tests/Internal/SafeHandles/

The legacy per-mechanism test folders under Tests/HighLevel/{Encrypt,
Sign, etc.} are intentionally left in place — reorganizing them into
the spec's per-algorithm Algorithms/<X>/ shape is a follow-up effort
beyond Plan 4's scope.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 14: Final sanity sweep — verify, prune, commit

This task confirms the migration is complete and that no stale `.HighLevel` / `.LowLevel` / `.Security` references remain in production code. The corresponding namespaces are still allowed in legacy test files under `Tests/HighLevel/` (those carry over from prior plans).

- [ ] **Step 1: Confirm `HighLevel/` is empty in production**

```bash
ls /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ 2>&1
```

Expected: directory empty OR doesn't exist. If files remain, identify them — they were missed by Tasks 7-10.

If empty, remove the directory:

```bash
rmdir src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel 2>&1 || echo "still has files"
```

- [ ] **Step 2: Confirm `LowLevel/` is gone from production**

```bash
ls /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/LowLevel/ 2>&1
```

Expected: `No such file or directory`.

- [ ] **Step 3: Confirm `Security/` is gone from production**

```bash
ls /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/ 2>&1
```

Expected: `No such file or directory`.

- [ ] **Step 4: Confirm no production source file still declares `.HighLevel` / `.LowLevel` / `.Security` namespaces**

```bash
grep -rn "^namespace KerckhoffsLabs\.Security\.Cryptography\.Pkcs11\.\(HighLevel\|LowLevel\|Security\)" \
    /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11 --include="*.cs"
```

Expected: empty.

- [ ] **Step 5: Confirm `Common/` keeps only CK enums**

```bash
ls /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/
```

Expected: 16 CK*.cs files only (CK.cs, CKA.cs, CKC.cs, CKD.cs, CKF.cs, CKG.cs, CKH.cs, CKK.cs, CKM.cs, CKN.cs, CKO.cs, CKP.cs, CKR.cs, CKS.cs, CKU.cs, CKZ.cs).

- [ ] **Step 6: Confirm provider files exist at root**

```bash
ls /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/{RSAPkcs11,ECDsaPkcs11,AesGcmPkcs11,AesCcmPkcs11,ChaCha20Poly1305Pkcs11,HMACPkcs11,Pkcs11Library,Pkcs11Workspace,Pkcs11Key,Pkcs11Slot,SecurePin,Mechanism}.cs
```

Expected: 12 file paths listed, no errors.

- [ ] **Step 7: Confirm `Pkcs11Session` is `internal` and lives in `Internal/`**

```bash
grep -n "^internal\|^public" /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs | head -5
```

Expected: first declaration is `internal sealed partial class Pkcs11Session`.

```bash
ls /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session*.cs | wc -l
```

Expected: 10.

- [ ] **Step 8: Confirm `ObjectHandle` is `internal`**

```bash
grep -n "internal readonly record struct ObjectHandle\|public readonly record struct ObjectHandle" \
    /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/ObjectHandle.cs
```

Expected: one match showing `internal readonly record struct ObjectHandle`. No `public` match.

- [ ] **Step 9: Confirm `Native/RawMechanismParams/` exists, `Native/MechanismParams/` does not**

```bash
ls -d /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/RawMechanismParams
ls -d /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/MechanismParams 2>&1
```

Expected: first succeeds, second prints `No such file or directory`.

- [ ] **Step 10: Final Debug test run**

```bash
dotnet test /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Debug --nologo
```

Expected: `Passed: 252` or higher, `Failed: 0`.

- [ ] **Step 11: Final Release build**

```bash
dotnet build /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.sln -c Release
```

Expected: `0 Error(s)`. Warnings are tolerated (mostly pre-existing CA2264).

- [ ] **Step 12: Report completion**

This task does not produce a commit on its own — it's verification only. If Steps 1–11 all pass, Plan 4 is done.

If Step 1 found stray files in `HighLevel/` (i.e., something the earlier tasks missed), make a small cleanup commit that moves the stray files to their proper destination, then re-run Steps 4 and 10.

---

## Self-review

**Spec coverage** (cross-referenced against migration plan §5–§6 in `2026-05-13-pkcs11-bcl-aligned-redesign-design.md`):

- ✅ Rename `Session` → `Pkcs11Session`, make internal — **Task 10**.
- ✅ Make `ObjectHandle` internal — **Task 11**.
- ⚠️ Delete `Session.*.cs` algorithm-specific helpers — **interpretation**: in this plan, the partials are *kept* but renamed to `Pkcs11Session.*.cs` and moved to `Internal/`, since their methods are still consumed by `Pkcs11Workspace` / `Pkcs11Key`. Deleting them would break Plan 3's providers. If the spec truly meant to inline-fold them into a single file, that's a separate housekeeping pass that doesn't change semantics.
- ✅ Delete `Security/` folder — **Tasks 1 + 2** (move `SecurePin` to root + `SecureBuffer` to `Internal/`, then `rmdir`).
- ✅ Move `SecurePin` to root — **Task 1**.
- ✅ Move `SecureBuffer` to `Internal/` — **Task 2**.
- ✅ Rename `Native/MechanismParams/` → `Native/RawMechanismParams/` — **Task 5**.
- ✅ Remove dead `Session` partial fragments — **Task 10** moves them all; nothing dead remains.
- ✅ Delete `HighLevel/` folder shell — **Task 14** confirms it's empty and removes it.

**Folder layout coverage** (spec §"Folder layout — production code"):
- ✅ Root: `Pkcs11Library.cs`, `Pkcs11Slot.cs`, `Pkcs11Workspace.cs`, `Pkcs11Key.cs`, `Mechanism.cs`, `SecurePin.cs` — Tasks 1, 8, 9.
- ✅ Root providers: `RSAPkcs11.cs`, `ECDsaPkcs11.cs`, `AesGcmPkcs11.cs`, `AesCcmPkcs11.cs`, `ChaCha20Poly1305Pkcs11.cs`, `HMACPkcs11.cs` — Task 7.
- ✅ `Objects/` folder — Task 6.
- ✅ `Exceptions/` folder — Task 3.
- ✅ `MechanismParams/` folder — Task 4.
- ✅ `Common/` keeps only enums — Task 3 removes the exceptions.
- ✅ `Logging/` unchanged — already in place.
- ✅ `Internal/` folder — Tasks 2, 3, 10, 11, 12 populate it.
- ✅ `Native/` and `Native/RawMechanismParams/` — Task 5.

**Test layout coverage**: Task 13 moves new tests; legacy tests deliberately stay in `Tests/HighLevel/{X}/` per plan scope statement.

**Out of scope (deferred)**:
- ⏳ `IPkcs11Library` mock seam (spec §8) — not in migration §5–§6.
- ⏳ `FakePkcs11Library` + `Fakes/` folder — depends on IPkcs11Library.
- ⏳ Native/Bindings/ subfolder (spec hints at it but doesn't require) — pure cosmetic move can land later.

**Placeholder scan**: no TBD / TODO / "similar to" / "handle edge cases" — every step has concrete commands.

**Type consistency**: All renames are well-defined (`Session → Pkcs11Session`, `Slot → Pkcs11Slot`). All namespace transformations are explicit. All file paths are absolute or clearly relative to the repo root.

**Risk profile**:
- Task 10 (Session rename + demote) is the highest-risk task. Mitigation: extensive build/test gates between every sub-step.
- Task 9 (Slot → Pkcs11Slot rename) has substring-collision risk with `SlotFlags`/`SlotInfo`/`SlotsType`. Mitigation: explicit `grep` after the sed pass to verify only the intended occurrences changed.
- Tasks 1-8, 11-12 are pure mechanical moves — low risk.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-13-pkcs11-demolition-reorg.md`. Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task with two-stage review. Used for Plans 1–3.
2. **Inline Execution** — I execute tasks in this session with batch checkpoints.

Which approach?
