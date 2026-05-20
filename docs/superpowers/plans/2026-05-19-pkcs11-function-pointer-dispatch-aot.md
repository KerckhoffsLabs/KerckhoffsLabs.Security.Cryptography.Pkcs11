# PKCS#11 Function-Pointer Dispatch (BL-025 AOT-Hardening) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `KerckhoffsLabs.Security.Cryptography.Pkcs11` Native AOT compatible by replacing the 135 `[UnmanagedFunctionPointer]` delegate-based dispatch table with `delegate* unmanaged[Cdecl]<...>` function pointers, plus eliminating remaining `[RequiresDynamicCode]` reflection paths.

**Architecture:** Strangler-pattern migration: introduce a new internal `FunctionPointers` class holding `delegate* unmanaged[Cdecl]<...>` fields alongside the existing `Delegates` class. Migrate function groups one task at a time — each task converts a coherent subset, removes the old delegate fields/types for that subset, and keeps tests green. Wrapper methods on `Delegates` preserve the existing call signatures so `LowLevelPkcs11Library.cs` callers do not change. After all functions migrate, delete the old delegate type declarations, replace `Marshal.PtrToStructure(IntPtr, Type)` calls with the generic `<T>` form, address the reflection-based packed-struct dispatch in `Pkcs11Marshal` / `UnmanagedMemory`, and enable `<IsAotCompatible>true</IsAotCompatible>` to fail the build on any residual warning.

**Tech Stack:** C# 14 (`net10.0`), `delegate* unmanaged[Cdecl]<...>` function pointers, `fixed` blocks for array/struct pinning, `Marshal.PtrToStructure<T>` generic, `<IsAotCompatible>` MSBuild property, `[RequiresDynamicCode]` annotations as a transition tool.

**Reference docs to keep open while implementing:**
- The current `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs` (135 delegate types, ~1330 lines)
- The current `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs` (~2074 lines — every call site)
- The PKCS#11 v3.2 function-list header (`vendor/softhsmv2/src/lib/pkcs11/pkcs11.h`) for the canonical C signatures
- BL-001's source generator (`src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators/PackedStructsGenerator.cs`) — both unified and Windows-sibling function pointers must keep working

**Invariants every task must preserve:**
- `LowLevelPkcs11Library` public method signatures (the wrapper methods that `Pkcs11Library` / `Pkcs11Session` / `Pkcs11Slot` call) must remain unchanged. Internal call sites use `_delegates.C_X(...)` — that exact call shape must continue to work, so wrapper methods on the new `Delegates`/`FunctionPointers` plumbing match the old delegate signatures one-for-one.
- The unified-vs-Windows dispatch (BL-001) keeps working: every `_Windows` delegate variant gets a matching function-pointer field.
- Tests stay green at every commit (565 tests must pass). The integration suite is the canonical correctness check — TDD here is harder because most behavioral coverage already exists; the bar is "no regression".
- Cryptographic correctness is non-negotiable. A subtle marshalling bug here will produce wrong-but-decodable ciphertext/signatures. Every task ends with the full `dotnet test` run, not a filter.

---

## File Structure

| Path | Responsibility | Action |
|------|----------------|--------|
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs` | New file. Holds `delegate* unmanaged[Cdecl]<...>` typed fields, one per cryptoki function (135 unified + Windows variants). Populated by direct IntPtr cast from `CK_FUNCTION_LIST*`. | Create in Task 2 |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs` | Existing file. Currently holds delegate types + delegate fields + populator methods. Will gradually have its fields/types replaced by wrapper methods that invoke `FunctionPointers`. | Modify in every task |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs` | Existing. Calls `_delegates.C_X(...)`. Should remain functionally untouched (only minor type tweaks if Delegates' wrapper signatures shift). | Read-only mostly |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/UnmanagedMemory.cs` | Existing. `SizeOf(Type)` / `Write(IntPtr, object)` / `Read(IntPtr, Type)` use reflection and `Marshal.SizeOf(Type)` / `Marshal.PtrToStructure(IntPtr, Type)` — `[RequiresDynamicCode]`. | Modify in Task 11 |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Pkcs11Marshal.cs` | Existing. Reflects on `T_Windows` sibling types via `t.Assembly.GetType(t.FullName + "_Windows")` — AOT-hostile. | Modify in Task 11 |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` | Add `<IsAotCompatible>true</IsAotCompatible>` plus `<EnableTrimAnalyzer>true</EnableTrimAnalyzer>` to fail the build on any residual AOT warning. | Modify in Task 12 |
| `BACKLOG.md` | Mark BL-025 resolved with a summary of what landed. | Modify in Task 13 |

---

## Task 1: Baseline — measure current AOT/trim warning surface

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` (temporary — reverted at end of task)

**Goal of this task:** Get a written baseline of every `[RequiresDynamicCode]` / `[RequiresUnreferencedCode]` / IL2xxx / IL3xxx warning before changing anything, so later tasks can verify they are eliminating warnings rather than masking them.

- [ ] **Step 1: Temporarily enable AOT analyzers**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` and add inside the first `<PropertyGroup>`:

```xml
    <IsAotCompatible>true</IsAotCompatible>
    <EnableAotAnalyzer>true</EnableAotAnalyzer>
    <EnableTrimAnalyzer>true</EnableTrimAnalyzer>
```

- [ ] **Step 2: Build and capture warnings**

Run:
```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo 2>&1 | grep -E "IL[0-9]{4}|RequiresDynamicCode|RequiresUnreferencedCode" | sort -u > /tmp/bl025-baseline.txt
wc -l /tmp/bl025-baseline.txt
```

Expected: dozens of lines, mostly IL2026 / IL3050 from `Marshal.GetDelegateForFunctionPointer` and `Marshal.PtrToStructure(IntPtr, Type)`.

- [ ] **Step 3: Save baseline to docs**

Run:
```
mkdir -p docs/superpowers/notes
cp /tmp/bl025-baseline.txt docs/superpowers/notes/2026-05-19-bl025-aot-baseline.txt
```

- [ ] **Step 4: Revert the csproj change**

Remove the three lines added in Step 1. We re-enable them permanently in Task 12 after the migration is complete.

- [ ] **Step 5: Verify revert**

Run:
```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo -v q 2>&1 | tail -3
```

Expected: `0 Error(s)` and roughly the same warning count we had at the start of this session (no analyzer warnings now that they are disabled).

- [ ] **Step 6: Commit baseline**

```bash
git add docs/superpowers/notes/2026-05-19-bl025-aot-baseline.txt
git commit -m "docs(bl-025): capture AOT analyzer baseline before delegate→fptr migration"
```

---

## Task 2: Introduce FunctionPointers class + migrate one simple delegate as proof

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs` (replace `C_Finalize` only)

**Goal of this task:** Establish the migration pattern using `C_Finalize` (a no-marshalling, single-IntPtr-param function) as the simplest possible test case. Every subsequent migration follows the same skeleton.

- [ ] **Step 1: Create FunctionPointers.cs**

Write the new file:

```csharp
using KerckhoffsLabs.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Holds the raw <c>delegate* unmanaged[Cdecl]&lt;...&gt;</c> function pointers for every
/// PKCS#11 cryptoki function the library binds. Populated by direct cast from
/// <see cref="CK_FUNCTION_LIST"/> / <see cref="CK_FUNCTION_LIST_3_0"/> / <see cref="CK_FUNCTION_LIST_3_2"/>
/// entries; no <c>Marshal.GetDelegateForFunctionPointer&lt;T&gt;</c> on this path so the
/// dispatch table is fully Native AOT compatible.
/// </summary>
/// <remarks>
/// Wrapper methods on <see cref="Delegates"/> do the per-call marshalling (pinning
/// <c>byte[]</c> / <c>CK_*[]</c> / <c>NativeCULong[]</c>, taking <c>fixed</c> addresses of
/// ref-struct parameters, converting <c>bool</c>↔<c>byte</c>) so the public dispatch
/// surface stays identical to the prior delegate-based version.
/// </remarks>
internal sealed unsafe class FunctionPointers
{
    /// <summary>Cryptoki <c>CK_RV C_Finalize(CK_VOID_PTR pReserved)</c>.</summary>
    public delegate* unmanaged[Cdecl]<IntPtr, NativeCULong> C_Finalize;

    // Additional fields are added one group at a time in Tasks 3-10.
}
```

- [ ] **Step 2: Wire FunctionPointers into Delegates**

In `Native/Delegates.cs`, at the top of the `Delegates` class declaration (just before the `NativeMethods` nested class), add:

```csharp
    /// <summary>
    /// Typed function pointer table. Populated by Initialize / TryLoadV30Symbols /
    /// TryLoadFromGetInterface alongside the legacy delegate fields. Migration target
    /// for BL-025 — every delegate field is being replaced by an entry here plus a
    /// wrapper method on this class.
    /// </summary>
    private readonly FunctionPointers _fp = new();
```

- [ ] **Step 3: Remove the old C_Finalize delegate field + add wrapper method**

In `Native/Delegates.cs`:

(a) Delete the `[UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate NativeCULong C_FinalizeDelegate(IntPtr reserved);` declaration (top of file).

(b) Delete the `internal C_FinalizeDelegate? C_Finalize = null;` field.

(c) Add a wrapper method that LowLevelPkcs11Library's existing call `_delegates.C_Finalize(reserved)` will bind to:

```csharp
    /// <summary>Wrapper for <c>C_Finalize</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Finalize(IntPtr reserved)
    {
        if (_fp.C_Finalize is null)
            throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Finalize");
        return _fp.C_Finalize(reserved);
    }
```

- [ ] **Step 4: Update the v2.40 function-list populator**

Find the line in `Delegates.cs` populator where the function-list pointers are bound:
```csharp
C_Finalize = Marshal.GetDelegateForFunctionPointer<C_FinalizeDelegate>(funcList.C_Finalize);
```
Replace it with:
```csharp
unsafe { _fp.C_Finalize = (delegate* unmanaged[Cdecl]<IntPtr, NativeCULong>)funcList.C_Finalize; }
```

- [ ] **Step 5: Build**

Run:
```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo -v q 2>&1 | tail -5
```

Expected: `0 Error(s)`.

- [ ] **Step 6: Run full test suite**

Run:
```
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --nologo -v q 2>&1 | tail -3
```

Expected: `Passed!  - Failed:     0, Passed:   565`.

- [ ] **Step 7: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
git commit -m "refactor(aot): introduce FunctionPointers class + migrate C_Finalize (BL-025 phase 1)"
```

---

## Task 3: Migrate the no-marshalling functions

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs`

**Scope:** Functions whose parameters are all scalar types (`NativeCULong`, `IntPtr`) — no arrays, no ref-structs, no bools. These take zero marshalling work in the wrapper.

The functions in this group:
- `C_CloseSession(session)`
- `C_CloseAllSessions(slotId)`
- `C_Logout(session)`
- `C_DestroyObject(session, objectId)`
- `C_GetObjectSize(session, objectId, ref NativeCULong size)` — has ref scalar, handle via address-of
- `C_FindObjectsFinal(session)`
- `C_EncryptFinal(session, encryptedPart, ref encryptedPartLen)` — out byte[] + ref scalar (deferred to Task 5)
- `C_SessionCancel(session, flags)` (v3.0)
- `C_CancelFunction(session)`

(Note: the byte[] ones move to Task 5; this task only handles fully scalar.)

The fully-scalar subset:
- `C_CloseSession(NativeCULong session)`
- `C_CloseAllSessions(NativeCULong slotId)`
- `C_Logout(NativeCULong session)`
- `C_DestroyObject(NativeCULong session, NativeCULong objectId)`
- `C_FindObjectsFinal(NativeCULong session)`
- `C_SessionCancel(NativeCULong session, NativeCULong flags)`
- `C_CancelFunction(NativeCULong session)`

- [ ] **Step 1: Add 7 function-pointer fields to FunctionPointers**

In `Native/FunctionPointers.cs`, add inside the class body:

```csharp
    /// <summary>Cryptoki <c>C_CloseSession</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_CloseSession;

    /// <summary>Cryptoki <c>C_CloseAllSessions</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_CloseAllSessions;

    /// <summary>Cryptoki <c>C_Logout</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_Logout;

    /// <summary>Cryptoki <c>C_DestroyObject</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong> C_DestroyObject;

    /// <summary>Cryptoki <c>C_FindObjectsFinal</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_FindObjectsFinal;

    /// <summary>Cryptoki <c>C_SessionCancel</c> (v3.0+).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong> C_SessionCancel;

    /// <summary>Cryptoki <c>C_CancelFunction</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_CancelFunction;
```

- [ ] **Step 2: Delete old delegate types and fields, add wrapper methods**

For each of the 7 functions above, in `Native/Delegates.cs`:

(a) Delete the `internal delegate NativeCULong C_XXXDelegate(...)` declaration at the top of the file.
(b) Delete the `internal C_XXXDelegate? C_XXX = null;` field.
(c) Add the wrapper method. Example for `C_CloseSession`:

```csharp
    public unsafe NativeCULong C_CloseSession(NativeCULong session)
    {
        if (_fp.C_CloseSession is null) throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_CloseSession");
        return _fp.C_CloseSession(session);
    }
```

Repeat with matching shape for `C_CloseAllSessions(slotId)`, `C_Logout(session)`, `C_DestroyObject(session, objectId)`, `C_FindObjectsFinal(session)`, `C_SessionCancel(session, flags)`, `C_CancelFunction(session)`. Each is a one-line forward — no `fixed`, no conversions.

- [ ] **Step 3: Update populators**

For each migrated function in this task, locate the `Marshal.GetDelegateForFunctionPointer<C_XXXDelegate>(funcList.C_XXX)` line and replace with:
```csharp
unsafe { _fp.C_XXX = (delegate* unmanaged[Cdecl]<...>)funcList.C_XXX; }
```
Match the field-type signature exactly.

For `C_SessionCancel`, the v3.0 path is in `TryLoadV30Symbols`/`TryLoadFromGetInterface`; same replacement pattern.

- [ ] **Step 4: Build and test**

```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo -v q 2>&1 | tail -3
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --nologo -v q 2>&1 | tail -3
```

Expected: build `0 Error(s)`; tests `Passed: 565`.

- [ ] **Step 5: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
git commit -m "refactor(aot): migrate no-marshalling cryptoki fns to fptr dispatch (BL-025 phase 2)"
```

---

## Task 4: Migrate `ref CK_*` struct functions (unified path)

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs`

**Scope:** Functions whose only marshalling concern is a single `ref CK_X` struct parameter. The Windows-variant pairs are handled separately in Task 8.

Functions in this group (unified path only; `_Windows` variants stay as delegates for now):
- `C_GetInfo(ref CK_INFO info)`
- `C_GetSlotInfo(slotId, ref CK_SLOT_INFO info)`
- `C_GetTokenInfo(slotId, ref CK_TOKEN_INFO info)`
- `C_GetSessionInfo(session, ref CK_SESSION_INFO info)`
- `C_GetMechanismInfo(slotId, type, ref CK_MECHANISM_INFO info)`

**Pattern for each:**

- [ ] **Step 1: Add 5 function-pointer fields**

In `Native/FunctionPointers.cs`, add:

```csharp
    public delegate* unmanaged[Cdecl]<CK_INFO*, NativeCULong> C_GetInfo;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_SLOT_INFO*, NativeCULong> C_GetSlotInfo;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_TOKEN_INFO*, NativeCULong> C_GetTokenInfo;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_SESSION_INFO*, NativeCULong> C_GetSessionInfo;
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_MECHANISM_INFO*, NativeCULong> C_GetMechanismInfo;
```

- [ ] **Step 2: Delete old delegate types and fields, add wrappers**

For each function, delete the `internal delegate ...` declaration and the `internal C_XXXDelegate? C_XXX = null;` field. Add the wrapper. Example for `C_GetInfo`:

```csharp
    public unsafe NativeCULong C_GetInfo(ref CK_INFO info)
    {
        if (_fp.C_GetInfo is null) throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetInfo");
        fixed (CK_INFO* p = &info) return _fp.C_GetInfo(p);
    }
```

Same shape for the other four — pin the ref struct address via `fixed (CK_X* p = &x)` and forward.

- [ ] **Step 3: Update populator**

Replace `Marshal.GetDelegateForFunctionPointer<C_GetInfoDelegate>(funcList.C_GetInfo)` (and the four siblings) with the direct-cast assignment to `_fp.C_GetInfo` etc.

- [ ] **Step 4: Build and test**

```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo -v q 2>&1 | tail -3
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --nologo -v q 2>&1 | tail -3
```

Expected: build `0 Error(s)`; tests `Passed: 565`.

- [ ] **Step 5: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
git commit -m "refactor(aot): migrate ref-struct cryptoki fns to fptr dispatch (BL-025 phase 3)"
```

---

## Task 5: Migrate `byte[]` and `out IntPtr` functions

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs`

**Scope:** Functions that pass byte arrays (PIN, plaintext, ciphertext, signature, etc.) or `out IntPtr`. Marshalling here requires `fixed (byte* p = arr)` and forwarding `&p`.

Functions in this group:
- `C_Initialize(IntPtr pInitArgs)` (no byte[] but trivial — bundle here)
- `C_GetFunctionList(out IntPtr functionList)`
- `C_InitToken(slotId, byte[] pin, pinLen, byte[] label)`
- `C_InitPIN(session, byte[] pin, pinLen)`
- `C_SetPIN(session, byte[] oldPin, oldPinLen, byte[] newPin, newPinLen)`
- `C_Login(session, userType, byte[] pin, pinLen)`
- `C_LoginUser(session, userType, byte[] pin, pinLen, byte[] username, usernameLen)` (v3.0)
- `C_GetOperationState(session, [In, Out] byte[] state, ref stateLen)`
- `C_SetOperationState(session, byte[] state, stateLen, encryptionKey, authenticationKey)`
- `C_GenerateRandom(session, [In, Out] byte[] randomData, randomLen)`
- `C_SeedRandom(session, byte[] seed, seedLen)`
- `C_GetInterface(byte[]? interfaceName, IntPtr version, out IntPtr interfacePtr, flags)` (v3.0)
- `C_GetInterfaceList([In, Out] CK_INTERFACE[]? interfaceList, ref count)` — deferred to Task 6 (it's a struct array)
- The crypto streaming functions (`C_EncryptUpdate`, `C_Encrypt`, `C_Decrypt*`, `C_Sign*`, `C_Verify*`, `C_Digest*`) which all take input/output byte[] pairs

**Decision:** For arrays that may be `null` (size-probe pattern: two-call buffer protocol), pass `null` through as a literal `(byte*)null` rather than entering a `fixed` block — `fixed` on a null array is allowed and produces `null` per the C# spec, so the cleaner option is to always `fixed` and let the runtime hand back `null`. Sample for `C_Login`:

```csharp
public unsafe NativeCULong C_Login(NativeCULong session, NativeCULong userType, byte[] pin, NativeCULong pinLen)
{
    if (_fp.C_Login is null) throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Login");
    fixed (byte* pinPtr = pin)
        return _fp.C_Login(session, userType, pinPtr, pinLen);
}
```

For functions that return a length-only probe (e.g. `C_GenerateRandom` called with `null` array to get required length):
```csharp
public unsafe NativeCULong C_GenerateRandom(NativeCULong session, byte[]? randomData, NativeCULong randomLen)
{
    if (_fp.C_GenerateRandom is null) throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GenerateRandom");
    fixed (byte* p = randomData) return _fp.C_GenerateRandom(session, p, randomLen);
}
```

- [ ] **Step 1: Add the function-pointer fields**

In `Native/FunctionPointers.cs` add one field per function in this group, using the right C signature. Sample:

```csharp
    public delegate* unmanaged[Cdecl]<IntPtr, NativeCULong> C_Initialize;
    public delegate* unmanaged[Cdecl]<IntPtr*, NativeCULong> C_GetFunctionList;
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong> C_InitToken;
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_InitPIN;
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_SetPIN;
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, byte*, NativeCULong, NativeCULong> C_Login;
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_LoginUser;
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong> C_GetOperationState;
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong, NativeCULong, NativeCULong> C_SetOperationState;
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_GenerateRandom;
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_SeedRandom;
    public delegate* unmanaged[Cdecl]<byte*, IntPtr, IntPtr*, NativeCULong, NativeCULong> C_GetInterface;
```

For the streaming crypto functions, each follows the same pattern (input byte*, input len, output byte*, ref output len). Sample for `C_Encrypt`:

```csharp
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_Encrypt;
```

- [ ] **Step 2: Delete old delegates and fields; add wrappers**

Per-function wrapper template (replace XXX accordingly):

```csharp
public unsafe NativeCULong C_Encrypt(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? encrypted, ref NativeCULong encryptedLen)
{
    if (_fp.C_Encrypt is null) throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Encrypt");
    fixed (byte* dataPtr = data)
    fixed (byte* encPtr = encrypted)
    fixed (NativeCULong* lenPtr = &encryptedLen)
        return _fp.C_Encrypt(session, dataPtr, dataLen, encPtr, lenPtr);
}
```

Cross-check parameter nullability against the existing delegate declaration in the pre-migration source — a parameter that was previously `byte[]` (non-null) keeps the non-null contract; ones that the spec allows to be `null` (size-probe path) become `byte[]?`.

For `C_Initialize`, signature is straightforward `(IntPtr) -> NativeCULong`:
```csharp
public unsafe NativeCULong C_Initialize(IntPtr pInitArgs)
{
    if (_fp.C_Initialize is null) throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Initialize");
    return _fp.C_Initialize(pInitArgs);
}
```

For `C_GetFunctionList(out IntPtr functionList)`:
```csharp
public unsafe NativeCULong C_GetFunctionList(out IntPtr functionList)
{
    if (_fp.C_GetFunctionList is null) throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetFunctionList");
    IntPtr local = IntPtr.Zero;
    NativeCULong rv = _fp.C_GetFunctionList(&local);
    functionList = local;
    return rv;
}
```

- [ ] **Step 3: Update populator calls**

For each function in this group, replace `Marshal.GetDelegateForFunctionPointer<...>(...)` with the typed direct cast. For v3.0 functions, update the `TryLoadV30Symbols` / `TryLoadFromGetInterface` blocks accordingly.

- [ ] **Step 4: Build and test**

```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo -v q 2>&1 | tail -3
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --nologo -v q 2>&1 | tail -3
```

Expected: build `0 Error(s)`; tests `Passed: 565`.

This is the most-touched task because the streaming crypto path is the busiest. If anything regresses, it shows up here — the integration suite covers RSA/EC/AES/ML-DSA/ML-KEM round-trips end-to-end.

- [ ] **Step 5: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
git commit -m "refactor(aot): migrate byte[]-param cryptoki fns to fptr dispatch (BL-025 phase 4)"
```

---

## Task 6: Migrate array-of-CK_* and array-of-NativeCULong functions

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs`

**Scope:** Functions whose parameters include `[In, Out] CK_ATTRIBUTE[] template` / `[In, Out] NativeCULong[] slotList` / `[In, Out] CK_INTERFACE[] interfaceList` etc. Same pinning pattern as Task 5 byte[] but typed to the struct.

Functions in this group (unified path only — Windows variants in Task 8):
- `C_GetSlotList(bool tokenPresent, [In, Out] NativeCULong[] slotList, ref count)`
- `C_GetMechanismList(slotId, [In, Out] NativeCULong[] mechanismList, ref count)`
- `C_GetInterfaceList([In, Out] CK_INTERFACE[]? interfaceList, ref count)` (v3.0)
- `C_FindObjects(session, [Out] NativeCULong[] objectIds, maxCount, ref count)`
- `C_GenerateKeyPair(session, ref CK_MECHANISM, CK_ATTRIBUTE[] pubTemplate, NativeCULong pubCount, CK_ATTRIBUTE[] privTemplate, NativeCULong privCount, ref pubKey, ref privKey)`

**Special: `bool` marshalling.** `C_GetSlotList` takes `bool tokenPresent` with `[MarshalAs(UnmanagedType.U1)]`. Function pointers don't auto-marshal — convert at the wrapper:
```csharp
return _fp.C_GetSlotList((byte)(tokenPresent ? 1 : 0), slotPtr, countPtr);
```

The function pointer field type is `byte` (one-byte BOOL on every platform per CK_BBOOL).

- [ ] **Step 1: Add the function-pointer fields**

```csharp
    public delegate* unmanaged[Cdecl]<byte, NativeCULong*, NativeCULong*, NativeCULong> C_GetSlotList;
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, NativeCULong*, NativeCULong> C_GetMechanismList;
    public delegate* unmanaged[Cdecl]<CK_INTERFACE*, NativeCULong*, NativeCULong> C_GetInterfaceList;
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, NativeCULong, NativeCULong*, NativeCULong> C_FindObjects;
```

(GenerateKeyPair moves to Task 7 because its mechanism param is a `ref CK_MECHANISM`.)

- [ ] **Step 2: Wrappers**

Sample for `C_GetSlotList`:
```csharp
public unsafe NativeCULong C_GetSlotList(bool tokenPresent, NativeCULong[]? slotList, ref NativeCULong count)
{
    if (_fp.C_GetSlotList is null) throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetSlotList");
    fixed (NativeCULong* slotPtr = slotList)
    fixed (NativeCULong* countPtr = &count)
        return _fp.C_GetSlotList((byte)(tokenPresent ? 1 : 0), slotPtr, countPtr);
}
```

Sample for `C_GetMechanismList`:
```csharp
public unsafe NativeCULong C_GetMechanismList(NativeCULong slotId, NativeCULong[]? mechanismList, ref NativeCULong count)
{
    if (_fp.C_GetMechanismList is null) throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetMechanismList");
    fixed (NativeCULong* arrPtr = mechanismList)
    fixed (NativeCULong* countPtr = &count)
        return _fp.C_GetMechanismList(slotId, arrPtr, countPtr);
}
```

Note: `LowLevelPkcs11Library.C_GetMechanismList` does a custom conversion through a temporary `NativeCULong[]`; that wrapper still works because the inner call still goes through `_delegates.C_GetMechanismList` which is now this method. No change at the call site.

- [ ] **Step 3: Update populator**

Same direct-cast pattern.

- [ ] **Step 4: Build and test**

```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo -v q 2>&1 | tail -3
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --nologo -v q 2>&1 | tail -3
```

Expected: `0 Error(s)`; `Passed: 565`.

- [ ] **Step 5: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
git commit -m "refactor(aot): migrate array-param cryptoki fns to fptr dispatch (BL-025 phase 5)"
```

---

## Task 7: Migrate mechanism-bound functions (`ref CK_MECHANISM` + `CK_ATTRIBUTE[]`)

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs`

**Scope:** The mechanism-and-key/template family. These are the busiest functions; care is required because they pass both a `ref CK_MECHANISM` (struct pointer) and a `CK_ATTRIBUTE[]` (struct array). All this task's functions are the **unified** variants. The `_Windows` siblings go in Task 8.

Functions in this group (unified path only):
- `C_CreateObject(session, CK_ATTRIBUTE[] template, count, ref objectId)`
- `C_CopyObject(session, objectId, CK_ATTRIBUTE[] template, count, ref newObjectId)`
- `C_GetAttributeValue(session, objectId, [In, Out] CK_ATTRIBUTE[] template, count)`
- `C_SetAttributeValue(session, objectId, CK_ATTRIBUTE[] template, count)`
- `C_FindObjectsInit(session, CK_ATTRIBUTE[] template, count)`
- `C_EncryptInit(session, ref CK_MECHANISM mech, key)`
- `C_DecryptInit(session, ref CK_MECHANISM mech, key)`
- `C_DigestInit(session, ref CK_MECHANISM mech)`
- `C_SignInit(session, ref CK_MECHANISM mech, key)`
- `C_SignRecoverInit(session, ref CK_MECHANISM mech, key)`
- `C_VerifyInit(session, ref CK_MECHANISM mech, key)`
- `C_VerifyRecoverInit(session, ref CK_MECHANISM mech, key)`
- `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate` (byte[]/ref structs — covered in Task 5 / pure byte[])
- `C_GenerateKey(session, ref CK_MECHANISM mech, CK_ATTRIBUTE[] template, count, ref keyHandle)`
- `C_GenerateKeyPair(session, ref CK_MECHANISM mech, CK_ATTRIBUTE[] pubTemplate, pubCount, CK_ATTRIBUTE[] privTemplate, privCount, ref pubKey, ref privKey)`
- `C_WrapKey(session, ref CK_MECHANISM mech, wrappingKey, key, [Out] byte[] wrapped, ref wrappedLen)`
- `C_UnwrapKey(session, ref CK_MECHANISM mech, unwrappingKey, byte[] wrapped, wrappedLen, CK_ATTRIBUTE[] template, count, ref unwrappedKey)`
- `C_DeriveKey(session, ref CK_MECHANISM mech, baseKey, CK_ATTRIBUTE[] template, count, ref derivedKey)`

- [ ] **Step 1: Add the function-pointer fields**

For each, the fptr type uses `CK_MECHANISM*` for the mech and `CK_ATTRIBUTE*` for the attribute array. Sample:

```csharp
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong> C_CreateObject;
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong> C_CopyObject;
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong> C_GetAttributeValue;
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong> C_SetAttributeValue;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong> C_FindObjectsInit;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_EncryptInit;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_DecryptInit;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong> C_DigestInit;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_SignInit;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_SignRecoverInit;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_VerifyInit;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_VerifyRecoverInit;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong> C_GenerateKey;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, CK_ATTRIBUTE*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong*, NativeCULong> C_GenerateKeyPair;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong, byte*, NativeCULong*, NativeCULong> C_WrapKey;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong> C_UnwrapKey;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong> C_DeriveKey;
```

- [ ] **Step 2: Wrappers**

Sample for `C_EncryptInit`:
```csharp
public unsafe NativeCULong C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
{
    if (_fp.C_EncryptInit is null) throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_EncryptInit");
    fixed (CK_MECHANISM* m = &mechanism) return _fp.C_EncryptInit(session, m, key);
}
```

Sample for `C_GenerateKeyPair`:
```csharp
public unsafe NativeCULong C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism,
    CK_ATTRIBUTE[] publicTemplate, NativeCULong publicCount,
    CK_ATTRIBUTE[] privateTemplate, NativeCULong privateCount,
    ref NativeCULong publicKey, ref NativeCULong privateKey)
{
    if (_fp.C_GenerateKeyPair is null) throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GenerateKeyPair");
    fixed (CK_MECHANISM* m = &mechanism)
    fixed (CK_ATTRIBUTE* pub = publicTemplate)
    fixed (CK_ATTRIBUTE* priv = privateTemplate)
    fixed (NativeCULong* pubK = &publicKey)
    fixed (NativeCULong* privK = &privateKey)
        return _fp.C_GenerateKeyPair(session, m, pub, publicCount, priv, privateCount, pubK, privK);
}
```

- [ ] **Step 3: Update populators**

Same direct-cast replacement. Be careful around v3.0 entries when the function also has a v3.0 location (e.g., `C_LoginUser`).

- [ ] **Step 4: Build and test**

```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo -v q 2>&1 | tail -3
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --nologo -v q 2>&1 | tail -3
```

Expected: `0 Error(s)`; `Passed: 565`.

- [ ] **Step 5: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
git commit -m "refactor(aot): migrate mechanism-bound cryptoki fns to fptr dispatch (BL-025 phase 6)"
```

---

## Task 8: Migrate all `_Windows` variants (BL-001 packed-struct dispatch)

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs`

**Scope:** Every cryptoki function that has both a unified and a `_Windows` variant from BL-001. The `_Windows` field uses the `CK_X_Windows` (Pack=1) sibling struct as its parameter types. The dispatch in `LowLevelPkcs11Library.cs` already chooses between them at runtime — that logic stays untouched.

Variants (from the existing `Delegates.cs`):
- `C_CreateObject_Windows`, `C_CopyObject_Windows`, `C_GetAttributeValue_Windows`, `C_SetAttributeValue_Windows`, `C_FindObjectsInit_Windows`
- `C_GetInfo_Windows`, `C_GetSlotInfo_Windows`, `C_GetTokenInfo_Windows`, `C_GetMechanismInfo_Windows`
- `C_EncryptInit_Windows`, `C_DecryptInit_Windows`, `C_DigestInit_Windows`, `C_SignInit_Windows`, `C_VerifyInit_Windows`, etc. (every `_Init` variant)
- `C_GenerateKey_Windows`, `C_GenerateKeyPair_Windows`, `C_WrapKey_Windows`, `C_UnwrapKey_Windows`, `C_DeriveKey_Windows`
- `C_EncapsulateKey_Windows`, `C_DecapsulateKey_Windows`
- `C_AsyncComplete_Windows`, `C_WrapKeyAuthenticated_Windows`, `C_UnwrapKeyAuthenticated_Windows`
- `C_MessageEncryptInit_Windows`, `C_MessageDecryptInit_Windows`, `C_MessageSignInit_Windows`, `C_MessageVerifyInit_Windows`

For each `_Windows` variant, the function-pointer field uses the `_Windows` sibling struct types (`CK_MECHANISM_Windows*`, `CK_ATTRIBUTE_Windows*`, etc.).

- [ ] **Step 1: Add `_Windows` function-pointer fields**

Mirror every Windows delegate in `Native/Delegates.cs`. Sample:

```csharp
    public delegate* unmanaged[Cdecl]<CK_INFO_Windows*, NativeCULong> C_GetInfo_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_SLOT_INFO_Windows*, NativeCULong> C_GetSlotInfo_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_TOKEN_INFO_Windows*, NativeCULong> C_GetTokenInfo_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_MECHANISM_INFO_Windows*, NativeCULong> C_GetMechanismInfo_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong> C_CreateObject_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong> C_CopyObject_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong> C_GetAttributeValue_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong> C_SetAttributeValue_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong> C_FindObjectsInit_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_EncryptInit_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_DecryptInit_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong> C_DigestInit_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_SignInit_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_VerifyInit_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong> C_GenerateKey_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, CK_ATTRIBUTE_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong*, NativeCULong> C_GenerateKeyPair_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong, byte*, NativeCULong*, NativeCULong> C_WrapKey_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong> C_UnwrapKey_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong> C_DeriveKey_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong> C_EncapsulateKey_Windows;
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong> C_DecapsulateKey_Windows;
    // Async / authenticated / message variants follow the same pattern — mirror the existing _Windows delegate signatures.
```

- [ ] **Step 2: Delete each `_Windows` delegate type + field, add wrapper**

Sample for `C_GetInfo_Windows`:
```csharp
public unsafe NativeCULong C_GetInfo_Windows(ref CK_INFO_Windows info)
{
    if (_fp.C_GetInfo_Windows is null) throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetInfo_Windows");
    fixed (CK_INFO_Windows* p = &info) return _fp.C_GetInfo_Windows(p);
}
```

Sample for `C_GenerateKeyPair_Windows`:
```csharp
public unsafe NativeCULong C_GenerateKeyPair_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism,
    CK_ATTRIBUTE_Windows[] publicTemplate, NativeCULong publicCount,
    CK_ATTRIBUTE_Windows[] privateTemplate, NativeCULong privateCount,
    ref NativeCULong publicKey, ref NativeCULong privateKey)
{
    if (_fp.C_GenerateKeyPair_Windows is null) throw new Pkcs11Exception(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GenerateKeyPair_Windows");
    fixed (CK_MECHANISM_Windows* m = &mechanism)
    fixed (CK_ATTRIBUTE_Windows* pub = publicTemplate)
    fixed (CK_ATTRIBUTE_Windows* priv = privateTemplate)
    fixed (NativeCULong* pubK = &publicKey)
    fixed (NativeCULong* privK = &privateKey)
        return _fp.C_GenerateKeyPair_Windows(session, m, pub, publicCount, priv, privateCount, pubK, privK);
}
```

- [ ] **Step 3: Update populators**

For Windows variants, the source function-list pointer is the same as the unified version (both point at the same native function — only the marshalling differs). So:

```csharp
unsafe
{
    _fp.C_GetInfo                = (delegate* unmanaged[Cdecl]<CK_INFO*, NativeCULong>)funcList.C_GetInfo;
    _fp.C_GetInfo_Windows        = (delegate* unmanaged[Cdecl]<CK_INFO_Windows*, NativeCULong>)funcList.C_GetInfo;
}
```

Repeat for every paired entry. Same in `TryLoadV30Symbols` for v3.0 functions.

- [ ] **Step 4: Build and test**

```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo -v q 2>&1 | tail -3
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --nologo -v q 2>&1 | tail -3
```

Expected: `0 Error(s)`; `Passed: 565` (Linux runner — the `_Windows` paths exist but are gated by `Pkcs11Marshal.IsWindows`).

- [ ] **Step 5: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
git commit -m "refactor(aot): migrate _Windows variant cryptoki fns to fptr dispatch (BL-025 phase 7)"
```

---

## Task 9: Migrate remaining v3.0 / v3.2 functions

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs`

**Scope:** The v3.0+ surface bound via `TryLoadV30Symbols` / `TryLoadFromGetInterface` that hasn't yet been migrated.

Functions in this group (any remaining beyond Tasks 5/7):
- `C_LoginUser` (v3.0) — already covered in Task 5 byte[] group; verify.
- `C_SessionCancel` (v3.0) — covered in Task 3; verify.
- `C_MessageEncryptInit`, `C_EncryptMessage`, `C_EncryptMessageBegin`, `C_EncryptMessageNext`, `C_MessageEncryptFinal`
- `C_MessageDecryptInit`, `C_DecryptMessage`, `C_DecryptMessageBegin`, `C_DecryptMessageNext`, `C_MessageDecryptFinal`
- `C_MessageSignInit`, `C_SignMessage`, `C_SignMessageBegin`, `C_SignMessageNext`, `C_MessageSignFinal`
- `C_MessageVerifyInit`, `C_VerifyMessage`, `C_VerifyMessageBegin`, `C_VerifyMessageNext`, `C_MessageVerifyFinal`
- `C_EncapsulateKey`, `C_DecapsulateKey` (v3.2)
- `C_VerifySignatureInit`, `C_VerifySignature`, `C_VerifySignatureUpdate`, `C_VerifySignatureFinal`
- `C_GetSessionValidationFlags`
- `C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin`
- `C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated`
- `C_GetInterfaceList`

Use the same per-function pattern as Tasks 3-7 — pick the right type group, add the function-pointer field, add the wrapper.

- [ ] **Step 1: Identify the unmigrated functions**

Run:
```
grep -n "^internal delegate " src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
```
Anything still listed is an unfinished migration target.

- [ ] **Step 2: Add function-pointer fields + wrappers + populator updates**

For each remaining function, follow the pattern from Tasks 3-7. Pay attention to v3.0/v3.2-only entries — they bind via `TryLoadV30Symbols` / `TryLoadFromGetInterface`, not the v2.40 populator.

- [ ] **Step 3: Confirm zero remaining `internal delegate` declarations**

Run:
```
grep -c "^internal delegate " src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
```
Expected: `0`.

- [ ] **Step 4: Confirm zero remaining `Marshal.GetDelegateForFunctionPointer` calls**

Run:
```
grep -rn "Marshal\.GetDelegateForFunctionPointer" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/ 2>/dev/null
```
Expected: no matches.

- [ ] **Step 5: Build and test**

```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo -v q 2>&1 | tail -3
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --nologo -v q 2>&1 | tail -3
```

Expected: `0 Error(s)`; `Passed: 565`.

- [ ] **Step 6: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
git commit -m "refactor(aot): migrate v3.0/v3.2 cryptoki fns to fptr dispatch (BL-025 phase 8)"
```

---

## Task 10: Migrate `TryGetDelegate` helper + static-link bootstrap

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs`

**Scope:** The two remaining residual `Marshal.GetDelegateForFunctionPointer` patterns:
1. The `TryGetDelegate<T>` helper at the bottom of `Delegates.cs` used for per-symbol lookup on the static-link / fallback path.
2. The `NativeMethods.C_GetFunctionList` `[DllImport("__Internal")]` bootstrap.

- [ ] **Step 1: Replace `TryGetDelegate<T>` with a typed alternative**

Each call site of `TryGetDelegate<T>(libraryHandle, "C_X")` becomes a direct `NativeLibrary.TryGetExport` + cast. Since the typed assignments now go straight into `_fp.C_X` fields (typed `delegate*`), we can inline:

```csharp
if (NativeLibrary.TryGetExport(libraryHandle, "C_SessionCancel", out IntPtr p) && p != IntPtr.Zero)
    unsafe { _fp.C_SessionCancel = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong>)p; }
```

Replace every `TryGetDelegate<X>(...)` callsite with the inlined form. Then delete the helper.

- [ ] **Step 2: Verify `NativeMethods.C_GetFunctionList` DllImport is unchanged**

This `[DllImport("__Internal")]` is the only one in the file and is fully AOT-compatible (no `Marshal.GetDelegateForFunctionPointer`). Leave it as-is.

- [ ] **Step 3: Confirm**

```
grep -c "TryGetDelegate\|Marshal\.GetDelegateForFunctionPointer" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
```
Expected: `0`.

- [ ] **Step 4: Build and test**

```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo -v q 2>&1 | tail -3
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --nologo -v q 2>&1 | tail -3
```

Expected: `0 Error(s)`; `Passed: 565`.

- [ ] **Step 5: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
git commit -m "refactor(aot): inline static-link symbol binding, drop TryGetDelegate helper (BL-025 phase 9)"
```

---

## Task 11: Replace `Marshal.PtrToStructure(IntPtr, Type)` with generic `<T>` form, and address reflection-based packed-struct dispatch

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs` (the v3.0 loader reads `CK_INTERFACE` and `CK_VERSION` via the non-generic form)
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/UnmanagedMemory.cs` (`SizeOf(Type)`, `Write(IntPtr, object)`, `Read(IntPtr, Type)`)
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Pkcs11Marshal.cs` (`SizeOf<T>`, `WriteStructure<T>`, `ReadStructure<T>` + `SiblingCache<T>` reflection lookup)
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/ObjectAttribute.cs:146` (`UnmanagedMemory.SizeOf(typeof(CK_ATTRIBUTE))` callsite)

**Scope:** Two distinct sub-problems lumped here because they share the same fix mechanism (generic instead of `Type`):

**Sub-problem A: `Marshal.PtrToStructure(IntPtr, Type)` calls.**
Direct call sites in `Delegates.cs`:
- Line 1067: `(CK_INTERFACE)UnmanagedMemory.Read(interfacePtr, typeof(CK_INTERFACE))`
- Line 1074: `(CK_VERSION)UnmanagedMemory.Read(iface.FunctionList, typeof(CK_VERSION))`
- Line 1077: `(CK_FUNCTION_LIST_3_0)UnmanagedMemory.Read(iface.FunctionList, typeof(CK_FUNCTION_LIST_3_0))`
- Similar for `CK_FUNCTION_LIST_3_2`

All go through `UnmanagedMemory.Read(IntPtr, Type)`. Fix at the source: add generic overload `UnmanagedMemory.Read<T>(IntPtr) where T : struct` using `Marshal.PtrToStructure<T>`, then migrate every callsite to the generic form.

**Sub-problem B: Reflection-based packed-struct sibling dispatch in `Pkcs11Marshal.SiblingCache<T>`.**
The current pattern:
```csharp
public static readonly Type? WindowsType;
static SiblingCache()
{
    WindowsType = typeof(T).Assembly.GetType(typeof(T).FullName + "_Windows");
    ...
}
```
Uses runtime `Type.GetType(string)` on a constructed name — AOT-hostile, the trimmer can drop the `_Windows` type. The source generator already emits these types into the same assembly; we can replace runtime reflection with a generated registry.

**Fix:** Extend the source generator to emit, alongside each `T_Windows`, two static helpers:
```csharp
internal static class CK_INFO_WindowsSiblings
{
    public static int SizeOfWindows() => Marshal.SizeOf<CK_INFO_Windows>();
    public static CK_INFO ReadUnified(IntPtr ptr) => Marshal.PtrToStructure<CK_INFO_Windows>(ptr).ToUnified();
    public static void WriteUnified(IntPtr ptr, in CK_INFO src) => Marshal.StructureToPtr(CK_INFO_Windows.FromUnified(in src), ptr, false);
}
```
And a single dispatcher class that the generator also emits:
```csharp
internal static partial class PackedDispatch
{
    public static int SizeOf<T>() where T : struct
    {
        if (typeof(T) == typeof(CK_INFO)) return CK_INFO_WindowsSiblings.SizeOfWindows();
        if (typeof(T) == typeof(CK_SLOT_INFO)) return CK_SLOT_INFO_WindowsSiblings.SizeOfWindows();
        // ... etc, one branch per [PackedForPkcs11] type
        return Marshal.SizeOf<T>();
    }
    // Similar Read<T>, Write<T>
}
```
The `typeof(T) == typeof(...)` chain is JIT-folded for each generic instantiation, so AOT collapses each call to a single direct invocation — no reflection.

Then `Pkcs11Marshal.SizeOf<T>`, `ReadStructure<T>`, `WriteStructure<T>` delegate to `PackedDispatch.*`, and `SiblingCache<T>` is deleted.

- [ ] **Step 1: Add generic `Read<T>` to `UnmanagedMemory`**

Edit `Native/UnmanagedMemory.cs`. Add:

```csharp
/// <summary>
/// Generic counterpart of <see cref="Read(IntPtr, Type)"/> that uses
/// <see cref="Marshal.PtrToStructure{T}(IntPtr)"/> — AOT-compatible (no
/// <c>[RequiresDynamicCode]</c>), unlike the legacy <c>Type</c>-accepting overload.
/// </summary>
public static T Read<T>(IntPtr memory) where T : struct
{
    if (memory == IntPtr.Zero) throw new ArgumentNullException(nameof(memory));
    if (IsPackedForPkcs11(typeof(T)))
        return (T)ReadPacked(memory, typeof(T))!;
    return Marshal.PtrToStructure<T>(memory);
}
```

- [ ] **Step 2: Migrate callsites in `Delegates.cs`**

Replace each `(CK_X)UnmanagedMemory.Read(ptr, typeof(CK_X))` with `UnmanagedMemory.Read<CK_X>(ptr)`.

- [ ] **Step 3: Confirm no `(Type)`-accepting overload callsite remains**

```
grep -rn "UnmanagedMemory\.Read(\|UnmanagedMemory\.SizeOf(\|Marshal\.PtrToStructure(\s*[A-Za-z_]\|Marshal\.SizeOf(\s*typeof" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/ 2>/dev/null
```
Inspect each result. Migrate any direct `Marshal.PtrToStructure(ptr, type)` to the generic, and any `Marshal.SizeOf(typeof(...))` to `Marshal.SizeOf<...>()`.

- [ ] **Step 4: Extend the source generator with packed-dispatch helpers**

Edit `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators/PackedStructsGenerator.cs`. After the existing emission for each marked struct, add an additional emission step that produces `<TypeName>_WindowsSiblings.g.cs` with the three helper methods (`SizeOfWindows`, `ReadUnified`, `WriteUnified`).

Then emit a single `PackedDispatch.g.cs` after the `foreach (var sym in syms)` loop:

```csharp
private static void EmitDispatch(SourceProductionContext spc, ImmutableArray<INamedTypeSymbol> syms)
{
    var sb = new StringBuilder();
    sb.AppendLine("// <auto-generated/> PackedStructsGenerator dispatch");
    sb.AppendLine("#nullable enable");
    sb.AppendLine("using System.Runtime.InteropServices;");
    sb.AppendLine();
    sb.AppendLine("namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;");
    sb.AppendLine();
    sb.AppendLine("internal static class PackedDispatch");
    sb.AppendLine("{");
    sb.AppendLine("    public static int SizeOf<T>() where T : struct");
    sb.AppendLine("    {");
    foreach (var sym in syms)
    {
        var fq = sym.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        sb.Append("        if (typeof(T) == typeof(").Append(fq).Append(")) return ").Append(fq).AppendLine("_WindowsSiblings.SizeOfWindows();");
    }
    sb.AppendLine("        return Marshal.SizeOf<T>();");
    sb.AppendLine("    }");
    // Similar Read<T>, Write<T> methods
    sb.AppendLine("}");
    spc.AddSource("PackedDispatch.g.cs", SourceText.From(sb.ToString(), Encoding.UTF8));
}
```

And invoke it from the existing `Emit` method.

- [ ] **Step 5: Delete `SiblingCache<T>` and reflection branches**

In `Native/Pkcs11Marshal.cs`:
- Delete the entire `SiblingCache<T>` nested class.
- Rewrite `SizeOf<T>()`, `WriteStructure<T>`, `ReadStructure<T>` to forward to `PackedDispatch.SizeOf<T>()`, etc., on Windows; fall back to `Marshal.SizeOf<T>()` / `Marshal.PtrToStructure<T>()` / `Marshal.StructureToPtr(structure, ptr, false)` on non-Windows.

In `Native/UnmanagedMemory.cs`:
- Replace `SizeOfPacked(Type t)` body to delegate to `PackedDispatch.SizeOf<T>()` via a small helper that knows the `Type` (since `SizeOfPacked` is called from `SizeOf(Type)`). Practically: change every caller of `UnmanagedMemory.SizeOf(typeof(CK_X))` to `UnmanagedMemory.SizeOf<CK_X>()`.

- [ ] **Step 6: Migrate `ObjectAttribute.cs:146`**

```csharp
int stride = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();
```

- [ ] **Step 7: Build and test**

```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo -v q 2>&1 | tail -3
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --nologo -v q 2>&1 | tail -3
```

Expected: `0 Error(s)`; `Passed: 565`.

- [ ] **Step 8: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/ src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators/
git commit -m "refactor(aot): generic PtrToStructure + generator-emitted packed dispatch (BL-025 phase 10)"
```

---

## Task 12: Enable `<IsAotCompatible>` and verify clean

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`

- [ ] **Step 1: Permanently enable AOT analyzers**

In `KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` first `<PropertyGroup>`, add:

```xml
    <IsAotCompatible>true</IsAotCompatible>
    <EnableAotAnalyzer>true</EnableAotAnalyzer>
    <EnableTrimAnalyzer>true</EnableTrimAnalyzer>
```

- [ ] **Step 2: Build expecting zero AOT/trim warnings**

```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo 2>&1 | grep -E "IL[0-9]{4}|RequiresDynamicCode|RequiresUnreferencedCode" | sort -u
```

Expected output: **no lines**. If anything appears, audit it. Common residual sources:
- `Marshal.SizeOf(Type)` callsites not yet generic
- `Marshal.StructureToPtr(object, ...)` (the non-generic / object overload triggers IL3050 in .NET 8+)
- `Type.GetType(string)` calls
- Any remaining LINQ over `Type` reflection in the source-generator output

For each warning, either migrate the call to an AOT-clean form or annotate it with `[RequiresDynamicCode]` *and* update the BACKLOG. Prefer migration.

- [ ] **Step 3: Verify the full test suite still passes**

```
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --nologo -v q 2>&1 | tail -3
```

Expected: `Passed: 565`.

- [ ] **Step 4: Try an actual AOT publish as a smoke test**

Build a tiny AOT host (one file under `tests/AotSmoke/`) that just loads the library and prints `LibraryInfo.ManufacturerId`:

```bash
mkdir -p tests/AotSmoke && cd tests/AotSmoke
cat > AotSmoke.csproj <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <PublishAot>true</PublishAot>
    <RootNamespace>AotSmoke</RootNamespace>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="..\..\src\KerckhoffsLabs.Security.Cryptography.Pkcs11\KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj" />
  </ItemGroup>
</Project>
EOF
cat > Program.cs <<'EOF'
using KerckhoffsLabs.Security.Cryptography.Pkcs11;
using var lib = new Pkcs11Library(args[0]);
System.Console.WriteLine(lib.GetInfo().ManufacturerId);
EOF
cd ../..
dotnet publish tests/AotSmoke/AotSmoke.csproj -c Release -r linux-x64 -p:PublishAot=true 2>&1 | tail -10
```

Expected: publish succeeds with no `IL3050` / `IL2026` warnings. The resulting binary at `tests/AotSmoke/bin/Release/net10.0/linux-x64/publish/AotSmoke` invoked with the path to pkcs11-mock prints a non-empty manufacturer string.

If the publish fails or warns, return to Task 11 to fix the residual.

- [ ] **Step 5: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj tests/AotSmoke/
git commit -m "refactor(aot): enable IsAotCompatible build flag, add AOT smoke project (BL-025 phase 11)"
```

---

## Task 13: Update BACKLOG.md and close BL-025

**Files:**
- Modify: `BACKLOG.md`

- [ ] **Step 1: Mark BL-025 resolved**

In `BACKLOG.md`, add the `Status:` line at the top of BL-025 mirroring the format used by the recently-closed items (BL-009, BL-015, BL-016, BL-019, BL-020, BL-022). Summarize:
- All 135 cryptoki function delegates replaced by `delegate* unmanaged[Cdecl]<...>` function pointers in a new `FunctionPointers` class
- `Marshal.GetDelegateForFunctionPointer` and `TryGetDelegate` helper removed
- `Marshal.PtrToStructure(IntPtr, Type)` callsites migrated to generic `<T>`
- Reflection-based `SiblingCache<T>` replaced by generator-emitted `PackedDispatch` switch
- `<IsAotCompatible>` enabled; build is now AOT/trim warning-clean
- AOT smoke project (`tests/AotSmoke`) added — `dotnet publish -p:PublishAot=true` succeeds and the resulting binary loads pkcs11-mock successfully

Decrement the **High** count by 1.

- [ ] **Step 2: Commit**

```bash
git add BACKLOG.md
git commit -m "docs(backlog): close BL-025 — AOT-compatible dispatch landed"
```

---

## Final code review

After all 13 tasks complete:

- [ ] **Run `superpowers:requesting-code-review`**

Dispatch the final code reviewer subagent on the full diff from BL-025's first commit to the BACKLOG-close commit. The reviewer should confirm:
- Zero `internal delegate` declarations remain in `Native/Delegates.cs`
- Zero `Marshal.GetDelegateForFunctionPointer` / `Marshal.PtrToStructure(IntPtr, Type)` / `Marshal.SizeOf(Type)` callsites in the assembly (excluding test code)
- Every wrapper method on `Delegates` matches the signature the old delegate field exposed, so call sites are unchanged
- No `[RequiresDynamicCode]` annotations were *added* (only removed)
- The AOT smoke project actually publishes and runs

If anything is flagged, fix it before signing off.
