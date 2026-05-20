# `*_INFO` Structs → Blittable + Function-Pointer Dispatch (BL-060 completion) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Eliminate the last 10 `[UnmanagedFunctionPointer]` delegates (the `*_INFO` family) by making `CK_INFO`/`CK_SLOT_INFO`/`CK_TOKEN_INFO`/`CK_VERSION` genuinely blittable via `[InlineArray]`, then migrating all 5 `*_INFO` functions (+ `_Windows` variants) to `delegate* unmanaged[Cdecl]` dispatch — achieving uniform function-pointer dispatch across the entire interop layer.

**Architecture:** `CK_SESSION_INFO` and `CK_MECHANISM_INFO` are already blittable (only `NativeCULong` fields) and migrate immediately. `CK_VERSION` becomes two `byte` fields (was `byte[1]` arrays). `CK_INFO`/`CK_SLOT_INFO`/`CK_TOKEN_INFO` replace their `[MarshalAs(ByValArray)] byte[]` fixed-char fields with `[InlineArray(N)]` blittable buffer structs. Once blittable, all 10 functions migrate with the same `fixed (CK_X* p = &x)` pattern used for the other ~125 functions in BL-060.

**Tech Stack:** C# 14 / net10.0, `[System.Runtime.CompilerServices.InlineArray(N)]`, `delegate* unmanaged[Cdecl]<...>`, the existing BL-001 `PackedStructsGenerator`.

**Why this is lower-risk than it first appears:**
- An `[InlineArray]` field is a *struct*, not an array — so `PackedStructsGenerator` treats it as an ordinary blittable field (plain value-copy in `FromUnified`/`ToUnified`, no `[MarshalAs]` forwarding, no array branch). **The generator likely needs zero changes** — verify, don't assume.
- The marshalled size is identical (a 32-byte `[MarshalAs(ByValArray,SizeConst=32)] byte[]` and an `[InlineArray(32)]` byte buffer both marshal to 32 inline bytes), so the `MarshalSizeOfTests` regression suite (from BL-001) is a guardrail that will catch any layout drift.
- `CK_SESSION_INFO`/`CK_MECHANISM_INFO` need no struct changes at all.

**Invariants every task must hold:**
- Full test suite stays at 565 passed / 23 skipped after every commit. **Run the FULL suite, never a filtered subset** — the T4 incident (a non-blittable struct crashing the test host) is exactly what the integration tests catch.
- Build stays zero-AOT-warning (`IsAotCompatible`/`EnableAotAnalyzer`/`EnableTrimAnalyzer` are on).
- `LowLevelPkcs11Library` public method signatures unchanged; the Windows-vs-unified dispatch (`if (Pkcs11Marshal.IsWindows && _delegates.HasC_X_Windows)`) keeps working.
- The `*_INFO` `_Windows` siblings still get `Pack=1` layout from the generator (packing matters for `CK_INFO` — `CK_ULONG Flags` after a 34-byte run aligns differently under Pack=1 vs natural). Do NOT drop `[PackedForPkcs11]` from `CK_INFO`/`CK_SLOT_INFO`/`CK_TOKEN_INFO`.

---

## File Structure

| Path | Change |
|---|---|
| `Native/CkCharBuffer.cs` (new) | `[InlineArray(N)]` blittable byte-buffer helper structs: sizes 16, 32, 64 (the SizeConsts used by the `*_INFO` structs). |
| `Native/CK_VERSION.cs` | `byte[1]` Major/Minor → plain `byte`; drop `[PackedForPkcs11]`; fix `ToString()`. |
| `Native/CK_INFO.cs`, `CK_SLOT_INFO.cs`, `CK_TOKEN_INFO.cs` | `[MarshalAs(ByValArray)] byte[]` fields → `[InlineArray]` buffer types. Keep `[PackedForPkcs11]`. |
| `Native/Delegates.cs` | Delete the 10 `*_INFO` delegate types + fields; add wrappers + populators; the version-negotiation reads (`version.Major[0]` → `version.Major`). |
| `Native/FunctionPointers.cs` | Add 10 `*_INFO` fptr fields. |
| `Native/LowLevelPkcs11Library.cs` | The Windows dispatch sites already use `HasC_X_Windows` / wrapper calls — verify they still compile against the migrated wrappers. |
| `LibraryInfo.cs`, `SlotInfo.cs`, `TokenInfo.cs` | Decode `[InlineArray]` buffers via `Encoding.UTF8.GetString(span)` instead of `byte[]`. |
| `PackedStructsGenerator.cs` | Verify it handles InlineArray fields; change only if the generated `_Windows` siblings are wrong. |

---

## Task 1: Migrate the already-blittable info functions (CK_SESSION_INFO, CK_MECHANISM_INFO)

**These two structs contain only `NativeCULong` fields — already blittable. They were reverted in T4 only because they shared a commit with the non-blittable ones.**

**Files:** `Native/FunctionPointers.cs`, `Native/Delegates.cs`

Functions: `C_GetSessionInfo` (unified + `_Windows`), `C_GetMechanismInfo` (unified + `_Windows`) — 4 functions.

- [ ] **Step 1:** Confirm blittability — read `CK_SESSION_INFO.cs` and `CK_MECHANISM_INFO.cs`; verify only `NativeCULong` fields (no `byte[]`, no `CK_VERSION`).

- [ ] **Step 2:** Add fptr fields to `FunctionPointers.cs`:
```csharp
public delegate* unmanaged[Cdecl]<NativeCULong, CK_SESSION_INFO*, NativeCULong> C_GetSessionInfo;
public delegate* unmanaged[Cdecl]<NativeCULong, CK_SESSION_INFO_Windows*, NativeCULong> C_GetSessionInfo_Windows;
public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_MECHANISM_INFO*, NativeCULong> C_GetMechanismInfo;
public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_MECHANISM_INFO_Windows*, NativeCULong> C_GetMechanismInfo_Windows;
```

- [ ] **Step 3:** In `Delegates.cs`, delete the 4 delegate types + 4 fields. Add wrappers (pattern from BL-060 T4/T8). For the `_Windows` ones add `HasC_X_Windows` properties if the dispatch site in `LowLevelPkcs11Library` needs them (check — `C_GetSessionInfo`/`C_GetMechanismInfo` dispatch sites currently use `_delegates.C_X_Windows is { } winFn`). Example:
```csharp
public unsafe NativeCULong C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
{
    if (_fp.C_GetSessionInfo is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetSessionInfo");
    fixed (CK_SESSION_INFO* p = &info) return _fp.C_GetSessionInfo(session, p);
}
public unsafe NativeCULong C_GetSessionInfo_Windows(NativeCULong session, ref CK_SESSION_INFO_Windows info)
{
    if (_fp.C_GetSessionInfo_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetSessionInfo_Windows");
    fixed (CK_SESSION_INFO_Windows* p = &info) return _fp.C_GetSessionInfo_Windows(session, p);
}
internal unsafe bool HasC_GetSessionInfo_Windows => _fp.C_GetSessionInfo_Windows is not null;
```
Update populators (both unified + `_Windows` bound from the same `funcList` entry). Update the `LowLevelPkcs11Library` dispatch sites if they used the `is { } winFn` capture pattern — switch to `HasC_GetSessionInfo_Windows` + a call to the wrapper, mirroring how the other functions were done in BL-060 T8.

- [ ] **Step 4:** Build (zero IL warnings) + FULL test suite (565):
```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo --no-incremental 2>&1 | grep -E "IL[0-9]{4}|RequiresDynamicCode|RequiresUnreferencedCode" | sort -u
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --nologo -v q 2>&1 | tail -3
```
Expected: empty IL output; `Passed: 565`.

- [ ] **Step 5:** Commit:
```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs
git commit -m "refactor(dispatch): migrate blittable *_INFO fns (session/mechanism) to fptr (BL-060 phase 9)"
```

---

## Task 2: Make CK_VERSION blittable

**Files:** `Native/CK_VERSION.cs`, `Native/Delegates.cs` (version-negotiation reads)

`CK_VERSION` currently uses `[MarshalAs(ByValArray, SizeConst=1)] byte[] Major/Minor` — non-blittable for no reason (it's two bytes). Convert to plain `byte` fields.

- [ ] **Step 1:** Rewrite `CK_VERSION.cs`:
```csharp
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>Describes the version. Blittable: two single-byte fields, identical layout on every platform (byte alignment), so it needs no [PackedForPkcs11] sibling.</summary>
[StructLayout(LayoutKind.Sequential)]
internal partial struct CK_VERSION
{
    /// <summary>Major version number (integer portion).</summary>
    public byte Major;
    /// <summary>Minor version number (hundredths portion).</summary>
    public byte Minor;

    public override readonly string ToString()
    {
        if (Minor == 0x00) return string.Format("{0}.{1}", Major, Minor);
        if (Minor <= 0x63) return string.Format("{0}.{1:D2}", Major, Minor);
        return "Invalid version";
    }
}
```
Note: `[PackedForPkcs11]` is REMOVED (2 bytes, packing is irrelevant; no `_Windows` sibling needed). The struct stays `partial` only if other partials exist — if not, drop `partial`. Verify there are no other `CK_VERSION` partial declarations (there shouldn't be once the generated `CK_VERSION_Windows.g.cs` stops being emitted).

- [ ] **Step 2:** Fix the version-negotiation reads in `Delegates.cs` (around the `TryLoadFromGetInterface` method). The current code:
```csharp
if (version.Major is null || version.Major.Length == 0 || version.Major[0] < 3) return false;
...
if (version.Minor is not null && version.Minor.Length > 0 && version.Minor[0] >= 2)
```
becomes:
```csharp
if (version.Major < 3) return false;
...
if (version.Minor >= 2)
```

- [ ] **Step 3:** Build. The generator will stop emitting `CK_VERSION_Windows.g.cs` (no more `[PackedForPkcs11]`). Any struct that embedded `CK_VERSION_Windows` via the generator's substitution (e.g. `CK_INFO_Windows`, `CK_TOKEN_INFO_Windows`, `CK_SLOT_INFO_Windows`) will now embed plain `CK_VERSION` — which is correct (uniform 2 bytes). Confirm the build is clean:
```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo --no-incremental 2>&1 | grep -E "error|IL[0-9]{4}" | sort -u
```
Expected: no errors, no IL warnings. If there's a "CK_VERSION_Windows not found" error from a generated sibling, it means a struct still references it — that resolves once Task 3 regenerates those siblings, BUT CK_VERSION must compile standalone here. If the error blocks the build, note it and proceed to verify after Task 3, OR if `CK_INFO`/`CK_TOKEN_INFO`/`CK_SLOT_INFO` (still `byte[]` at this point) reference `CK_VERSION_Windows`, the generator substitution for the embedded version field is the cause — in that case do Task 2 and Task 3 together as one commit (the version + InlineArray changes are coupled through the generated siblings).

- [ ] **Step 4:** FULL test suite (565). The `MarshalSizeOfTests` pins `CK_VERSION` size at 2 bytes — must still pass.

- [ ] **Step 5:** Commit:
```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_VERSION.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
git commit -m "refactor(interop): make CK_VERSION blittable (two byte fields, drop packed sibling) (BL-060 phase 10)"
```

**NOTE:** If Step 3 reveals Task 2 and Task 3 are coupled (the generated `*_INFO_Windows` siblings reference `CK_VERSION_Windows`), merge Task 2 and Task 3 into a single commit and skip this separate commit. Report which path you took.

---

## Task 3: Convert CK_INFO / CK_SLOT_INFO / CK_TOKEN_INFO to InlineArray buffers

**Files:** `Native/CkCharBuffer.cs` (new), `Native/CK_INFO.cs`, `Native/CK_SLOT_INFO.cs`, `Native/CK_TOKEN_INFO.cs`, `LibraryInfo.cs`, `SlotInfo.cs`, `TokenInfo.cs`, possibly `PackedStructsGenerator.cs`

- [ ] **Step 1:** Create `Native/CkCharBuffer.cs` with InlineArray buffer structs for the sizes used (16, 32, 64):
```csharp
using System.Runtime.CompilerServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>Blittable inline 16-byte buffer (replaces [MarshalAs(ByValArray, SizeConst=16)] byte[]).</summary>
[InlineArray(16)]
internal struct CkChar16 { private byte _e0; }

/// <summary>Blittable inline 32-byte buffer.</summary>
[InlineArray(32)]
internal struct CkChar32 { private byte _e0; }

/// <summary>Blittable inline 64-byte buffer.</summary>
[InlineArray(64)]
internal struct CkChar64 { private byte _e0; }
```

- [ ] **Step 2:** Rewrite the three structs' char-buffer fields. `CK_INFO.cs`:
```csharp
public CK_VERSION CryptokiVersion;
public CkChar32 ManufacturerId;
public NativeCULong Flags;
public CkChar32 LibraryDescription;
public CK_VERSION LibraryVersion;
```
Remove the `[MarshalAs(...)]` attributes and the `using` for them if now unused. Keep `[StructLayout(LayoutKind.Sequential)]` and `[PackedForPkcs11]`. Do the same for `CK_SLOT_INFO` (`CkChar64 SlotDescription; CkChar32 ManufacturerId;`) and `CK_TOKEN_INFO` (`CkChar32 Label/ManufacturerId; CkChar16 Model/SerialNumber/UtcTime;`).

- [ ] **Step 3:** Update the high-level wrappers to decode via span. In `LibraryInfo.cs`:
```csharp
internal LibraryInfo(CK_INFO ck_info)
{
    CryptokiVersion = ck_info.CryptokiVersion.ToString();
    ManufacturerId = System.Text.Encoding.UTF8.GetString(ck_info.ManufacturerId).TrimEnd();
    Flags = (ulong)ck_info.Flags;
    LibraryDescription = System.Text.Encoding.UTF8.GetString(ck_info.LibraryDescription).TrimEnd();
    LibraryVersion = ck_info.LibraryVersion.ToString();
}
```
`Encoding.UTF8.GetString` has a `ReadOnlySpan<byte>` overload; an `[InlineArray]` field implicitly converts to `ReadOnlySpan<byte>` when accessed from a non-readonly local. If the implicit conversion doesn't bind, use `ck_info.ManufacturerId[..]` to get a `Span<byte>` explicitly. **Compile and verify the exact spelling.** Do the same in `SlotInfo.cs` and `TokenInfo.cs` for every char-buffer field.

- [ ] **Step 4:** Build and inspect the generated `*_INFO_Windows.g.cs`:
```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo --no-incremental 2>&1 | grep -E "error|IL[0-9]{4}" | sort -u
find src/KerckhoffsLabs.Security.Cryptography.Pkcs11/obj/generated -name "CK_INFO_Windows.g.cs" -exec cat {} \;
```
Verify the generated `CK_INFO_Windows` (a) uses `CkChar32` for the buffer fields (not substituted to a `_Windows` type — the buffers aren't packed), (b) embeds plain `CK_VERSION` (not `CK_VERSION_Windows`), (c) `FromUnified`/`ToUnified` do plain value-assignment for the buffer + version fields. If the generator mishandles InlineArray fields (e.g. tries to treat them as arrays or substitute their type), THEN modify `PackedStructsGenerator.cs`:
- The `SubstituteFieldType` should leave `CkChar*` types unchanged (they're not in `packedNames`) — should already work.
- The array branch (`f.Type is IArrayTypeSymbol`) won't trigger for InlineArray structs — should already work.
- `FromUnified`/`ToUnified` should emit `ManufacturerId = src.ManufacturerId` (value copy) — should already work.
Document whether the generator needed changes.

- [ ] **Step 5:** FULL test suite (565). `MarshalSizeOfTests` is the critical guardrail — it pins the marshalled sizes of `CK_INFO`/`CK_SLOT_INFO`/`CK_TOKEN_INFO` and their `_Windows` siblings on both platforms. If sizes drifted, the InlineArray layout differs from the old ByValArray layout — investigate before proceeding. The mock smoke test (`SmokeTests_Mock`) decodes `GetInfo().ManufacturerId` — confirms the buffer round-trips correctly through the still-delegate `C_GetInfo`.

- [ ] **Step 6:** Commit (or combine with Task 2 per its NOTE):
```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CkCharBuffer.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_INFO.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_SLOT_INFO.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_TOKEN_INFO.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/LibraryInfo.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/SlotInfo.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/TokenInfo.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators/PackedStructsGenerator.cs
git commit -m "refactor(interop): make CK_INFO/CK_SLOT_INFO/CK_TOKEN_INFO blittable via InlineArray (BL-060 phase 11)"
```

---

## Task 4: Migrate the 3 now-blittable info functions + final cleanup

**Files:** `Native/FunctionPointers.cs`, `Native/Delegates.cs`, `Native/LowLevelPkcs11Library.cs`, `Native/PackedForPkcs11Attribute.cs` (only if removing the attribute), `BACKLOG.md`

Functions: `C_GetInfo`, `C_GetSlotInfo`, `C_GetTokenInfo` (unified + `_Windows`) — 6 functions. Now blittable, so the simple `fixed` pattern works.

- [ ] **Step 1:** Add 6 fptr fields to `FunctionPointers.cs` (e.g. `delegate* unmanaged[Cdecl]<CK_INFO*, NativeCULong> C_GetInfo;` and the `_Windows` variant with `CK_INFO_Windows*`).

- [ ] **Step 2:** In `Delegates.cs`, delete the 6 delegate types + 6 fields, add wrappers (`fixed (CK_INFO* p = &info)`), add `HasC_X_Windows` properties as needed, update populators. Update `LowLevelPkcs11Library` dispatch sites that used `is { } winFn` capture to use `HasC_X_Windows` + wrapper call (mirroring BL-060 T8).

- [ ] **Step 3:** Confirm ZERO `internal delegate` declarations and ZERO `Marshal.GetDelegateForFunctionPointer` calls remain:
```
grep -c "^internal delegate " src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
grep -n "Marshal.GetDelegateForFunctionPointer" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
```
Expected: `0` and no matches.

- [ ] **Step 4:** Check whether `[UnmanagedFunctionPointer]` is now entirely unused:
```
grep -rn "UnmanagedFunctionPointer" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/ 2>/dev/null | grep -v obj/ | grep -v bin/
```
If no usages remain, that's expected (all delegates gone). No file needs deletion — the attribute is a BCL type, not project-owned.

- [ ] **Step 5:** Build (zero IL warnings) + FULL test suite (565):
```
dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -nologo --no-incremental 2>&1 | grep -E "IL[0-9]{4}|RequiresDynamicCode|RequiresUnreferencedCode" | sort -u
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --nologo -v q 2>&1 | tail -3
```
Expected: empty IL output; `Passed: 565`.

- [ ] **Step 6:** AOT smoke test still publishes + runs:
```
dotnet publish tests/AotSmoke/AotSmoke.csproj -c Release -r linux-x64 -p:PublishAot=true --nologo 2>&1 | tail -5
PUBLISH_DIR=$(find tests/AotSmoke/bin/Release -type d -name publish | head -1)
MOCK=$(find src -name "pkcs11-mock.so" | head -1)
"$PUBLISH_DIR/AotSmoke" "$MOCK"
```
Expected: prints `manufacturer=...` non-empty. This confirms the InlineArray structs round-trip correctly through the full AOT-published native dispatch.

- [ ] **Step 7:** Update `BACKLOG.md` — revise the BL-060 Status line: remove the "*_INFO functions intentionally kept as delegates" caveat and replace with "completed in full — all cryptoki functions now fptr-dispatched; `*_INFO` structs made blittable via `[InlineArray]` (commits …). Zero `[UnmanagedFunctionPointer]` delegates remain." No count change (BL-060 already counted as resolved).

- [ ] **Step 8:** Commit:
```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs \
        BACKLOG.md
git commit -m "refactor(dispatch): migrate *_INFO fns to fptr, retire all delegates (BL-060 complete)"
```

---

## Final review

After Task 4: dispatch a final reviewer to confirm zero delegates, zero `GetDelegateForFunctionPointer`, the InlineArray structs marshal at the correct sizes (MarshalSizeOfTests green on the current platform), and the AOT smoke binary runs. Pay special attention to the generated `*_INFO_Windows.g.cs` since the Windows packing path can't be exercised on the Linux CI — the reviewer should read the generated sibling and confirm field offsets are sane (Pack=1, InlineArray buffers inline, plain CK_VERSION embedded).
