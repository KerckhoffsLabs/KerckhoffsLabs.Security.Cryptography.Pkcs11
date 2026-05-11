# PKCS11.NET — Utility-Class Redesign Design (Phase 0a)

**Date:** 2026-05-11
**Status:** Approved
**Parent spec:** `2026-05-11-pkcs11-completion-design.md`
**Scope:** Phase 0a — replace upstream `Pkcs11Interop`'s `ConvertUtils2` / `CkaUtils` / `CkmUtils` with idiomatic C# in the local "better-design" port.

## Background

The local codebase at `/home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/` is a from-scratch port of `Pkcs11Interop/Pkcs11Interop` with three upstream utility classes **intentionally omitted**:

1. `Common/ConvertUtils2.cs` (~847 lines, ~70 methods) — per-enum `UInt32From/ToCKx`, `UInt64From/ToCKx`, plus integer conversions.
2. `CkaUtils` (~577 lines) — builds and reads `CK_ATTRIBUTE` structs for typed values, with unmanaged-memory allocation.
3. `CkmUtils` (~152 lines) — builds `CK_MECHANISM` structs.

The omission was deliberate: the author wants a better design than the upstream pattern.

Execution of the original Phase 0 plan ("build fix in 3 trivial edits") surfaced ~409 build errors from call sites of these missing utilities. This sub-spec defines the redesigned replacement and revises Phase 0 sequencing.

## Design summary

| Upstream class | Local replacement |
|---|---|
| `ConvertUtils2.cs` — per-enum integer/enum conversion helpers | (a) explicit cast operators on `NativeCULong` between all primitive integer types; (b) per-enum `ToCULong()`/`ToCKx(NativeCULong)`/`ToCKxChecked(NativeCULong)` extension methods; (c) `<CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>` project-wide. |
| `ConvertUtils1.cs` — `Utf8StringToBytes`, `BytesToUtf8String`, `UtcTimeStringToDateTime`, `BoolToBytes`, `BytesToBool` | Deleted. String conversions become direct `System.Text.Encoding.UTF8` calls. Bool/date helpers fold into `ObjectAttribute` as private statics (their only consumer). |
| `CkaUtils.CreateAttribute` / `ConvertValue` | Inlined into `ObjectAttribute`'s constructors and `GetValueAs*` methods. `ObjectAttribute` becomes `IDisposable` and `sealed`. |
| `CkmUtils.CreateMechanism` | Already replaced by static `CK_MECHANISM.CreateMechanism(...)` factories on the struct (existing local code). 6 call sites in the project rewrite to use them. |

## NativeCULong becomes a first-class primitive

`NativeCULong` already implements `IBinaryInteger<NativeCULong>` and `INumberBase<NativeCULong>`. Add explicit cast operators so callers can write `(uint)x`, `(int)c`, `(NativeCULong)42` without ceremony.

```csharp
// Primitive → NativeCULong (range-checked under <CheckForOverflowUnderflow>true)
public static explicit operator NativeCULong(int    value);
public static explicit operator NativeCULong(uint   value);
public static explicit operator NativeCULong(long   value);
public static explicit operator NativeCULong(ulong  value);
public static explicit operator NativeCULong(nuint  value);

// NativeCULong → primitive (range-checked under <CheckForOverflowUnderflow>true)
public static explicit operator int    (NativeCULong value);
public static explicit operator uint   (NativeCULong value);
public static explicit operator long   (NativeCULong value);
public static explicit operator ulong  (NativeCULong value);
public static explicit operator nuint  (NativeCULong value);
```

All explicit (no silent conversions). All routed through the existing `Value` getter (`nuint`). Range-check semantics inherited from the project-wide `<CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>` setting.

The existing generic-math path remains available for callers who prefer it: `NativeCULong.CreateChecked(x)` and `int.CreateChecked(c)`. XML docs on the operators mention this alternative.

**Project-wide property** added to both `KerckhoffsLabs.Runtime.InteropServices.csproj` and `KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`:

```xml
<PropertyGroup>
  <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
</PropertyGroup>
```

Every plain cast in the project is now range-checked at runtime. Existing `unchecked` blocks (if any) are unaffected.

## Per-enum extension methods (complete the set)

**Current state audit:**

| Enum | `ToCULong()` | `ToCKx()` reverse |
|---|---|---|
| CKA, CKC, CKM | extension (`this`) | only CKM has reverse |
| CKR | static (no `this`) | yes (no `this`) |
| CKD, CKG, CKH, CKK, CKN, CKO, CKP, CKS, CKU | static (no `this`) | no |

**Convention to apply uniformly:**

1. All extensions use `this` (so `value.ToCULong()` works, not `CKxExtensions.ToCULong(value)`).
2. Each enum's extension class is named `<EnumName>Extensions` and sits at the bottom of the matching `Common/<EnumName>.cs` file.
3. Every enum gets both a loose `ToCKx(this NativeCULong)` and a strict `ToCKxChecked(this NativeCULong)`. The loose variant casts through; the strict variant validates via `Enum.IsDefined` and throws `InvalidEnumValueException` on garbage.

```csharp
public static class CKRExtensions
{
    public static NativeCULong ToCULong(this CKR value) => (NativeCULong)(ulong)value;

    /// <summary>Fast cast. Use only when the source value is trusted.</summary>
    public static CKR ToCKR(this NativeCULong value) => (CKR)(ulong)value;

    /// <summary>Validates the value is a defined CKR member. Throws <see cref="InvalidEnumValueException"/> otherwise.</summary>
    public static CKR ToCKRChecked(this NativeCULong value)
    {
        var result = (CKR)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKR), (ulong)value);
        return result;
    }
}
```

**Convention for when to call which.** P/Invoke return-value handlers (HSM-supplied data, malformed responses must fail loudly) use `*Checked`. Internal-only conversions where the value originates in trusted application code use the loose variant. The codebase defaults to `*Checked` everywhere unless a measurable hot path proves otherwise.

**New exception type** in `Common/InvalidEnumValueException.cs`:

```csharp
public sealed class InvalidEnumValueException : Exception
{
    public Type EnumType { get; }
    public ulong RawValue { get; }

    public InvalidEnumValueException(Type enumType, ulong rawValue)
        : base($"Value 0x{rawValue:X} is not a defined member of {enumType.Name}")
    {
        EnumType = enumType;
        RawValue = rawValue;
    }
}
```

Total per-enum work: ~14 reverse extensions added + ~10 method conversions (plain static → `this` extension) + 14 `*Checked` variants. ~250 lines across 14 files.

## ObjectAttribute owns its marshalling

`CkaUtils` is gone. The marshalling logic — `UnmanagedMemory.Allocate`/`Write`, PKCS#11 wire-format encoding — moves into `ObjectAttribute` itself.

```csharp
public sealed class ObjectAttribute : IDisposable
{
    private CK_ATTRIBUTE _ckAttribute;
    private bool _disposed;

    // --- Typed constructors -------------------------------------------------
    public ObjectAttribute(CKA type);
    public ObjectAttribute(CKA type, bool value);
    public ObjectAttribute(CKA type, ulong value);
    public ObjectAttribute(CKA type, string value);
    public ObjectAttribute(CKA type, byte[] value);
    public ObjectAttribute(CKA type, ReadOnlySpan<byte> value);
    public ObjectAttribute(CKA type, DateTime value);
    public ObjectAttribute(CKA type, CKC value);
    public ObjectAttribute(CKA type, CKK value);
    public ObjectAttribute(CKA type, CKO value);
    public ObjectAttribute(CKA type, List<ObjectAttribute> value);
    public ObjectAttribute(CKA type, List<ulong> value);
    public ObjectAttribute(CKA type, List<CKM> value);

    // Raw-vendor-ID overloads for attributes outside the CKA enum
    public ObjectAttribute(ulong type);
    public ObjectAttribute(ulong type, bool value);
    public ObjectAttribute(ulong type, ulong value);
    // ... matching set for every value type above

    // Internal constructor used by Session when reading attributes back
    internal ObjectAttribute(CK_ATTRIBUTE raw);

    // --- Read-back ---------------------------------------------------------
    public ulong  Type { get; }
    public bool   CannotBeRead { get; }
    public bool   GetValueAsBool();
    public ulong  GetValueAsUlong();
    public string GetValueAsString();
    public byte[] GetValueAsByteArray();
    public int    CopyValueTo(Span<byte> destination);   // zero-allocation variant; returns bytes written
    public int    ValueLength { get; }                   // so callers can size their destination
    public DateTime? GetValueAsDateTime();
    public ObjectAttribute[] GetValueAsAttributeArray();
    public ulong[] GetValueAsUlongArray();
    public CKM[]   GetValueAsCkmArray();

    // --- Marshalling adapter ----------------------------------------------
    internal CK_ATTRIBUTE CkAttribute => _ckAttribute;   // by-ref to caller

    // --- Disposal ----------------------------------------------------------
    public void Dispose();
}
```

### Encoding rules — preserved from PKCS#11 spec

Wire formats are spec-mandated; we do not change them.

| Type | Wire format |
|---|---|
| `bool` | 1 byte: `0x01` (true) or `0x00` (false). Read accepts any non-zero as true. |
| `ulong` and enums-as-`ulong` | `sizeof(NativeCULong)` bytes, little-endian |
| `string` | UTF-8, **no null terminator** |
| `DateTime` → `CK_DATE` | 8 bytes ASCII: `value.ToString("yyyyMMdd", CultureInfo.InvariantCulture)` |
| `byte[]` / `ReadOnlySpan<byte>` | copy as-is into unmanaged memory |
| `List<ObjectAttribute>` | contiguous unmanaged buffer of `CK_ATTRIBUTE` structs |
| `List<ulong>` | contiguous array of `NativeCULong`-sized integers |
| `List<CKM>` | same as `List<ulong>` after `mechanism.ToCULong()` per element |

### Correctness improvements vs. upstream that come for free

1. **`IDisposable` lifetime.** Upstream's `ObjectAttribute` allocates unmanaged memory in its constructors but never frees it — a leak per construction. `Dispose` frees `_ckAttribute.value` via `UnmanagedMemory.Free`. Library-internal callers wrap with `using` or own a `List<ObjectAttribute>` they dispose. This is a **breaking change to consumers of the public class**: callers must dispose. Documented in CHANGELOG.
2. **`sealed`.** Today the class is open with no documented extension contract. Sealing prevents subclasses from violating handle-lifetime invariants.
3. **`CannotBeRead` short-circuit.** Every `GetValueAs*` checks `CannotBeRead` first and throws `AttributeValueException("attribute is sensitive or unextractable")` instead of silently returning a zero/empty value (today's behavior on some paths).
4. **Range-checked `valueLen`.** When reading length-prefixed data (`byte[]`, `string`, list types), the cast `(int)valueLen` is checked — `OverflowException` on absurd lengths instead of silent truncation.
5. **Span-friendly buffer API.** Inputs accept `ReadOnlySpan<byte>` alongside `byte[]` (a `byte[]` argument implicitly converts to `ReadOnlySpan<byte>`, so the additional overload is non-breaking). Outputs offer `CopyValueTo(Span<byte> destination)` for zero-allocation reads, returning the number of bytes written. The pre-existing `GetValueAsByteArray()` stays as the convenience form. **`Span<byte>` is never exposed directly over the unmanaged buffer** — disposal would dangle it. The internal `_ckAttribute.value` pointer stays private.

### Lifetime model

```csharp
// Build a template, hand to FindObjectsInit, dispose at end of scope
ObjectAttribute[] template = new[]
{
    new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
    new ObjectAttribute(CKA.CKA_LABEL, "signing-key"),
};
try
{
    using var session = library.OpenSession(...);
    var found = session.FindObjects(template, maxObjects: 10);
}
finally
{
    foreach (var a in template) a.Dispose();
}
```

A `ObjectAttribute[].ToCkAttributeArray()` extension snapshots the underlying `CK_ATTRIBUTE` structs into a contiguous array to hand to P/Invoke without transferring ownership.

## CkmUtils — already replaced

`Native/CK_MECHANISM.cs` already exposes `public static CK_MECHANISM CreateMechanism(CKM mechanism)`, `(CKM mechanism, byte[] parameter)`, and `(CKM mechanism, object parameterStructure)`. Local call sites of `CkmUtils.CreateMechanism(...)` (6 in total) rewrite to `CK_MECHANISM.CreateMechanism(...)`. The internal use of `ConvertUtils.UInt32ToInt32` inside that factory rewrites to `(int)nativeCULong`.

Add one `ReadOnlySpan<byte>` overload for the parameter-bytes path, matching the `ObjectAttribute` precedent:

```csharp
public static CK_MECHANISM CreateMechanism(CKM mechanism, ReadOnlySpan<byte> parameter);
public static CK_MECHANISM CreateMechanism(NativeCULong mechanism, ReadOnlySpan<byte> parameter);
```

Internally these share the existing private `_CreateMechanism` helper, which moves from accepting `byte[]?` to accepting `ReadOnlySpan<byte>` (the `byte[]` overload passes its argument implicitly).

## ConvertUtils — deletion plan

After migration, `Common/ConvertUtils1.cs` is empty and the entire `ConvertUtils` type is deleted.

Call-site substitutions (big-bang in a single PR; all of them mechanical):

| Today | After |
|---|---|
| `ConvertUtils.UInt32FromInt32(x)` | `(NativeCULong)x` |
| `ConvertUtils.UInt32ToInt32(c)` | `(int)c` |
| `ConvertUtils.UInt32FromUInt64(u)` | `(NativeCULong)u` |
| `ConvertUtils.UInt32ToUInt64(c)` | `(ulong)c` |
| `ConvertUtils.UInt32FromCKA(a)` / `UInt64FromCKA(a)` | `a.ToCULong()` then `(uint)` / `(ulong)` if a primitive is needed |
| `ConvertUtils.CULongToCKR(rv)` | `rv.ToCKRChecked()` (default) or `rv.ToCKR()` in hot paths |
| `ConvertUtils.CULongFromCKU(u)` | `u.ToCULong()` |
| `ConvertUtils.Utf8StringToBytes(s)` | `Encoding.UTF8.GetBytes(s)` |
| `ConvertUtils.BytesToUtf8String(b)` | `Encoding.UTF8.GetString(b).TrimEnd('\0')` |
| `ConvertUtils.BoolToBytes(b)` | private static helper inside `ObjectAttribute` |
| `ConvertUtils.BytesToBool(b)` | private helper inside `ObjectAttribute` |
| `ConvertUtils.UtcTimeStringToDateTime(s)` | private helper inside `ObjectAttribute.GetValueAsDateTime()` |

## File inventory

| Action | Path | Why |
|---|---|---|
| Modify | `src/KerckhoffsLabs.Runtime.InteropServices/NativeCULong.cs` | Add 10 explicit cast operators |
| Modify | `src/KerckhoffsLabs.Runtime.InteropServices/KerckhoffsLabs.Runtime.InteropServices.csproj` | `<CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>` |
| Add | `src/KerckhoffsLabs.Runtime.InteropServices.UnitTests/NativeCULongTests.Casts.cs` | Round-trip + overflow tests for the new operators |
| Modify | `src/.../Common/{CKA,CKC,CKD,CKG,CKH,CKK,CKN,CKO,CKP,CKS,CKU}.cs` | Add `*Extensions` static class with `this`-keyword `ToCULong` + `ToCKx` + `ToCKxChecked` |
| Modify | `src/.../Common/{CKM,CKR}.cs` | Add `*Checked` variant; existing methods stay |
| Add | `src/.../Common/InvalidEnumValueException.cs` | New exception type |
| Delete | `src/.../Common/ConvertUtils1.cs` | Class is gone after migration |
| Modify | `src/.../HighLevel/ObjectAttribute.cs` | Fold marshalling inline; add `IDisposable`; tighten `CannotBeRead`; seal |
| Modify | `src/.../Native/CK_MECHANISM.cs` | Replace internal `ConvertUtils.UInt32ToInt32` with cast |
| Modify | `src/.../Native/LowLevelPkcs11Library.cs` | Replace `ConvertUtils.CULongToCKR(rv)` with `rv.ToCKRChecked()` etc. (~70 call sites) |
| Modify | `src/.../Native/Delegates.cs` | Same (~2 call sites) |
| Modify | `src/.../HighLevel/Session.cs` | Cast/extension rewrites (~150 call sites) |
| Modify | `src/.../HighLevel/{Pkcs11Library,Slot,Mechanism,*Info}.cs` | Remaining call-site rewrites |
| Modify | `src/.../KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` | `<CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>` |

**The three mechanical fixes from the original Phase 0 plan also land here** since they're prerequisites for the redesign migration to compile:

| Action | Path | Why |
|---|---|---|
| Modify | `src/.../KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` | Add `<ProjectReference>` to Runtime.InteropServices |
| Modify | `src/.../Native/PlatormSpecificPackAttribute.cs` | Add `using System.Runtime.InteropServices;` |
| Modify | `src/.../Logging/Pkcs11InteropLogUtils.cs` | Add `using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;` |

## Tests added in this phase

1. **`NativeCULongTests.Casts.cs`** in the existing `KerckhoffsLabs.Runtime.InteropServices.UnitTests` project. Round-trips every primitive ↔ `NativeCULong` operator on values across the supported ranges. Overflow tests: assert `OverflowException` from `(NativeCULong)(-1)` under the checked context; assert silent wrap inside an explicit `unchecked` block.
2. **Hand-written sanity tests** for each enum's `ToCULong` round-trip and a representative `ToCKxChecked` failure case. These tests live in `NativeCULongTests` for Phase 0a (they don't need a new test project). They get migrated to a dedicated `Pkcs11.Tests` project in Phase 0b.
3. **Span overload smoke tests.** For each of `ObjectAttribute(CKA, ReadOnlySpan<byte>)` and `CK_MECHANISM.CreateMechanism(CKM, ReadOnlySpan<byte>)`, a single test confirms the span and the `byte[]` overload produce byte-identical unmanaged buffers (mock-free; uses `UnmanagedMemory.Read` to compare). For `ObjectAttribute.CopyValueTo(Span<byte>)`, a test confirms: (a) returns 0 for an empty attribute, (b) writes exactly `ValueLength` bytes for a populated attribute, (c) throws `ArgumentException` when destination is too small.
4. **`ObjectAttribute` tests deferred to Phase 0b** — they require the dedicated test project plus pkcs11-mock's allocation counters to validate the `IDisposable` semantics end-to-end. Phase 0a verifies `ObjectAttribute` compiles. Inline unit testing of its private encoding/decoding helpers is out of scope for Phase 0a; if internals access is needed, Phase 0b adds an `InternalsVisibleTo` attribute on the main library targeting the dedicated test assembly.

## Phasing — revision of the original Phase 0

The original Phase 0 plan (`docs/superpowers/plans/2026-05-11-phase0-build-and-scaffolding.md`) is split:

- **Phase 0a — utility-class redesign (this spec).** Single big-bang PR. End state: `dotnet build src/src.sln` → 0 errors (warnings tolerated and triaged opportunistically). Test summary: existing `NativeCULong` tests pass; new cast-operator tests pass; new enum-extension tests pass. No project-scaffolding work, no submodule, no CI, no test project additions — those are Phase 0b.

- **Phase 0b — build scaffolding** (original Phase 0 minus the build fix). Adds `Pkcs11.Tests` project, `Pkcs11.Mock` project, `pkcs11-mock` submodule, build scripts, MSBuild target, CI workflow, packaging metadata, `net8.0;net9.0` multi-target, MIT `LICENSE`, README. End state: smoke test green against the mock.

- **Phases 1–5** from the parent spec proceed unchanged after Phase 0b.

## Exit criteria for Phase 0a

- `dotnet build src/src.sln -c Release` succeeds with 0 errors on `net9.0` (the only currently-targeted TFM).
- All existing `KerckhoffsLabs.Runtime.InteropServices.UnitTests` tests pass.
- New cast-operator tests in `NativeCULongTests.Casts.cs` pass.
- New enum-extension tests pass.
- `grep -r "ConvertUtils\." src/KerckhoffsLabs.Security.Cryptography.Pkcs11/` returns no results.
- `grep -r "CkaUtils\|CkmUtils" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/` returns no results.
- `Common/ConvertUtils1.cs` is deleted.
- `ObjectAttribute` implements `IDisposable` and is `sealed`.

## Risks and mitigations

1. **Big-bang PR is large.** ~300 modified call sites + new tests + cast operators. Mitigation: tightly templated rewrites (each substitution is one of ~12 patterns from the table above), reviewed against a test suite that exercises the changed paths.
2. **`<CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>` may surface latent bugs.** Casts that quietly truncated today will now throw. Mitigation: tests are run after the property is added; any failing test is a real bug to be fixed in the same PR. Existing `NativeCULong` tests already exercise overflow paths.
3. **`ObjectAttribute.IDisposable` is a breaking change.** Consumers must dispose. Mitigation: Phase 0a is pre-1.0; the breaking change is recorded in commit messages and will land in `CHANGELOG.md` when that file is introduced (Phase 0b's `LICENSE`/`README` step is the natural moment). The analyzer-recognized `IDisposable` warning surfaces missed disposals at compile time, providing an immediate signal to consumers without requiring docs.
4. **`Enum.IsDefined`-backed `*Checked` variants have a small perf overhead.** Mitigation: hot paths can opt into the loose `ToCKx()` variant; documented in XML comments.

## Sequencing within Phase 0a

A natural micro-phasing exists for execution (informs the implementation plan that writing-plans will produce next):

1. Add cast operators on `NativeCULong` + project-wide `CheckForOverflowUnderflow` + tests. (Self-contained, no callers affected.)
2. Add `InvalidEnumValueException` + complete the per-enum extension methods + tests.
3. Apply the three mechanical build fixes from the original plan (project ref + missing usings) to unblock compilation of dependent files.
4. Refactor `ObjectAttribute` to inline the marshalling (constructors and read paths absorb `CkaUtils.CreateAttribute` / `ConvertValue` semantics; class becomes `sealed` and implements `IDisposable`).
5. Rewrite all `ConvertUtils.*` / `CkaUtils.*` / `CkmUtils.*` call sites. Delete `ConvertUtils1.cs`.
6. Run full build and tests. Drive to 0 errors, 0 warnings.

Each step ends with a green build for the files touched so far (with the partial codebase having other files still red). The whole PR is reviewed at step 6.
