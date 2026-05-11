# PKCS11.NET Phase 0a: Utility-Class Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Drive the PKCS11.NET library to a green build (`dotnet build src/src.sln` → 0 errors) by replacing upstream `Pkcs11Interop`'s `ConvertUtils2` / `CkaUtils` / `CkmUtils` utility classes with idiomatic C#: cast operators on `NativeCULong`, per-enum extension methods, marshalling folded into `ObjectAttribute`, project-wide `<CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>`, and `(ReadOnly)Span<byte>` overloads for buffer parameters.

**Architecture:** Big-bang single-PR rewrite. TDD where it makes sense (the new operators, new extension methods, new exception type); mechanical pattern substitution where it doesn't (the ~410 call-site rewrites). Each task ends in a commit. Build is intentionally red between Tasks 1 and 8; Task 9 drives it to 0 errors.

**Tech Stack:** C# 12 / .NET 9 (Phase 0a stays single-TFM; multi-targeting is Phase 0b). xUnit + `Microsoft.DotNet.XUnitExtensions` for the existing `NativeCULongTests` project.

**Reference spec:** `docs/superpowers/specs/2026-05-11-utility-class-redesign-design.md`

**Pre-flight note (read before starting Task 1):**
A previous execution attempt left a git stash with the entry `task1-partial: 3 mechanical fixes + CKA enum-initializer fix; exposes 409 design-gap errors` on branch `phase-0-build-and-scaffolding`. That stash is **superseded by this plan** — Task 4 redoes those edits cleanly with full understanding of why they exist. Drop the stash before starting:

```bash
git -C /home/alexandre/dev/PKCS11.NET stash list
# If the task1-partial entry is present, drop it:
git -C /home/alexandre/dev/PKCS11.NET stash drop stash@{0}   # adjust index if needed
```

---

## File Structure

After this phase, file changes are:

```
src/
├── KerckhoffsLabs.Runtime.InteropServices/
│   ├── KerckhoffsLabs.Runtime.InteropServices.csproj        [MODIFY — add CheckForOverflowUnderflow]
│   └── NativeCULong.cs                                       [MODIFY — add 10 explicit cast operators]
│
├── KerckhoffsLabs.Runtime.InteropServices.UnitTests/
│   └── NativeCULongTests.Casts.cs                            [CREATE — cast operator tests]
│
└── KerckhoffsLabs.Security.Cryptography.Pkcs11/
    ├── KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj    [MODIFY — add ProjectReference, CheckForOverflowUnderflow]
    │
    ├── Common/
    │   ├── ConvertUtils1.cs                                  [DELETE]
    │   ├── InvalidEnumValueException.cs                      [CREATE]
    │   ├── CKA.cs                                            [MODIFY — fix enum initializer + add ToCKAChecked]
    │   ├── CKC.cs                                            [MODIFY — add ToCKCChecked]
    │   ├── CKM.cs                                            [MODIFY — add ToCKMChecked]
    │   ├── CKD.cs                                            [MODIFY — add `this` keyword + ToCKDChecked]
    │   ├── CKG.cs                                            [MODIFY — add `this` keyword + ToCKGChecked]
    │   ├── CKH.cs                                            [MODIFY — add `this` keyword + ToCKHChecked]
    │   ├── CKK.cs                                            [MODIFY — add `this` keyword + ToCKKChecked]
    │   ├── CKO.cs                                            [MODIFY — add `this` keyword + ToCKOChecked]
    │   ├── CKP.cs                                            [MODIFY — add `this` keyword + ToCKPChecked]
    │   ├── CKR.cs                                            [MODIFY — add `this` keyword + ToCKRChecked]
    │   ├── CKS.cs                                            [MODIFY — add `this` keyword + ToCKSChecked]
    │   ├── CKU.cs                                            [MODIFY — add `this` keyword + ToCKUChecked]
    │   └── CKN.cs                                            [MODIFY — add forward ToCULong + ToCKNChecked]
    │
    ├── Logging/
    │   └── Pkcs11InteropLogUtils.cs                          [MODIFY — add missing using]
    │
    ├── Native/
    │   ├── PlatormSpecificPackAttribute.cs                   [MODIFY — add missing using]
    │   ├── CK_MECHANISM.cs                                   [MODIFY — add ReadOnlySpan overload, cast replaces ConvertUtils call]
    │   ├── LowLevelPkcs11Library.cs                          [MODIFY — ~70 call-site rewrites]
    │   ├── Delegates.cs                                      [MODIFY — ~2 call-site rewrites]
    │   └── UnmanagedMemory.cs                                [MODIFY if needed — caller of ConvertUtils]
    │
    └── HighLevel/
        ├── ObjectAttribute.cs                                [MODIFY — biggest single change; see Task 5]
        ├── Session.cs                                        [MODIFY — bulk of call-site rewrites]
        ├── Pkcs11Library.cs                                  [MODIFY — ~3 call-site rewrites]
        ├── Slot.cs                                           [MODIFY — call-site rewrites]
        ├── Mechanism.cs                                      [MODIFY — call-site rewrites]
        ├── LibraryInfo.cs                                    [MODIFY — call-site rewrites]
        ├── SlotInfo.cs                                       [MODIFY — call-site rewrites]
        ├── TokenInfo.cs                                      [MODIFY — call-site rewrites]
        ├── SessionInfo.cs                                    [MODIFY — call-site rewrites]
        └── MechanismInfo.cs                                  [MODIFY — call-site rewrites]
```

---

## Task 1: Add explicit cast operators to NativeCULong + project-wide checked arithmetic

This is the foundation — every later task assumes the operators exist.

**Files:**
- Modify: `src/KerckhoffsLabs.Runtime.InteropServices/NativeCULong.cs`
- Modify: `src/KerckhoffsLabs.Runtime.InteropServices/KerckhoffsLabs.Runtime.InteropServices.csproj`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`
- Create: `src/KerckhoffsLabs.Runtime.InteropServices.UnitTests/NativeCULongTests.Casts.cs`

- [ ] **Step 1: Write the failing test file**

Create `src/KerckhoffsLabs.Runtime.InteropServices.UnitTests/NativeCULongTests.Casts.cs`:

```csharp
// Licensed under the MIT License

using KerckhoffsLabs.Runtime.InteropServices;
using Xunit;

namespace KerckhoffsLabs.Runtime.InteropServices.UnitTests;

public class NativeCULongCastTests
{
    // ---- Primitive -> NativeCULong (round-trip via Value) -------------------

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(int.MaxValue)]
    public void Cast_FromInt_RoundTrips(int value)
    {
        NativeCULong c = (NativeCULong)value;
        Assert.Equal((uint)value, (uint)c.Value);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(uint.MaxValue)]
    public void Cast_FromUInt_RoundTrips(uint value)
    {
        NativeCULong c = (NativeCULong)value;
        Assert.Equal(value, (uint)c.Value);
    }

    [Fact]
    public void Cast_FromLong_RoundTrips_ZeroAndPositive()
    {
        Assert.Equal(0u, (uint)((NativeCULong)0L).Value);
        Assert.Equal(42u, (uint)((NativeCULong)42L).Value);
    }

    [Fact]
    public void Cast_FromULong_RoundTrips_WithinRange()
    {
        Assert.Equal(0u, (uint)((NativeCULong)0UL).Value);
        Assert.Equal(uint.MaxValue, (uint)((NativeCULong)(ulong)uint.MaxValue).Value);
    }

    [Fact]
    public void Cast_FromNUint_Identity()
    {
        nuint n = 12345;
        NativeCULong c = (NativeCULong)n;
        Assert.Equal(n, c.Value);
    }

    // ---- NativeCULong -> primitive ------------------------------------------

    [Fact]
    public void Cast_ToInt_PreservesValue()
    {
        NativeCULong c = new NativeCULong(42u);
        Assert.Equal(42, (int)c);
    }

    [Fact]
    public void Cast_ToUInt_PreservesValue()
    {
        NativeCULong c = new NativeCULong(42u);
        Assert.Equal(42u, (uint)c);
    }

    [Fact]
    public void Cast_ToLong_PreservesValue()
    {
        NativeCULong c = new NativeCULong(42u);
        Assert.Equal(42L, (long)c);
    }

    [Fact]
    public void Cast_ToULong_PreservesValue()
    {
        NativeCULong c = new NativeCULong(42u);
        Assert.Equal(42UL, (ulong)c);
    }

    [Fact]
    public void Cast_ToNUint_PreservesValue()
    {
        NativeCULong c = new NativeCULong(42u);
        Assert.Equal((nuint)42, (nuint)c);
    }

    // ---- Overflow: with project-wide CheckForOverflowUnderflow=true,
    //               a negative int cast to NativeCULong throws.
    //               Inside explicit `unchecked`, it wraps. -------------------

    [Fact]
    public void Cast_FromNegativeInt_Throws_UnderCheckedContext()
    {
        Assert.Throws<System.OverflowException>(() =>
        {
            int negative = -1;
            NativeCULong _ = (NativeCULong)negative;
        });
    }

    [Fact]
    public void Cast_FromNegativeInt_Wraps_InsideUncheckedBlock()
    {
        unchecked
        {
            int negative = -1;
            NativeCULong c = (NativeCULong)negative;
            Assert.Equal(uint.MaxValue, (uint)c.Value);
        }
    }
}
```

- [ ] **Step 2: Run the new tests; expect compile failure**

Run from repo root: `dotnet test src/src.sln --filter "FullyQualifiedName~NativeCULongCastTests" 2>&1 | tail -10`

Expected: build failure with errors like `error CS0030: Cannot convert type 'int' to 'NativeCULong'` for every cast — the operators don't exist yet.

- [ ] **Step 3: Add explicit cast operators to NativeCULong**

Open `src/KerckhoffsLabs.Runtime.InteropServices/NativeCULong.cs`. Find the existing `public nuint Value => _value;` line (around line 63). Insert the following block **immediately after** that line:

```csharp

    // ---- Explicit cast operators (range-checked under <CheckForOverflowUnderflow>true>) ----
    //
    // These let callers write idiomatic `(NativeCULong)x` and `(int)c` instead of
    // verbose `new NativeCULong((uint)x)` / `(int)c.Value`. With project-wide
    // CheckForOverflowUnderflow enabled, out-of-range conversions throw
    // OverflowException. Callers wanting silent truncation use `unchecked { ... }`.
    //
    // The generic-math path remains available: NativeCULong.CreateChecked(int) and
    // int.CreateChecked(nativeCULong) work today via INumberBase<T>.

    public static explicit operator NativeCULong(int   value) => new NativeCULong((uint)value);
    public static explicit operator NativeCULong(uint  value) => new NativeCULong(value);
    public static explicit operator NativeCULong(long  value) => new NativeCULong((nuint)value);
    public static explicit operator NativeCULong(ulong value) => new NativeCULong((nuint)value);
    public static explicit operator NativeCULong(nuint value) => new NativeCULong(value);

    public static explicit operator int   (NativeCULong value) => (int)value._value;
    public static explicit operator uint  (NativeCULong value) => (uint)value._value;
    public static explicit operator long  (NativeCULong value) => (long)value._value;
    public static explicit operator ulong (NativeCULong value) => (ulong)value._value;
    public static explicit operator nuint (NativeCULong value) => value._value;
```

- [ ] **Step 4: Enable project-wide checked arithmetic in both csprojs**

Open `src/KerckhoffsLabs.Runtime.InteropServices/KerckhoffsLabs.Runtime.InteropServices.csproj`. Find the first `<PropertyGroup>` (the one containing `<TargetFramework>` or `<TargetFrameworks>`). Add this child element to that PropertyGroup, after the existing properties:

```xml
    <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
```

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` and do the same — add the property to the first `<PropertyGroup>`.

- [ ] **Step 5: Rebuild and run the new tests; expect pass**

Run: `dotnet test src/src.sln --filter "FullyQualifiedName~NativeCULongCastTests" 2>&1 | tail -10`

Expected: `Passed: 13, Failed: 0` (or whichever count matches the test methods written). The existing `NativeCULongTests` should also still pass — `dotnet test src/src.sln --filter "FullyQualifiedName~NativeCULongTests"` shows all green.

If a test fails, do not proceed. Diagnose and fix; the cast operators are the foundation of every subsequent task.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Runtime.InteropServices/NativeCULong.cs src/KerckhoffsLabs.Runtime.InteropServices/KerckhoffsLabs.Runtime.InteropServices.csproj src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj src/KerckhoffsLabs.Runtime.InteropServices.UnitTests/NativeCULongTests.Casts.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(NativeCULong): add explicit cast operators + project-wide checked

NativeCULong becomes a first-class primitive: explicit cast operators
to/from int, uint, long, ulong, nuint. Combined with project-wide
<CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>, callers
write idiomatic (NativeCULong)x / (int)c instead of verbose ConvertUtils
helpers. Out-of-range conversions throw OverflowException by default;
explicit unchecked blocks opt out.

This is the foundation that lets us delete ConvertUtils2.cs in later
tasks."
```

---

## Task 2: Add InvalidEnumValueException

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/InvalidEnumValueException.cs`

- [ ] **Step 1: Write the exception class**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/InvalidEnumValueException.cs`:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Thrown when a raw integer value coming from a PKCS#11 module cannot be
/// mapped to a defined member of the expected CK* enum. Always indicates a
/// protocol violation by the module — never an application bug — and should
/// be allowed to propagate.
/// </summary>
public sealed class InvalidEnumValueException : Exception
{
    /// <summary>
    /// The enum type that the raw value was being converted to.
    /// </summary>
    public Type EnumType { get; }

    /// <summary>
    /// The raw integer value that did not match any defined enum member.
    /// </summary>
    public ulong RawValue { get; }

    /// <summary>
    /// Initializes a new <see cref="InvalidEnumValueException"/>.
    /// </summary>
    /// <param name="enumType">The enum type being targeted.</param>
    /// <param name="rawValue">The raw value that failed validation.</param>
    public InvalidEnumValueException(Type enumType, ulong rawValue)
        : base($"Value 0x{rawValue:X} is not a defined member of {enumType.Name}")
    {
        EnumType = enumType;
        RawValue = rawValue;
    }
}
```

- [ ] **Step 2: Verify the project builds**

Run: `dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj 2>&1 | grep -E "Build succeeded|error CS" | head -5`

Expected: build still has the same ~931 errors it had before (we have not started fixing them yet) — but **none** of them point at `InvalidEnumValueException.cs`. The new file itself compiles cleanly.

- [ ] **Step 3: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/InvalidEnumValueException.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Common): add InvalidEnumValueException

Thrown by ToCKxChecked extension methods (added in next task) when a
module-supplied integer cannot be mapped to a defined CK* enum member.
Indicates protocol violation by the module."
```

---

## Task 3: Complete per-enum extension methods

Audit shows 13 enum files need work. Patterns differ slightly across enums; per-file changes are below.

**Files:** all under `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/`:

- `CKA.cs`, `CKC.cs`, `CKM.cs` — already use `this`; only add `ToCKxChecked`
- `CKD.cs`, `CKG.cs`, `CKH.cs`, `CKK.cs`, `CKO.cs`, `CKP.cs`, `CKR.cs`, `CKS.cs`, `CKU.cs` — convert plain statics to `this`-extensions; add `ToCKxChecked`
- `CKN.cs` — add forward `ToCULong` as extension; convert reverse to `this`; add `ToCKNChecked`

`CK.cs`, `CKF.cs`, `CKZ.cs` are flag/constants classes (not enums); skip.

- [ ] **Step 1: For each of CKA, CKC, CKM — add the `*Checked` variant**

For each of `Common/CKA.cs`, `Common/CKC.cs`, `Common/CKM.cs`: locate the existing extension class (e.g. `public static class CKMExtensions`). Inside it, immediately after the existing `ToCKx(this NativeCULong)` method, add a `ToCKxChecked` variant. For `CKM` the addition looks like:

```csharp
    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKM"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// Use this for values coming from the PKCS#11 module (return codes, attribute values, etc.)
    /// where a malformed response must fail loudly. For values that originate in trusted
    /// application code, prefer the loose <see cref="ToCKM(NativeCULong)"/> for speed.
    /// </summary>
    /// <param name="value">NativeCULong value to convert.</param>
    /// <returns>The corresponding CKM enum member.</returns>
    /// <exception cref="InvalidEnumValueException">if <paramref name="value"/> is not a defined CKM member.</exception>
    public static CKM ToCKMChecked(this NativeCULong value)
    {
        CKM result = (CKM)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKM), (ulong)value);
        return result;
    }
```

Replace `CKM` with `CKA` / `CKC` and update the XML doc references accordingly for the other two files.

Each file gets a `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;` only if it's not already a same-namespace file (it is — CKM.cs lives in `Common`, so the using is unnecessary).

- [ ] **Step 2: For each of CKD, CKG, CKH, CKK, CKO, CKP, CKR, CKS, CKU — `this`-keyword the existing methods AND add the `*Checked` variant**

Each of these files has an extension class shaped like (using CKR as the concrete example — the others mirror exactly):

```csharp
public static class CKRExtensions
{
    public static NativeCULong ToCULong(CKR value)
    {
        return new NativeCULong(Convert.ToUInt32(value));
    }

    public static CKR ToCKR(NativeCULong value)
    {
        return (CKR)value.Value;
    }
}
```

Replace it with:

```csharp
public static class CKRExtensions
{
    /// <summary>Converts <see cref="CKR"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKR value)
    {
        return (NativeCULong)(ulong)value;
    }

    /// <summary>
    /// Fast loose cast from <see cref="NativeCULong"/> to <see cref="CKR"/>. Use only when the
    /// value is trusted; otherwise prefer <see cref="ToCKRChecked"/>.
    /// </summary>
    public static CKR ToCKR(this NativeCULong value)
    {
        return (CKR)(ulong)value;
    }

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKR"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// </summary>
    public static CKR ToCKRChecked(this NativeCULong value)
    {
        CKR result = (CKR)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKR), (ulong)value);
        return result;
    }
}
```

Apply the same pattern to `CKD`, `CKG`, `CKH`, `CKK`, `CKO`, `CKP`, `CKS`, `CKU` (substitute the enum name throughout). Note the two structural changes vs. the original:
- `ToCULong(...)` parameter gets `this`; body changes from `new NativeCULong(Convert.ToUInt32(value))` to `(NativeCULong)(ulong)value` (uses the cast operator from Task 1).
- `ToCKx(NativeCULong value)` parameter gets `this`; body becomes `(CKx)(ulong)value` (uniform pattern; the original sometimes used `.Value` which is `nuint`-typed and inconsistent across files).

- [ ] **Step 3: For CKN — add the missing forward direction AND add `*Checked`**

`Common/CKN.cs` has only a reverse method today (plain static, no `this`). Replace the existing extension class (or append a new one if the file lacks one) with:

```csharp
public static class CKNExtensions
{
    /// <summary>Converts <see cref="CKN"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKN value)
    {
        return (NativeCULong)(ulong)value;
    }

    /// <summary>Fast loose cast from <see cref="NativeCULong"/> to <see cref="CKN"/>.</summary>
    public static CKN ToCKN(this NativeCULong value)
    {
        return (CKN)(ulong)value;
    }

    /// <summary>Strict variant; throws <see cref="InvalidEnumValueException"/> on undefined values.</summary>
    public static CKN ToCKNChecked(this NativeCULong value)
    {
        CKN result = (CKN)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKN), (ulong)value);
        return result;
    }
}
```

- [ ] **Step 4: Sanity-check that the extension files compile in isolation**

Each enum file is now a self-contained compilation unit (it only depends on `NativeCULong`, the enum itself, and `InvalidEnumValueException`).

Run: `dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj 2>&1 | grep -E "^.*Common.*CK[A-Z].cs.*error" | head -10`

Expected: **zero errors point at any `Common/CK*.cs` file**. The rest of the codebase remains red (those errors point at Session.cs, LowLevelPkcs11Library.cs, etc. — addressed in later tasks).

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CK*.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Common): standardize per-enum ToCULong / ToCKx / ToCKxChecked

For 13 CK* enums (CKA, CKC, CKD, CKG, CKH, CKK, CKM, CKN, CKO, CKP, CKR,
CKS, CKU): every extension class now exposes a uniform trio of
this-keyword extensions:

  ToCULong(this T)              forward
  ToCKx(this NativeCULong)      loose reverse (fast cast)
  ToCKxChecked(this NativeCULong) strict reverse, Enum.IsDefined-validated,
                                throws InvalidEnumValueException on garbage

Replaces upstream Pkcs11Interop's per-enum UInt32From/ToCKx + UInt64From/ToCKx
static helpers in ConvertUtils2.cs with discoverable, dot-completable
extensions. The strict variant is the default at PKCS#11 boundary handlers;
the loose variant is for trusted internal paths."
```

---

## Task 4: Apply the mechanical build-unblocker fixes

These three trivial fixes are prerequisites for the build to even attempt the design-gap call sites. After this task, the build still has ~409 errors (the call-site errors fixed in Tasks 5–8).

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PlatormSpecificPackAttribute.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Logging/Pkcs11InteropLogUtils.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKA.cs`

- [ ] **Step 1: Add the missing project reference**

Edit `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`. If there is no `<ItemGroup>` containing a `<ProjectReference>` yet, add this above the closing `</Project>`:

```xml
  <ItemGroup>
    <ProjectReference Include="..\KerckhoffsLabs.Runtime.InteropServices\KerckhoffsLabs.Runtime.InteropServices.csproj" />
  </ItemGroup>
```

- [ ] **Step 2: Add `using System.Runtime.InteropServices;` to `PlatormSpecificPackAttribute.cs`**

Edit `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PlatormSpecificPackAttribute.cs`. The file currently starts with the namespace declaration. Make the first line `using System.Runtime.InteropServices;` and add a blank line after it, so the top of the file reads:

```csharp
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
```

- [ ] **Step 3: Add the missing `HighLevel` using to `Pkcs11InteropLogUtils.cs`**

Edit `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Logging/Pkcs11InteropLogUtils.cs`. The file's current first line is `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;`. Append a second using so the top reads:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
```

- [ ] **Step 4: Fix the CKA.cs enum-initializer issue**

`Common/CKA.cs` defines an `enum CKA` whose underlying type allows constant integer expressions only. Four members currently initialize with `CKF.CKF_ARRAY_ATTRIBUTE | 0x000002xx`, but `CKF_ARRAY_ATTRIBUTE` is a runtime `NativeCULong`, not a compile-time constant — illegal in an enum initializer.

Find the four members. Their initializers look like:

```csharp
CKA_WRAP_TEMPLATE      = CKF.CKF_ARRAY_ATTRIBUTE | 0x00000211,
CKA_UNWRAP_TEMPLATE    = CKF.CKF_ARRAY_ATTRIBUTE | 0x00000212,
CKA_DERIVE_TEMPLATE    = CKF.CKF_ARRAY_ATTRIBUTE | 0x00000213,
CKA_ALLOWED_MECHANISMS = CKF.CKF_ARRAY_ATTRIBUTE | 0x00000600,
```

`CKF_ARRAY_ATTRIBUTE` has the literal value `0x40000000` (per PKCS#11 v3.1 spec; verify by reading `Common/CKF.cs` and confirming the constant's numeric value). Replace each member with the inlined literal:

```csharp
CKA_WRAP_TEMPLATE      = 0x40000000 | 0x00000211,
CKA_UNWRAP_TEMPLATE    = 0x40000000 | 0x00000212,
CKA_DERIVE_TEMPLATE    = 0x40000000 | 0x00000213,
CKA_ALLOWED_MECHANISMS = 0x40000000 | 0x00000600,
```

(If `CKF.cs` defines `CKF_ARRAY_ATTRIBUTE` as a different value, use that value instead. Confirm before committing.)

- [ ] **Step 5: Build and confirm the design-gap errors are now visible**

Run from repo root: `dotnet build src/src.sln 2>&1 | tail -3`

Expected: a build failure summary like `~409 Error(s)`. The errors now point at *real* code:
- `ConvertUtils` does not contain a definition for ... (the design-gap errors)
- The name `CkaUtils` does not exist in the current context
- The name `CkmUtils` does not exist in the current context

These are the errors Tasks 5–8 fix. **No `NativeCULong not found` errors should remain.** If any do, the project reference (Step 1) didn't take — diagnose before continuing.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PlatormSpecificPackAttribute.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Logging/Pkcs11InteropLogUtils.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKA.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "fix(build): unblock the design-gap errors with mechanical fixes

Four trivial fixes that surface the real ~409 design-gap errors (called
out in the Phase 0a spec and addressed in subsequent commits):
- ProjectReference to KerckhoffsLabs.Runtime.InteropServices (clears the
  NativeCULong-not-found cascade)
- using System.Runtime.InteropServices; in PlatormSpecificPackAttribute.cs
- using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel; in
  Pkcs11InteropLogUtils.cs (for SessionType reference)
- CKA.cs: inline 0x40000000 instead of CKF.CKF_ARRAY_ATTRIBUTE in 4 enum
  member initializers (runtime NativeCULong is illegal in enum initializer)

Build is now red on the call-site errors, not on infrastructure errors."
```

---

## Task 5: Refactor `ObjectAttribute` to inline its marshalling

This is the largest single change. The class today (`HighLevel/ObjectAttribute.cs`, ~694 lines) has ~20 typed constructors that delegate to `CkaUtils.CreateAttribute(...)` (which doesn't exist) and `GetValueAs*` methods that delegate to `CkaUtils.ConvertValue(...)` (also doesn't exist).

After this task, `ObjectAttribute`:
- Is `sealed` and `IDisposable`.
- Constructors build `_ckAttribute` inline via private helpers (`_CreateAttribute`, `_BuildBoolBytes`, `_BuildDateBytes`, etc.).
- `GetValueAs*` methods unmarshal inline.
- Adds `ObjectAttribute(CKA, ReadOnlySpan<byte>)` and `ObjectAttribute(ulong, ReadOnlySpan<byte>)` overloads.
- Adds `int ValueLength { get; }` and `int CopyValueTo(Span<byte> destination)`.
- Stops referencing `CkaUtils` and `ConvertUtils` entirely.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ObjectAttribute.cs`

- [ ] **Step 1: Read the current file fully**

The file is 694 lines. Read it end-to-end so the refactor preserves the existing public surface (every existing public constructor + `GetValueAs*` method stays callable with the same signature; only the bodies change). Take note of any unusual encoding (e.g., the DateTime branch).

- [ ] **Step 2: Replace the class declaration**

Change line 10 from `public class ObjectAttribute` to `public sealed class ObjectAttribute : IDisposable`.

- [ ] **Step 3: Replace each constructor body and add the inline marshalling helpers**

The entire file body (between `public sealed class ObjectAttribute : IDisposable {` and `}`) becomes the following. Preserve all the existing public surface; add the items called out in the spec.

```csharp
public sealed class ObjectAttribute : IDisposable
{
    private CK_ATTRIBUTE _ckAttribute;
    private bool _disposed;

    // --- Public read surface -------------------------------------------------

    /// <summary>Attribute type (raw, e.g. 0x00000000 for CKA_CLASS).</summary>
    public ulong Type
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return (ulong)_ckAttribute.type;
        }
    }

    /// <summary>Length in bytes of the attribute's value, or 0 if no value.</summary>
    public int ValueLength
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (CannotBeRead) return 0;
            return (int)_ckAttribute.valueLen;
        }
    }

    /// <summary>
    /// True when the underlying CK_ATTRIBUTE's valueLen is the sentinel -1, indicating
    /// the module refused to disclose the attribute (sensitive/unextractable).
    /// </summary>
    public bool CannotBeRead
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return (CLong)_ckAttribute.valueLen == -1;
        }
    }

    // --- Marshalling adapter (internal-only; not exposed publicly) ----------

    internal CK_ATTRIBUTE CkAttribute
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _ckAttribute;
        }
    }

    // --- Constructors --------------------------------------------------------

    /// <summary>Wraps an existing low-level CK_ATTRIBUTE. The instance takes ownership of any unmanaged buffer.</summary>
    internal ObjectAttribute(CK_ATTRIBUTE attribute)
    {
        _ckAttribute = attribute;
    }

    public ObjectAttribute(ulong type)             { _ckAttribute = _CreateAttribute((NativeCULong)type, ReadOnlySpan<byte>.Empty); }
    public ObjectAttribute(CKA   type)             : this((ulong)type) { }

    public ObjectAttribute(ulong type, ulong value)
    {
        Span<byte> buf = stackalloc byte[sizeof(ulong)];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(buf, value);
        _ckAttribute = _CreateAttribute((NativeCULong)type, buf[..UnmanagedMemory.NativeULongSize]);
    }
    public ObjectAttribute(CKA type, ulong value)  : this((ulong)type, value) { }
    public ObjectAttribute(CKA type, CKC   value)  : this((ulong)type, (ulong)value) { }
    public ObjectAttribute(CKA type, CKK   value)  : this((ulong)type, (ulong)value) { }
    public ObjectAttribute(CKA type, CKO   value)  : this((ulong)type, (ulong)value) { }

    public ObjectAttribute(ulong type, bool value)
    {
        Span<byte> buf = stackalloc byte[1];
        buf[0] = value ? (byte)0x01 : (byte)0x00;
        _ckAttribute = _CreateAttribute((NativeCULong)type, buf);
    }
    public ObjectAttribute(CKA type, bool value)   : this((ulong)type, value) { }

    public ObjectAttribute(ulong type, string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        ReadOnlySpan<byte> bytes = System.Text.Encoding.UTF8.GetBytes(value); // no null terminator
        _ckAttribute = _CreateAttribute((NativeCULong)type, bytes);
    }
    public ObjectAttribute(CKA type, string value) : this((ulong)type, value) { }

    public ObjectAttribute(ulong type, byte[] value)
        : this(type, (ReadOnlySpan<byte>)(value ?? Array.Empty<byte>())) { }
    public ObjectAttribute(CKA type, byte[] value) : this((ulong)type, value) { }

    public ObjectAttribute(ulong type, ReadOnlySpan<byte> value)
    {
        _ckAttribute = _CreateAttribute((NativeCULong)type, value);
    }
    public ObjectAttribute(CKA type, ReadOnlySpan<byte> value) : this((ulong)type, value) { }

    public ObjectAttribute(ulong type, DateTime value)
    {
        // CK_DATE wire format: 8 ASCII bytes "YYYYMMDD"
        string formatted = value.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture);
        ReadOnlySpan<byte> bytes = System.Text.Encoding.ASCII.GetBytes(formatted);
        _ckAttribute = _CreateAttribute((NativeCULong)type, bytes);
    }
    public ObjectAttribute(CKA type, DateTime value) : this((ulong)type, value) { }

    public ObjectAttribute(ulong type, List<ObjectAttribute> value)
    {
        ArgumentNullException.ThrowIfNull(value);
        int stride = UnmanagedMemory.SizeOf(typeof(CK_ATTRIBUTE));
        byte[] flat = new byte[stride * value.Count];
        // Marshal each child's CK_ATTRIBUTE into the flat buffer.
        unsafe
        {
            fixed (byte* p = flat)
            {
                IntPtr basePtr = (IntPtr)p;
                for (int i = 0; i < value.Count; i++)
                {
                    IntPtr slot = new IntPtr(basePtr.ToInt64() + (long)i * stride);
                    System.Runtime.InteropServices.Marshal.StructureToPtr<CK_ATTRIBUTE>(value[i]._ckAttribute, slot, false);
                }
            }
        }
        _ckAttribute = _CreateAttribute((NativeCULong)type, flat);
    }
    public ObjectAttribute(CKA type, List<ObjectAttribute> value) : this((ulong)type, value) { }

    public ObjectAttribute(ulong type, List<ulong> value)
    {
        ArgumentNullException.ThrowIfNull(value);
        int stride = UnmanagedMemory.NativeULongSize;
        byte[] flat = new byte[stride * value.Count];
        Span<byte> dest = flat;
        for (int i = 0; i < value.Count; i++)
        {
            // PKCS#11 uses CK_ULONG (NativeCULong) for these lists — 4 bytes on Windows, 8 on Unix-x64.
            // We always write the low 32 bits little-endian when stride==4, otherwise 64 bits.
            if (stride == 4)
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(dest.Slice(i * stride, 4), checked((uint)value[i]));
            else
                System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(dest.Slice(i * stride, 8), value[i]);
        }
        _ckAttribute = _CreateAttribute((NativeCULong)type, flat);
    }
    public ObjectAttribute(CKA type, List<ulong> value) : this((ulong)type, value) { }

    public ObjectAttribute(ulong type, List<CKM> value)
    {
        ArgumentNullException.ThrowIfNull(value);
        // Reuse the List<ulong> path after converting each CKM.
        List<ulong> ulist = new(value.Count);
        for (int i = 0; i < value.Count; i++)
            ulist.Add((ulong)value[i]);
        // Inline rather than `this(type, ulist)` so we only allocate the native buffer once.
        int stride = UnmanagedMemory.NativeULongSize;
        byte[] flat = new byte[stride * ulist.Count];
        Span<byte> dest = flat;
        for (int i = 0; i < ulist.Count; i++)
        {
            if (stride == 4)
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(dest.Slice(i * stride, 4), checked((uint)ulist[i]));
            else
                System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(dest.Slice(i * stride, 8), ulist[i]);
        }
        _ckAttribute = _CreateAttribute((NativeCULong)type, flat);
    }
    public ObjectAttribute(CKA type, List<CKM> value) : this((ulong)type, value) { }

    // --- Read-back -----------------------------------------------------------

    public bool GetValueAsBool()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException("Attribute is sensitive or unextractable.");
        if ((int)_ckAttribute.valueLen != 1)
            throw new AttributeValueException($"Expected 1-byte bool, got {(int)_ckAttribute.valueLen} bytes.");
        byte b = System.Runtime.InteropServices.Marshal.ReadByte(_ckAttribute.value);
        return b != 0;
    }

    public ulong GetValueAsUlong()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException("Attribute is sensitive or unextractable.");
        int len = (int)_ckAttribute.valueLen;
        if (len != UnmanagedMemory.NativeULongSize)
            throw new AttributeValueException($"Expected {UnmanagedMemory.NativeULongSize}-byte CK_ULONG, got {len} bytes.");
        Span<byte> tmp = stackalloc byte[8];
        UnmanagedMemory.Read(_ckAttribute.value, tmp[..len]);
        return len == 4
            ? System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(tmp[..4])
            : System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(tmp[..8]);
    }

    public string GetValueAsString()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException("Attribute is sensitive or unextractable.");
        int len = (int)_ckAttribute.valueLen;
        if (len == 0) return string.Empty;
        byte[] buf = new byte[len];
        UnmanagedMemory.Read(_ckAttribute.value, buf);
        return System.Text.Encoding.UTF8.GetString(buf).TrimEnd('\0');
    }

    public byte[] GetValueAsByteArray()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException("Attribute is sensitive or unextractable.");
        int len = (int)_ckAttribute.valueLen;
        byte[] buf = new byte[len];
        if (len > 0) UnmanagedMemory.Read(_ckAttribute.value, buf);
        return buf;
    }

    /// <summary>
    /// Copies the attribute's raw value bytes into <paramref name="destination"/>. Returns the
    /// number of bytes written. Allocates nothing. Use <see cref="ValueLength"/> to size the
    /// destination buffer.
    /// </summary>
    /// <exception cref="ArgumentException">if <paramref name="destination"/> is too small.</exception>
    public int CopyValueTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException("Attribute is sensitive or unextractable.");
        int len = (int)_ckAttribute.valueLen;
        if (destination.Length < len)
            throw new ArgumentException($"Destination too small: needs {len} bytes, got {destination.Length}.", nameof(destination));
        if (len > 0) UnmanagedMemory.Read(_ckAttribute.value, destination[..len]);
        return len;
    }

    public DateTime? GetValueAsDateTime()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException("Attribute is sensitive or unextractable.");
        int len = (int)_ckAttribute.valueLen;
        if (len == 0) return null;
        if (len != 8) throw new AttributeValueException($"Expected 8-byte CK_DATE, got {len} bytes.");
        byte[] buf = new byte[8];
        UnmanagedMemory.Read(_ckAttribute.value, buf);
        string s = System.Text.Encoding.ASCII.GetString(buf);
        if (!DateTime.TryParseExact(s, "yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture,
                                    System.Globalization.DateTimeStyles.None, out DateTime dt))
        {
            return null;
        }
        return DateTime.SpecifyKind(dt, DateTimeKind.Utc);
    }

    public ObjectAttribute[] GetValueAsAttributeArray()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException("Attribute is sensitive or unextractable.");
        int total = (int)_ckAttribute.valueLen;
        int stride = UnmanagedMemory.SizeOf(typeof(CK_ATTRIBUTE));
        int n = total / stride;
        if (total % stride != 0)
            throw new AttributeValueException("Attribute byte length is not a multiple of CK_ATTRIBUTE size.");
        ObjectAttribute[] result = new ObjectAttribute[n];
        for (int i = 0; i < n; i++)
        {
            IntPtr slot = new IntPtr(_ckAttribute.value.ToInt64() + (long)i * stride);
            CK_ATTRIBUTE attr = (CK_ATTRIBUTE)UnmanagedMemory.Read(slot, typeof(CK_ATTRIBUTE));
            result[i] = new ObjectAttribute(attr);
        }
        return result;
    }

    public ulong[] GetValueAsUlongArray()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException("Attribute is sensitive or unextractable.");
        int stride = UnmanagedMemory.NativeULongSize;
        int total = (int)_ckAttribute.valueLen;
        int n = total / stride;
        if (total % stride != 0)
            throw new AttributeValueException("Attribute byte length is not a multiple of CK_ULONG size.");
        ulong[] result = new ulong[n];
        byte[] buf = new byte[total];
        if (total > 0) UnmanagedMemory.Read(_ckAttribute.value, buf);
        for (int i = 0; i < n; i++)
        {
            ReadOnlySpan<byte> slice = buf.AsSpan(i * stride, stride);
            result[i] = stride == 4
                ? System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(slice)
                : System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(slice);
        }
        return result;
    }

    public CKM[] GetValueAsCkmArray()
    {
        ulong[] raw = GetValueAsUlongArray();
        CKM[] result = new CKM[raw.Length];
        for (int i = 0; i < raw.Length; i++) result[i] = (CKM)raw[i];
        return result;
    }

    // --- IDisposable ---------------------------------------------------------

    public void Dispose()
    {
        if (_disposed) return;
        if (_ckAttribute.value != IntPtr.Zero)
        {
            UnmanagedMemory.Free(ref _ckAttribute.value);
        }
        _ckAttribute.valueLen = (NativeCULong)0;
        _disposed = true;
    }

    // --- Private marshalling kernel ------------------------------------------

    private static CK_ATTRIBUTE _CreateAttribute(NativeCULong type, ReadOnlySpan<byte> value)
    {
        CK_ATTRIBUTE a = new CK_ATTRIBUTE { type = type };
        if (value.Length > 0)
        {
            a.value = UnmanagedMemory.Allocate(value.Length);
            UnmanagedMemory.Write(a.value, value);
            a.valueLen = (NativeCULong)value.Length;
        }
        else
        {
            a.value = IntPtr.Zero;
            a.valueLen = (NativeCULong)0;
        }
        return a;
    }
}

// (The size constant referenced above lives on `UnmanagedMemory` — see Step 4.)
```

Notes on the rewrite:

- The `internal CK_ATTRIBUTE CkAttribute` property replaces the upstream `ToMarshalableStructure()` method — same purpose, idiomatic property, internal access only.
- `_CreateAttribute` is the single allocator for all paths; `byte[]` constructors funnel through `ReadOnlySpan<byte>` overload.
- All paths use `System.Buffers.Binary.BinaryPrimitives` for endian-safe encoding/decoding of `CK_ULONG`-sized integers, avoiding `BitConverter`'s platform-endianness ambiguity.
- The class still depends on `UnmanagedMemory.Allocate / Write / Read / Free / SizeOf`. These already exist in `Native/UnmanagedMemory.cs` (verify in Step 4).

- [ ] **Step 4: Verify and extend `UnmanagedMemory`**

We call `UnmanagedMemory.Allocate(int)`, `UnmanagedMemory.Write(IntPtr, byte[])`, `UnmanagedMemory.Write(IntPtr, ReadOnlySpan<byte>)`, `UnmanagedMemory.Read(IntPtr, byte[])`, `UnmanagedMemory.Read(IntPtr, Span<byte>)`, `UnmanagedMemory.Read(IntPtr, Type)`, `UnmanagedMemory.Free(ref IntPtr)`, `UnmanagedMemory.SizeOf(Type)`, and a new public `UnmanagedMemory.NativeULongSize` property.

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/UnmanagedMemory.cs` and confirm each. If `Write(IntPtr, ReadOnlySpan<byte>)` or `Read(IntPtr, Span<byte>)` is missing, add them next to the existing `byte[]` overloads. The implementations are 3-line wrappers:

```csharp
public static void Write(IntPtr ptr, ReadOnlySpan<byte> data)
{
    unsafe { fixed (byte* src = data) Buffer.MemoryCopy(src, (void*)ptr, data.Length, data.Length); }
}

public static void Read(IntPtr ptr, Span<byte> destination)
{
    unsafe { fixed (byte* dst = destination) Buffer.MemoryCopy((void*)ptr, dst, destination.Length, destination.Length); }
}
```

Also add the `NativeULongSize` constant as a static property somewhere near the top of the class:

```csharp
/// <summary>Size in bytes of one CK_ULONG (NativeCULong) on the current platform: 4 on Windows, 8 on Unix-LP64.</summary>
public static int NativeULongSize { get; } = System.Runtime.InteropServices.Marshal.SizeOf<NativeCULong>();
```

- [ ] **Step 5: Build the ObjectAttribute file in isolation**

Run: `dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj 2>&1 | grep -E "ObjectAttribute\.cs|UnmanagedMemory\.cs" | head -20`

Expected: zero errors point at `ObjectAttribute.cs` or `UnmanagedMemory.cs`. Errors elsewhere are still present and addressed in later tasks.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ObjectAttribute.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/UnmanagedMemory.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor(ObjectAttribute): inline marshalling, IDisposable, ReadOnlySpan API

ObjectAttribute now owns its CK_ATTRIBUTE marshalling end-to-end:
- sealed class implementing IDisposable; constructors call a single
  private _CreateAttribute kernel; GetValueAs* methods unmarshal inline
- Adds ObjectAttribute(CKA|ulong, ReadOnlySpan<byte>) constructor overload
- Adds int ValueLength { get; } and int CopyValueTo(Span<byte>) for
  zero-allocation reads
- All multi-byte encoding/decoding via System.Buffers.Binary, endian-safe
- CannotBeRead is honored in every GetValueAs* (throws
  AttributeValueException instead of silently returning a zero/empty)

Replaces upstream CkaUtils.CreateAttribute / ConvertValue. The internal
CK_ATTRIBUTE getter is used by Session.cs in subsequent commits."
```

---

## Task 6: Add `ReadOnlySpan<byte>` overload to `CK_MECHANISM.CreateMechanism`

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_MECHANISM.cs`

- [ ] **Step 1: Add the Span overload and route `byte[]` through it**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_MECHANISM.cs`. Find the private `_CreateMechanism(NativeCULong, byte[]?)` method (around line 110). Replace the section starting at the public `(CKM, byte[])` overload and ending at the private `_CreateMechanism` with:

```csharp
    public static CK_MECHANISM CreateMechanism(CKM mechanism, byte[]? parameter)
        => CreateMechanism(mechanism.ToCULong(), (ReadOnlySpan<byte>)(parameter ?? Array.Empty<byte>()));

    public static CK_MECHANISM CreateMechanism(NativeCULong mechanism, byte[]? parameter)
        => CreateMechanism(mechanism, (ReadOnlySpan<byte>)(parameter ?? Array.Empty<byte>()));

    public static CK_MECHANISM CreateMechanism(CKM mechanism, ReadOnlySpan<byte> parameter)
        => CreateMechanism(mechanism.ToCULong(), parameter);

    public static CK_MECHANISM CreateMechanism(NativeCULong mechanism, ReadOnlySpan<byte> parameter)
    {
        CK_MECHANISM mech = new() { Mechanism = mechanism };
        if (parameter.Length > 0)
        {
            mech.Parameter = UnmanagedMemory.Allocate(parameter.Length);
            UnmanagedMemory.Write(mech.Parameter, parameter);
            mech.ParameterLen = (NativeCULong)parameter.Length;
        }
        else
        {
            mech.Parameter = IntPtr.Zero;
            mech.ParameterLen = (NativeCULong)0;
        }
        return mech;
    }
```

Also update the `(CKM, object parameterStructure)` overload's body to use the new cast operator (replace `ConvertUtils.UInt32ToInt32(...)` with `(int)...`):

```csharp
    public static CK_MECHANISM CreateMechanism(NativeCULong mechanism, object parameterStructure)
    {
        ArgumentNullException.ThrowIfNull(parameterStructure);
        CK_MECHANISM mech = new()
        {
            Mechanism = mechanism,
            ParameterLen = (NativeCULong)UnmanagedMemory.SizeOf(parameterStructure.GetType())
        };
        mech.Parameter = UnmanagedMemory.Allocate((int)mech.ParameterLen);
        UnmanagedMemory.Write(mech.Parameter, parameterStructure);
        return mech;
    }
```

Remove the now-unused private `_CreateMechanism(NativeCULong, byte[]?)` helper (its logic moved into the `ReadOnlySpan<byte>` overload above).

- [ ] **Step 2: Build CK_MECHANISM.cs in isolation**

Run: `dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj 2>&1 | grep "CK_MECHANISM\.cs"`

Expected: zero errors pointing at `CK_MECHANISM.cs`.

- [ ] **Step 3: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_MECHANISM.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(CK_MECHANISM): add ReadOnlySpan<byte> parameter overload

byte[] overloads now route through ReadOnlySpan<byte> internally. The
internal ConvertUtils.UInt32ToInt32 call is replaced with a (int) cast.
Private _CreateMechanism helper removed; logic absorbed into the Span
overload."
```

---

## Task 7: Mechanical rewrite of all `ConvertUtils.*` call sites

This task is pure pattern substitution. The replacement is one of the 12 patterns from the spec's call-site-substitution table. Apply them in order; build incrementally to confirm each pattern lands cleanly.

The patterns are:

| # | Pattern (old) | Pattern (new) |
|---|---|---|
| A | `ConvertUtils.CULongToCKR(<expr>)` | `(<expr>).ToCKRChecked()` |
| B | `ConvertUtils.UInt32FromInt32(<expr>)` | `(NativeCULong)(<expr>)` |
| C | `ConvertUtils.UInt32ToInt32(<expr>)` | `(int)(<expr>)` |
| D | `ConvertUtils.UInt32FromUInt64(<expr>)` | `(NativeCULong)(<expr>)` |
| E | `ConvertUtils.UInt32ToUInt64(<expr>)` | `(ulong)(<expr>)` |
| F | `ConvertUtils.UInt32FromCKA(<expr>)` | `(uint)(<expr>).ToCULong()` |
| G | `ConvertUtils.UInt64FromCKA(<expr>)` | `(ulong)(<expr>).ToCULong()` |
| H | `ConvertUtils.CULongFromCKU(<expr>)` | `(<expr>).ToCULong()` |
| I | `ConvertUtils.Utf8StringToBytes(<expr>)` | `System.Text.Encoding.UTF8.GetBytes(<expr>)` |
| J | `ConvertUtils.BytesToUtf8String(<expr>)` | `System.Text.Encoding.UTF8.GetString(<expr>).TrimEnd('\0')` |
| K | `ConvertUtils.UtcTimeStringToDateTime(<expr>)` | inline parse (see Step 11 below) |
| L | `ConvertUtils.BoolToBytes` / `BytesToBool` | should not appear outside ObjectAttribute now — verify zero occurrences |

**Files affected (per earlier audit):** `Native/LowLevelPkcs11Library.cs`, `Native/Delegates.cs`, `HighLevel/Session.cs`, `HighLevel/Pkcs11Library.cs`, `HighLevel/Slot.cs`, `HighLevel/Mechanism.cs`, `HighLevel/{LibraryInfo, SlotInfo, TokenInfo, SessionInfo, MechanismInfo}.cs`, plus any `Native/MechanismParams/*.cs` files that reference `ConvertUtils`.

- [ ] **Step 1: Pattern A — `CULongToCKR`**

The most common pattern (~70 call sites). Each replacement is line-local:
```csharp
// Before:
CKR rv = ConvertUtils.CULongToCKR(NativeMethods.C_xxx(...));
// After:
CKR rv = NativeMethods.C_xxx(...).ToCKRChecked();
```

For each `*.cs` file under `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/`, run a search-and-replace from `ConvertUtils.CULongToCKR(` to `(` and append `.ToCKRChecked()` to the matching closing paren of that call. The mechanical way is to use Edit's `replace_all` for the *prefix* — but the suffix needs human or careful regex matching. A practical sequence:

For `Native/LowLevelPkcs11Library.cs` specifically (~70 occurrences, all of the form `return ConvertUtils.CULongToCKR(rv);`):
```csharp
// before
NativeCULong rv = _delegates.C_xxx(...);
return ConvertUtils.CULongToCKR(rv);
// after
NativeCULong rv = _delegates.C_xxx(...);
return rv.ToCKRChecked();
```

So a simple `replace_all` of `return ConvertUtils.CULongToCKR(rv);` with `return rv.ToCKRChecked();` covers most of this file.

Apply analogous substitutions to `Native/Delegates.cs` (~2 occurrences).

- [ ] **Step 2: Build and confirm the CULongToCKR errors are gone**

Run: `dotnet build src/src.sln 2>&1 | grep -c "CULongToCKR"`

Expected: `0`. If non-zero, find the remaining occurrences with `grep -rn "CULongToCKR" src/` and finish substituting.

- [ ] **Step 3: Pattern B — `UInt32FromInt32`**

73 occurrences, varied surrounding contexts. The substitution is `ConvertUtils.UInt32FromInt32(EXPR)` → `(NativeCULong)EXPR` (parens around EXPR not needed when EXPR is a single identifier or simple member access).

For each affected file, apply `replace_all` of these specific forms first (handles the bulk):
- `ConvertUtils.UInt32FromInt32(0)` → `(NativeCULong)0`
- `ConvertUtils.UInt32FromInt32(1)` → `(NativeCULong)1`
- `ConvertUtils.UInt32FromInt32(slotList.Length)` → `(NativeCULong)slotList.Length`
- (etc. — list specifics by grepping)

Pragmatic approach: do the file-by-file replacement in `Session.cs` (the biggest user), running `grep -c "UInt32FromInt32" src/.../HighLevel/Session.cs` before and after to verify each batch landed.

- [ ] **Step 4: Build and confirm `UInt32FromInt32` errors are gone**

Run: `dotnet build src/src.sln 2>&1 | grep -c "UInt32FromInt32"`

Expected: `0`.

- [ ] **Step 5: Pattern C — `UInt32ToInt32`**

55 occurrences. `ConvertUtils.UInt32ToInt32(EXPR)` → `(int)EXPR` (with parens around EXPR if it's a complex expression).

Apply via `replace_all` in each affected file.

- [ ] **Step 6: Build and confirm `UInt32ToInt32` errors are gone**

```
dotnet build src/src.sln 2>&1 | grep -c "UInt32ToInt32"
```
Expected: `0`.

- [ ] **Step 7: Pattern D — `UInt32FromUInt64`**

42 occurrences. `ConvertUtils.UInt32FromUInt64(EXPR)` → `(NativeCULong)EXPR`.

`replace_all` per file. Build check: `grep -c "UInt32FromUInt64"` → `0`.

- [ ] **Step 8: Pattern E — `UInt32ToUInt64`**

6 occurrences. `ConvertUtils.UInt32ToUInt64(EXPR)` → `(ulong)EXPR`.

- [ ] **Step 9: Patterns F, G, H — `UInt32FromCKA`, `UInt64FromCKA`, `CULongFromCKU`**

1 + 3 + 1 = 5 occurrences combined. Apply individually:
- `ConvertUtils.UInt32FromCKA(EXPR)` → `(uint)EXPR.ToCULong()`
- `ConvertUtils.UInt64FromCKA(EXPR)` → `(ulong)EXPR.ToCULong()`
- `ConvertUtils.CULongFromCKU(EXPR)` → `EXPR.ToCULong()`

- [ ] **Step 10: Patterns I and J — UTF-8 string helpers**

10 + 9 = 19 occurrences combined.

`ConvertUtils.Utf8StringToBytes(EXPR)` → `System.Text.Encoding.UTF8.GetBytes(EXPR)`
`ConvertUtils.BytesToUtf8String(EXPR)` → `System.Text.Encoding.UTF8.GetString(EXPR).TrimEnd('\0')`

After applying, add `using System.Text;` to any file whose top doesn't already have it (so callers can drop the `System.Text.` prefix if preferred — optional but cleaner).

- [ ] **Step 11: Pattern K — `UtcTimeStringToDateTime`**

1 occurrence. Find it (likely in `HighLevel/TokenInfo.cs`). Replace with inline parse:

```csharp
// Before:
DateTime? utcTime = ConvertUtils.UtcTimeStringToDateTime(someString);
// After:
DateTime? utcTime = DateTime.TryParseExact(
    someString,
    "yyyyMMddHHmmssff",
    System.Globalization.CultureInfo.InvariantCulture,
    System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
    out var parsed)
        ? parsed
        : (DateTime?)null;
```

(Confirm the format string by checking the original `UtcTimeStringToDateTime` body in `Common/ConvertUtils1.cs` — PKCS#11's CK_TOKEN_INFO uses `YYYYMMDDhhmmssXX` where XX is two reserved characters; the format string above matches.)

- [ ] **Step 12: Confirm zero remaining ConvertUtils references**

```bash
grep -rn "ConvertUtils\." src/KerckhoffsLabs.Security.Cryptography.Pkcs11/ | grep -v "ConvertUtils1.cs" | wc -l
```
Expected: `0`. If non-zero, list and address.

- [ ] **Step 13: Build the solution**

Run: `dotnet build src/src.sln 2>&1 | tail -3`

Expected: still some errors, but **none** mentioning `ConvertUtils`. Remaining errors should be `CkaUtils not found` / `CkmUtils not found` / `ObjectAttribute does not contain a definition for CkAttribute` (Task 5 left an internal field) — these are addressed in Tasks 5 (already done — verify it lined up with the file), 6 (done), 8 (next).

- [ ] **Step 14: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor: rewrite ~410 ConvertUtils.* call sites with new idioms

Mechanical pattern substitution across LowLevelPkcs11Library, Delegates,
Session, Pkcs11Library, Slot, Mechanism, *Info, and MechanismParams files:
- ConvertUtils.CULongToCKR(rv)          -> rv.ToCKRChecked()
- ConvertUtils.UInt32FromInt32(x)       -> (NativeCULong)x
- ConvertUtils.UInt32ToInt32(c)         -> (int)c
- ConvertUtils.UInt32FromUInt64(u)      -> (NativeCULong)u
- ConvertUtils.UInt32ToUInt64(c)        -> (ulong)c
- ConvertUtils.{UInt32,UInt64}FromCKA(a)-> ({uint,ulong})a.ToCULong()
- ConvertUtils.CULongFromCKU(u)         -> u.ToCULong()
- ConvertUtils.Utf8StringToBytes(s)     -> Encoding.UTF8.GetBytes(s)
- ConvertUtils.BytesToUtf8String(b)     -> Encoding.UTF8.GetString(b).TrimEnd('\\0')
- ConvertUtils.UtcTimeStringToDateTime  -> inlined DateTime.TryParseExact

ConvertUtils1.cs deletion comes in the final commit."
```

---

## Task 8: Rewrite `CkmUtils.CreateMechanism` call sites + verify `CkaUtils` is gone

**Files:**
- Modify: any file referencing `CkmUtils.CreateMechanism` (6 occurrences)
- Modify: any file referencing `CkaUtils.CreateAttribute` or `CkaUtils.ConvertValue` (the only legitimate remaining caller after Task 5 should be... none — `ObjectAttribute` no longer uses `CkaUtils`)

- [ ] **Step 1: Locate the 6 `CkmUtils.CreateMechanism` call sites**

```bash
grep -rn "CkmUtils\.CreateMechanism" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
```

Expected: 6 lines. Each substitutes `CkmUtils.CreateMechanism(EXPR1, EXPR2)` → `CK_MECHANISM.CreateMechanism(EXPR1, EXPR2)`.

- [ ] **Step 2: Apply the substitution**

For each file in the grep output, `replace_all` of `CkmUtils.CreateMechanism(` with `CK_MECHANISM.CreateMechanism(`.

- [ ] **Step 3: Confirm `CkmUtils` is unreferenced**

```bash
grep -rn "CkmUtils" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
```

Expected: `0` results.

- [ ] **Step 4: Confirm `CkaUtils` is unreferenced**

```bash
grep -rn "CkaUtils" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
```

Expected: `0` results. (Task 5's rewrite of `ObjectAttribute` should have removed every `CkaUtils.CreateAttribute(...)` / `CkaUtils.ConvertValue(...)` reference. If any remain, fix them now by inlining them via `ObjectAttribute`'s private helpers.)

- [ ] **Step 5: Build**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: either 0 errors (great — proceed to Task 9 cleanup) or only a small remainder of errors. List any remainders before committing.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor: replace CkmUtils.CreateMechanism with CK_MECHANISM.CreateMechanism

The 6 internal call sites that constructed CK_MECHANISM through the
intentionally-omitted CkmUtils helper now use the static factory on
the struct itself. CkmUtils and CkaUtils references are both at zero."
```

---

## Task 9: Add enum-extension tests and Span smoke tests

These tests live in the existing `KerckhoffsLabs.Runtime.InteropServices.UnitTests` project (per spec: "tests live in `NativeCULongTests` for Phase 0a — they don't need a new test project"). The test project needs a reference to the main Pkcs11 library; that reference is safe to add only now, because the Pkcs11 library finally builds clean after Tasks 4–8.

**Files:**
- Modify: `src/KerckhoffsLabs.Runtime.InteropServices.UnitTests/KerckhoffsLabs.Runtime.InteropServices.UnitTests.csproj`
- Create: `src/KerckhoffsLabs.Runtime.InteropServices.UnitTests/EnumExtensionsTests.cs`
- Create: `src/KerckhoffsLabs.Runtime.InteropServices.UnitTests/SpanOverloadSmokeTests.cs`

- [ ] **Step 1: Add the project reference**

Open `src/KerckhoffsLabs.Runtime.InteropServices.UnitTests/KerckhoffsLabs.Runtime.InteropServices.UnitTests.csproj`. In the existing `<ItemGroup>` containing the `<ProjectReference>` to `KerckhoffsLabs.Runtime.InteropServices`, add a second project reference so the item group reads:

```xml
  <ItemGroup>
    <ProjectReference Include="..\KerckhoffsLabs.Runtime.InteropServices\KerckhoffsLabs.Runtime.InteropServices.csproj" />
    <ProjectReference Include="..\KerckhoffsLabs.Security.Cryptography.Pkcs11\KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj" />
  </ItemGroup>
```

Restore: `dotnet restore src/src.sln`. Build to confirm the test project builds: `dotnet build src/KerckhoffsLabs.Runtime.InteropServices.UnitTests/ 2>&1 | tail -3`. Expected: 0 errors.

- [ ] **Step 2: Write enum-extension tests**

Create `src/KerckhoffsLabs.Runtime.InteropServices.UnitTests/EnumExtensionsTests.cs`:

```csharp
// Licensed under the MIT License

using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using Xunit;

namespace KerckhoffsLabs.Runtime.InteropServices.UnitTests;

/// <summary>
/// Round-trip and *Checked-failure tests for the per-enum extension methods.
/// One representative sample per enum keeps the test count reasonable; the
/// extension implementations are mechanically identical across enums.
/// </summary>
public class EnumExtensionsTests
{
    [Fact] public void CKR_RoundTrip()  { CKR v = CKR.CKR_OK;             Assert.Equal(v, v.ToCULong().ToCKR());  Assert.Equal(v, v.ToCULong().ToCKRChecked()); }
    [Fact] public void CKM_RoundTrip()  { CKM v = CKM.CKM_AES_GCM;        Assert.Equal(v, v.ToCULong().ToCKM());  Assert.Equal(v, v.ToCULong().ToCKMChecked()); }
    [Fact] public void CKA_RoundTrip()  { CKA v = CKA.CKA_CLASS;          Assert.Equal(v, v.ToCULong().ToCKA());  Assert.Equal(v, v.ToCULong().ToCKAChecked()); }
    [Fact] public void CKC_RoundTrip()  { CKC v = CKC.CKC_X_509;          Assert.Equal(v, v.ToCULong().ToCKC());  Assert.Equal(v, v.ToCULong().ToCKCChecked()); }
    [Fact] public void CKD_RoundTrip()  { CKD v = CKD.CKD_NULL;           Assert.Equal(v, v.ToCULong().ToCKD());  Assert.Equal(v, v.ToCULong().ToCKDChecked()); }
    [Fact] public void CKG_RoundTrip()  { CKG v = CKG.CKG_MGF1_SHA256;    Assert.Equal(v, v.ToCULong().ToCKG());  Assert.Equal(v, v.ToCULong().ToCKGChecked()); }
    [Fact] public void CKH_RoundTrip()  { CKH v = CKH.CKH_MONOTONIC_COUNTER; Assert.Equal(v, v.ToCULong().ToCKH()); Assert.Equal(v, v.ToCULong().ToCKHChecked()); }
    [Fact] public void CKK_RoundTrip()  { CKK v = CKK.CKK_AES;            Assert.Equal(v, v.ToCULong().ToCKK());  Assert.Equal(v, v.ToCULong().ToCKKChecked()); }
    [Fact] public void CKN_RoundTrip()  { CKN v = CKN.CKN_SURRENDER;      Assert.Equal(v, v.ToCULong().ToCKN());  Assert.Equal(v, v.ToCULong().ToCKNChecked()); }
    [Fact] public void CKO_RoundTrip()  { CKO v = CKO.CKO_PRIVATE_KEY;    Assert.Equal(v, v.ToCULong().ToCKO());  Assert.Equal(v, v.ToCULong().ToCKOChecked()); }
    [Fact] public void CKP_RoundTrip()  { CKP v = CKP.CKP_PKCS5_PBKD2_HMAC_SHA1; Assert.Equal(v, v.ToCULong().ToCKP()); Assert.Equal(v, v.ToCULong().ToCKPChecked()); }
    [Fact] public void CKS_RoundTrip()  { CKS v = CKS.CKS_RO_PUBLIC_SESSION; Assert.Equal(v, v.ToCULong().ToCKS()); Assert.Equal(v, v.ToCULong().ToCKSChecked()); }
    [Fact] public void CKU_RoundTrip()  { CKU v = CKU.CKU_USER;           Assert.Equal(v, v.ToCULong().ToCKU());  Assert.Equal(v, v.ToCULong().ToCKUChecked()); }

    [Fact]
    public void Checked_ThrowsOnUndefinedValue()
    {
        NativeCULong garbage = (NativeCULong)0xDEADBEEFu;
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKRChecked());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKAChecked());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKMChecked());
    }

    [Fact]
    public void Loose_CastsThroughWithoutValidation()
    {
        NativeCULong garbage = (NativeCULong)0xDEADBEEFu;
        // Loose variant does not validate; result is a non-canonical enum value.
        CKR r = garbage.ToCKR();
        Assert.Equal((ulong)0xDEADBEEF, (ulong)r);
    }
}
```

If any enum sample doesn't have the named member used above (e.g., `CKK_AES`), substitute any defined member from that enum — the test only cares that the value round-trips.

- [ ] **Step 3: Write Span overload smoke tests**

Create `src/KerckhoffsLabs.Runtime.InteropServices.UnitTests/SpanOverloadSmokeTests.cs`:

```csharp
// Licensed under the MIT License

using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Xunit;

namespace KerckhoffsLabs.Runtime.InteropServices.UnitTests;

public class SpanOverloadSmokeTests
{
    [Fact]
    public void ObjectAttribute_SpanCtor_ProducesIdenticalBufferToByteArrayCtor()
    {
        byte[] payload = new byte[] { 1, 2, 3, 4, 5 };

        using var fromArray = new ObjectAttribute(CKA.CKA_VALUE, payload);
        using var fromSpan  = new ObjectAttribute(CKA.CKA_VALUE, (ReadOnlySpan<byte>)payload);

        Assert.Equal(fromArray.ValueLength, fromSpan.ValueLength);

        byte[] readBackArray = fromArray.GetValueAsByteArray();
        byte[] readBackSpan  = fromSpan.GetValueAsByteArray();
        Assert.Equal(readBackArray, readBackSpan);
        Assert.Equal(payload, readBackArray);
    }

    [Fact]
    public void ObjectAttribute_CopyValueTo_WritesExactBytesAndReturnsCount()
    {
        byte[] payload = new byte[] { 9, 8, 7 };
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, payload);

        Span<byte> destination = stackalloc byte[8];
        int written = attr.CopyValueTo(destination);

        Assert.Equal(payload.Length, written);
        Assert.Equal(payload, destination[..written].ToArray());
    }

    [Fact]
    public void ObjectAttribute_CopyValueTo_ThrowsWhenDestinationTooSmall()
    {
        byte[] payload = new byte[] { 1, 2, 3, 4, 5 };
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, payload);

        byte[] tooSmall = new byte[3];
        Assert.Throws<ArgumentException>(() => attr.CopyValueTo(tooSmall));
    }

    [Fact]
    public void ObjectAttribute_DoubleDisposeIsSafe()
    {
        var attr = new ObjectAttribute(CKA.CKA_VALUE, new byte[] { 1, 2, 3 });
        attr.Dispose();
        attr.Dispose(); // must not throw
    }

    [Fact]
    public void ObjectAttribute_PostDisposeAccess_Throws()
    {
        var attr = new ObjectAttribute(CKA.CKA_VALUE, new byte[] { 1, 2, 3 });
        attr.Dispose();
        Assert.Throws<ObjectDisposedException>(() => attr.GetValueAsByteArray());
    }

    [Fact]
    public void CKMechanism_SpanCtor_ProducesIdenticalBufferToByteArrayCtor()
    {
        byte[] paramBytes = new byte[] { 0x10, 0x20, 0x30 };

        CK_MECHANISM fromArray = CK_MECHANISM.CreateMechanism(CKM.CKM_AES_GCM, paramBytes);
        CK_MECHANISM fromSpan  = CK_MECHANISM.CreateMechanism(CKM.CKM_AES_GCM, (ReadOnlySpan<byte>)paramBytes);

        try
        {
            Assert.Equal(fromArray.Mechanism, fromSpan.Mechanism);
            Assert.Equal((int)fromArray.ParameterLen, (int)fromSpan.ParameterLen);

            byte[] aBytes = new byte[(int)fromArray.ParameterLen];
            byte[] bBytes = new byte[(int)fromSpan.ParameterLen];
            UnmanagedMemory.Read(fromArray.Parameter, aBytes);
            UnmanagedMemory.Read(fromSpan.Parameter, bBytes);
            Assert.Equal(aBytes, bBytes);
            Assert.Equal(paramBytes, aBytes);
        }
        finally
        {
            UnmanagedMemory.Free(ref fromArray.Parameter);
            UnmanagedMemory.Free(ref fromSpan.Parameter);
        }
    }
}
```

- [ ] **Step 4: Run the new tests; expect pass**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~EnumExtensionsTests|FullyQualifiedName~SpanOverloadSmokeTests" 2>&1 | tail -10
```

Expected: all new tests pass.

If a per-enum round-trip fails, check the enum file for that enum — the extension class likely has a typo or a stale plain-static method shadowing the new `this`-extension.

If a Span smoke test fails, debug the relevant constructor in `ObjectAttribute.cs` or `CK_MECHANISM.cs`.

- [ ] **Step 5: Run the full test suite to confirm nothing else regressed**

```bash
dotnet test src/src.sln 2>&1 | tail -10
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Runtime.InteropServices.UnitTests/
git -C /home/alexandre/dev/PKCS11.NET commit -m "test: enum-extension round-trips and Span overload smoke tests

Adds two test files to the existing Runtime.InteropServices unit-test
project (with a project reference to the main Pkcs11 library):

- EnumExtensionsTests.cs: per-enum ToCULong / ToCKx / ToCKxChecked
  round-trip sample (1 representative member per enum) plus negative
  tests confirming ToCKxChecked throws InvalidEnumValueException on
  undefined values and ToCKx (loose) does not validate.

- SpanOverloadSmokeTests.cs: ObjectAttribute and CK_MECHANISM Span
  overloads produce byte-identical unmanaged buffers vs the byte[]
  overloads. CopyValueTo writes the expected count and throws on
  too-small destinations. ObjectAttribute disposes idempotently and
  throws ObjectDisposedException on post-dispose access.

These tests migrate to a dedicated Pkcs11.Tests project in Phase 0b."
```

---

## Task 10: Final cleanup — delete `ConvertUtils1.cs`, drive build to 0 errors, run full tests

**Files:**
- Delete: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/ConvertUtils1.cs`

- [ ] **Step 1: Delete the file**

```bash
git -C /home/alexandre/dev/PKCS11.NET rm src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/ConvertUtils1.cs
```

- [ ] **Step 2: Clean build + full build**

```bash
cd /home/alexandre/dev/PKCS11.NET
dotnet clean src/src.sln >/dev/null
dotnet build src/src.sln --configuration Debug 2>&1 | tail -5
```

Expected: `0 Error(s)`. Warnings tolerated for this phase (Phase 0b/1 phases will clean them up).

If errors remain, they are real residuals — diagnose and fix. Common cases:
- A `ConvertUtils.X` reference in a file I missed: add to Task 7's pattern set and re-apply.
- A `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common.ConvertUtils;`-style import: remove it.
- A test or doc reference: remove or update.

- [ ] **Step 3: Run the full test suite**

```bash
dotnet test src/src.sln --no-build --logger "console;verbosity=normal" 2>&1 | tail -20
```

Expected: All tests pass. The count includes the original `NativeCULongTests` (~20+) plus the new `NativeCULongCastTests` (13 tests).

If any test fails: do not commit. Diagnose. Common cases:
- A cast that silently truncated before now throws `OverflowException`. The test exercising it must be updated (and the production callsite, if the truncation was a bug, also fixed). Either is a real finding worth a separate commit if substantive.

- [ ] **Step 4: Verify the exit-criteria invariants**

```bash
# No more references to the deleted utility classes:
grep -rn "ConvertUtils\." src/KerckhoffsLabs.Security.Cryptography.Pkcs11/ ; echo "exit=$?"
grep -rn "CkaUtils\|CkmUtils" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/ ; echo "exit=$?"
# ConvertUtils1.cs is gone:
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/ConvertUtils1.cs 2>&1
# ObjectAttribute is sealed + IDisposable:
grep -E "public sealed class ObjectAttribute|: IDisposable" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ObjectAttribute.cs
```

Expected:
- Both `grep -rn` produce no output (`exit=1` from grep).
- `ls` reports "No such file or directory".
- The class-declaration grep shows the sealed + `IDisposable` declaration.

- [ ] **Step 5: Final commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET commit -m "chore: delete ConvertUtils1.cs (now empty); Phase 0a complete

Phase 0a exit criteria met:
- dotnet build src/src.sln: 0 errors
- All KerckhoffsLabs.Runtime.InteropServices.UnitTests pass (existing
  NativeCULong tests + new NativeCULongCastTests)
- Zero references to ConvertUtils, CkaUtils, CkmUtils
- ObjectAttribute is sealed and IDisposable
- ConvertUtils1.cs deleted

Library is now ready for Phase 0b (build scaffolding) and Phases 1-5
(API completion + test suite)."
```

- [ ] **Step 6: Optional milestone tag**

```bash
git -C /home/alexandre/dev/PKCS11.NET tag -a phase-0a-complete -m "Phase 0a complete: utility-class redesign; clean build; tests green"
```

---

## Phase 0a Exit Checklist

- [ ] `dotnet build src/src.sln -c Debug` succeeds with 0 errors.
- [ ] `dotnet build src/src.sln -c Release` succeeds with 0 errors.
- [ ] `dotnet test src/src.sln --no-build` shows all tests passing.
- [ ] `grep -rn "ConvertUtils\." src/KerckhoffsLabs.Security.Cryptography.Pkcs11/` returns no results.
- [ ] `grep -rn "CkaUtils\|CkmUtils" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/` returns no results.
- [ ] `Common/ConvertUtils1.cs` is deleted.
- [ ] `ObjectAttribute` is declared `public sealed class ObjectAttribute : IDisposable`.
- [ ] `NativeCULong` defines explicit cast operators to/from `int`, `uint`, `long`, `ulong`, `nuint`.
- [ ] Both `KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` and `KerckhoffsLabs.Runtime.InteropServices.csproj` have `<CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>`.
- [ ] Each of 13 `CK*` enum extension classes (CKA, CKC, CKD, CKG, CKH, CKK, CKM, CKN, CKO, CKP, CKR, CKS, CKU) exposes `ToCULong(this T)`, `ToCKx(this NativeCULong)`, and `ToCKxChecked(this NativeCULong)`.
- [ ] `Common/InvalidEnumValueException.cs` exists.
- [ ] `Native/CK_MECHANISM.cs` exposes a `(CKM, ReadOnlySpan<byte>)` overload.

When all checked, Phase 0a is complete. Phase 0b (build scaffolding) plan can be written next.
