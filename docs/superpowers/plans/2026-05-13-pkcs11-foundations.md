# PKCS11 Foundations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land internal seams the rest of the redesign depends on — typed exception hierarchy with centralized CKR mapping, and a fluent `ObjectTemplate` builder — without changing any existing public API behavior.

**Architecture:** Purely additive. New typed exception subclasses sit under the existing `Pkcs11Exception` base, all native call-sites route through a new central `Pkcs11Exception.ThrowIfError(CKR, string)` helper, and a new `ObjectTemplate` + per-class fluent builders coexist with the current `List<ObjectAttribute>` template construction (which keeps working). No type is removed; no public method changes shape.

**Tech Stack:** C# 12, .NET 8/9 (multi-target), xUnit 2.9, Microsoft.DotNet.XUnitExtensions, coverlet.

**Spec:** `docs/superpowers/specs/2026-05-13-pkcs11-bcl-aligned-redesign-design.md`

**Working directory:** `/home/alexandre/dev/PKCS11.NET`

---

## Project conventions worth knowing

- **Solution file:** `src/KerckhoffsLabs.sln`. Build everything with `dotnet build src/KerckhoffsLabs.sln -c Debug`. Run all tests with `dotnet test src/KerckhoffsLabs.sln -c Debug`. Run a single test class with `dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj --filter "FullyQualifiedName~ClassName"`.
- **InternalsVisibleTo:** the test project already sees internals of the production assembly (`<InternalsVisibleTo Include="KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests" />`). Tests can construct internal types directly.
- **Existing exception namespace:** `KerckhoffsLabs.Security.Cryptography.Pkcs11.Common`. Plan 1 does **not** move files between folders — that is Plan 4's job. All new exception types in this plan go under `Common/` next to the existing `Pkcs11Exception.cs`.
- **Existing exception shape:** `Pkcs11Exception` is currently a concrete `public class` with primary ctor `(string method, CKR rv)`, properties `Method` and `RV`. There are no external consumers of these properties — only the production code throws them. Renaming `RV → ReturnValue` and reordering the ctor parameters is safe.
- **Existing throw pattern:** every native call site looks like

  ```csharp
  CKR rv = _p11.C_SomeMethod(...);
  if (rv != CKR.CKR_OK)
      throw new Pkcs11Exception("C_SomeMethod", rv);
  ```

  appearing 129 times across 13 files. The target pattern is

  ```csharp
  CKR rv = _p11.C_SomeMethod(...);
  Pkcs11Exception.ThrowIfError(rv, "C_SomeMethod");
  ```
- **ObjectAttribute is `IDisposable`** — it owns an unmanaged buffer. Anything that holds `ObjectAttribute` instances and exposes a builder must dispose them deterministically (including in error paths and when `.Build()` is never called).
- **xUnit conventions:** the test project uses xUnit 2.9 with `[Fact]` and `[Theory]`. Assertions use `Assert.Throws<T>(Action)` / `Assert.IsType<T>(obj)` / `Assert.Equal(...)`. No additional fixture is required for managed-only tests in this plan.
- **Commits:** the project is not under git source control inside the workspace (`Is a git repository: false` in the host environment context) — there is no expectation to run `git commit`. Instead, after each task is complete, the implementer reports completion to the orchestrator. **Treat "Commit" steps below as completion checkpoints, not actual `git commit` invocations.**

---

## File structure

### New files

```
src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
├── Common/
│   ├── ExceptionMapper.cs                   internal. CKR → typed subclass.
│   ├── Pkcs11AuthenticationException.cs     PUBLIC. CKR_PIN_*, CKR_USER_*.
│   ├── Pkcs11SessionException.cs            PUBLIC. CKR_SESSION_*.
│   ├── Pkcs11TokenException.cs              PUBLIC. CKR_TOKEN_*, CKR_DEVICE_*.
│   ├── Pkcs11MechanismException.cs          PUBLIC. CKR_MECHANISM_*, CKR_KEY_FUNCTION_NOT_PERMITTED.
│   ├── Pkcs11ObjectException.cs             PUBLIC. CKR_OBJECT_*, CKR_ATTRIBUTE_*.
│   ├── Pkcs11ArgumentException.cs           PUBLIC. CKR_ARGUMENTS_BAD, CKR_DATA_INVALID, CKR_BUFFER_TOO_SMALL.
│   └── Pkcs11UnclassifiedException.cs       PUBLIC. CKR values not covered above.
│
└── HighLevel/
    ├── ObjectTemplate.cs                    PUBLIC. Owns disposable attributes. Static factories.
    ├── ObjectTemplateBuilderBase.cs         internal. Generic CRTP base for all builders.
    ├── SecretKeyTemplateBuilder.cs          PUBLIC.
    ├── PrivateKeyTemplateBuilder.cs         PUBLIC.
    ├── PublicKeyTemplateBuilder.cs          PUBLIC.
    ├── CertificateTemplateBuilder.cs        PUBLIC.
    ├── DataTemplateBuilder.cs               PUBLIC.
    └── GenericTemplateBuilder.cs            PUBLIC.
```

### Modified files

```
src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
├── Common/Pkcs11Exception.cs                Rename RV → ReturnValue, reorder ctor args,
│                                            add ThrowIfError static, make abstract.
│
└── HighLevel/                               Migrate throw sites (mechanical sweep, no
    ├── Pkcs11Library.cs                       behavior change). 13 files total.
    ├── Session.cs
    ├── Session.Derive.cs
    ├── Session.Decrypt.cs
    ├── Session.Encrypt.cs
    ├── Session.Sign.cs
    ├── Session.Random.cs
    ├── Session.Objects.cs
    ├── Slot.cs
    ├── Session.Verify.cs
    ├── Session.Digest.cs
    └── Session.Keys.cs
src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
└── Native/Delegates.cs                      2 throw sites in C_GetFunctionList fallback.
```

### New test files

```
src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
└── HighLevel/
    ├── Pkcs11ExceptionTests.cs              ThrowIfError dispatch, ReturnValue property.
    ├── ExceptionMapperTests.cs              Every CKR category → expected subclass.
    └── ObjectTemplateTests.cs               Builders, secure defaults, Dispose, attribute
                                             replacement, error paths.
```

---

## Task list

### Task 1: Pkcs11Exception base — additive changes

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/Pkcs11Exception.cs`
- Test: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11ExceptionTests.cs`

Purpose: Add the new ctor shape and `ReturnValue` property without breaking the 129 existing call sites. The class stays concrete (non-abstract) for now; we make it abstract in Task 10 after every call site is migrated.

- [ ] **Step 1: Write the failing test**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11ExceptionTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public class Pkcs11ExceptionTests
{
    [Fact]
    public void ReturnValue_ExposesCkr()
    {
        var ex = new Pkcs11Exception(CKR.CKR_PIN_INCORRECT, "C_Login", null);

        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        Assert.Equal("C_Login", ex.Method);
    }

    [Fact]
    public void NewCtor_DefaultMessage_MentionsMethodAndCkr()
    {
        var ex = new Pkcs11Exception(CKR.CKR_DEVICE_ERROR, "C_OpenSession", null);

        Assert.Contains("C_OpenSession", ex.Message);
        Assert.Contains("CKR_DEVICE_ERROR", ex.Message);
    }

    [Fact]
    public void NewCtor_ExplicitMessage_OverridesDefault()
    {
        var ex = new Pkcs11Exception(CKR.CKR_DEVICE_ERROR, "C_OpenSession", "boom");

        Assert.Equal("boom", ex.Message);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11ExceptionTests" -c Debug
```

Expected: build error — `Pkcs11Exception` has no ctor taking `(CKR, string, string?)` and no `ReturnValue` property.

- [ ] **Step 3: Rewrite `Pkcs11Exception.cs` with the additive changes**

Replace the entire file contents of `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/Pkcs11Exception.cs` with:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Base type for exceptions raised in response to a non-CKR_OK return value from a
/// PKCS#11 native call.
/// </summary>
/// <remarks>
/// Carries the PKCS#11 method name that failed and the underlying CKR. Typed subclasses
/// (<see cref="Pkcs11AuthenticationException"/>, <see cref="Pkcs11SessionException"/>,
/// etc.) categorize related CKR values so callers can catch by category. All native
/// call-sites should funnel through <see cref="ThrowIfError(CKR, string)"/> rather than
/// constructing instances directly.
/// </remarks>
public class Pkcs11Exception : Exception
{
    /// <summary>PKCS#11 return value that triggered this exception.</summary>
    public CKR ReturnValue { get; }

    /// <summary>Name of the PKCS#11 method whose return value triggered this exception.</summary>
    public string Method { get; }

    /// <summary>
    /// Initializes a new instance carrying the CKR and method name. Used by
    /// <see cref="ExceptionMapper"/> when dispatching <see cref="ThrowIfError(CKR, string)"/>.
    /// </summary>
    /// <param name="returnValue">The PKCS#11 return value.</param>
    /// <param name="method">Name of the failing PKCS#11 method.</param>
    /// <param name="message">Optional explanatory message. When null, a default message
    /// of the form <c>"PKCS#11 method &lt;method&gt; returned &lt;returnValue&gt;"</c> is used.</param>
    public Pkcs11Exception(CKR returnValue, string method, string? message)
        : base(message ?? $"PKCS#11 method {method} returned {returnValue}")
    {
        ReturnValue = returnValue;
        Method = method;
    }

    /// <summary>
    /// Legacy constructor. Kept for the duration of Plan 1 so the 129 existing
    /// <c>throw new Pkcs11Exception("C_X", rv)</c> call sites continue to compile while
    /// they are migrated to <see cref="ThrowIfError(CKR, string)"/>. Removed in Task 10.
    /// </summary>
    [Obsolete("Use Pkcs11Exception.ThrowIfError(rv, method) instead. Removed at end of Plan 1.", error: false)]
    public Pkcs11Exception(string method, CKR rv)
        : this(rv, method, message: null)
    {
    }

    /// <summary>
    /// Throws the appropriate typed <see cref="Pkcs11Exception"/> subclass when
    /// <paramref name="returnValue"/> is anything other than <see cref="CKR.CKR_OK"/>.
    /// Returns immediately on success.
    /// </summary>
    /// <param name="returnValue">The PKCS#11 return value to inspect.</param>
    /// <param name="method">Name of the PKCS#11 method that produced the value.</param>
    public static void ThrowIfError(CKR returnValue, string method)
    {
        if (returnValue == CKR.CKR_OK) return;
        throw ExceptionMapper.Map(returnValue, method);
    }
}
```

- [ ] **Step 4: Add a no-op stub for `ExceptionMapper` so the file compiles**

The `ThrowIfError` body references `ExceptionMapper.Map`. Create the placeholder file `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/ExceptionMapper.cs`:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Maps a non-CKR_OK return value to the typed <see cref="Pkcs11Exception"/> subclass.
/// Stub implementation — Task 3 fills in the category dispatch.
/// </summary>
internal static class ExceptionMapper
{
    internal static Pkcs11Exception Map(CKR returnValue, string method)
    {
        // Stub: returns the (non-typed) base exception until Task 3 lands the dispatch.
        return new Pkcs11Exception(returnValue, method, message: null);
    }
}
```

- [ ] **Step 5: Build and verify tests pass**

```bash
dotnet build src/KerckhoffsLabs.sln -c Debug
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11ExceptionTests" -c Debug
```

Expected: build succeeds (existing 129 call sites compile because the legacy ctor still exists, only marked `[Obsolete]` with `error: false`). The three new tests pass.

- [ ] **Step 6: Verify the full test suite still passes**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures. There will be `CS0618` warnings about legacy ctor use — those are intentional, they are tackled in Tasks 9 and 10.

- [ ] **Step 7: Completion checkpoint**

Report task complete. No file moves, no behavior change beyond adding the new ctor and `ReturnValue` property.

---

### Task 2: Typed exception subclasses

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/Pkcs11AuthenticationException.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/Pkcs11SessionException.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/Pkcs11TokenException.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/Pkcs11MechanismException.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/Pkcs11ObjectException.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/Pkcs11ArgumentException.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/Pkcs11UnclassifiedException.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11ExceptionTests.cs`

- [ ] **Step 1: Append type-hierarchy tests to `Pkcs11ExceptionTests.cs`**

Add the following at the end of the existing test class (before the closing brace):

```csharp
    [Fact]
    public void AuthenticationException_DerivesFromPkcs11Exception()
    {
        var ex = new Pkcs11AuthenticationException(CKR.CKR_PIN_INCORRECT, "C_Login", null);

        Assert.IsAssignableFrom<Pkcs11Exception>(ex);
        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
    }

    [Fact]
    public void SessionException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11SessionException(CKR.CKR_SESSION_HANDLE_INVALID, "C_GetSessionInfo", null));

    [Fact]
    public void TokenException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11TokenException(CKR.CKR_TOKEN_NOT_PRESENT, "C_GetTokenInfo", null));

    [Fact]
    public void MechanismException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11MechanismException(CKR.CKR_MECHANISM_INVALID, "C_SignInit", null));

    [Fact]
    public void ObjectException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11ObjectException(CKR.CKR_OBJECT_HANDLE_INVALID, "C_DestroyObject", null));

    [Fact]
    public void ArgumentException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11ArgumentException(CKR.CKR_ARGUMENTS_BAD, "C_GenerateKey", null));

    [Fact]
    public void UnclassifiedException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11UnclassifiedException(CKR.CKR_GENERAL_ERROR, "C_Finalize", null));
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11ExceptionTests" -c Debug
```

Expected: build errors — none of the seven typed-exception types are defined.

- [ ] **Step 3: Create the seven subclass files**

Each subclass is a thin sealed type that forwards to the base ctor. Identical shape; one per CKR category. Create `Pkcs11AuthenticationException.cs`:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Raised when a PKCS#11 call fails with a PIN- or user-related return value
/// (CKR_PIN_*, CKR_USER_*).
/// </summary>
public sealed class Pkcs11AuthenticationException : Pkcs11Exception
{
    /// <inheritdoc/>
    public Pkcs11AuthenticationException(CKR returnValue, string method, string? message)
        : base(returnValue, method, message)
    {
    }
}
```

Create `Pkcs11SessionException.cs`:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Raised when a PKCS#11 call fails with a session-related return value
/// (CKR_SESSION_*).
/// </summary>
public sealed class Pkcs11SessionException : Pkcs11Exception
{
    /// <inheritdoc/>
    public Pkcs11SessionException(CKR returnValue, string method, string? message)
        : base(returnValue, method, message)
    {
    }
}
```

Create `Pkcs11TokenException.cs`:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Raised when a PKCS#11 call fails with a token- or device-related return value
/// (CKR_TOKEN_*, CKR_DEVICE_*).
/// </summary>
public sealed class Pkcs11TokenException : Pkcs11Exception
{
    /// <inheritdoc/>
    public Pkcs11TokenException(CKR returnValue, string method, string? message)
        : base(returnValue, method, message)
    {
    }
}
```

Create `Pkcs11MechanismException.cs`:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Raised when a PKCS#11 call fails because of a mechanism or key-function constraint
/// (CKR_MECHANISM_*, CKR_KEY_FUNCTION_NOT_PERMITTED).
/// </summary>
public sealed class Pkcs11MechanismException : Pkcs11Exception
{
    /// <inheritdoc/>
    public Pkcs11MechanismException(CKR returnValue, string method, string? message)
        : base(returnValue, method, message)
    {
    }
}
```

Create `Pkcs11ObjectException.cs`:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Raised when a PKCS#11 call fails with an object- or attribute-related return value
/// (CKR_OBJECT_*, CKR_ATTRIBUTE_*).
/// </summary>
public sealed class Pkcs11ObjectException : Pkcs11Exception
{
    /// <inheritdoc/>
    public Pkcs11ObjectException(CKR returnValue, string method, string? message)
        : base(returnValue, method, message)
    {
    }
}
```

Create `Pkcs11ArgumentException.cs`:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Raised when a PKCS#11 call fails because of an invalid argument or buffer
/// (CKR_ARGUMENTS_BAD, CKR_DATA_INVALID, CKR_BUFFER_TOO_SMALL, and related values).
/// </summary>
public sealed class Pkcs11ArgumentException : Pkcs11Exception
{
    /// <inheritdoc/>
    public Pkcs11ArgumentException(CKR returnValue, string method, string? message)
        : base(returnValue, method, message)
    {
    }
}
```

Create `Pkcs11UnclassifiedException.cs`:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Raised when a PKCS#11 call fails with a return value that has no narrower
/// categorization. Catches everything <see cref="ExceptionMapper"/> does not route to a
/// more specific subclass.
/// </summary>
public sealed class Pkcs11UnclassifiedException : Pkcs11Exception
{
    /// <inheritdoc/>
    public Pkcs11UnclassifiedException(CKR returnValue, string method, string? message)
        : base(returnValue, method, message)
    {
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11ExceptionTests" -c Debug
```

Expected: 10 tests pass.

- [ ] **Step 5: Verify the full test suite still passes**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 6: Completion checkpoint**

---

### Task 3: ExceptionMapper dispatch

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/ExceptionMapper.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ExceptionMapperTests.cs`

- [ ] **Step 1: Write the failing tests**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ExceptionMapperTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public class ExceptionMapperTests
{
    public static IEnumerable<object[]> AuthenticationCases() => new[]
    {
        new object[] { CKR.CKR_PIN_INCORRECT },
        new object[] { CKR.CKR_PIN_INVALID },
        new object[] { CKR.CKR_PIN_LEN_RANGE },
        new object[] { CKR.CKR_PIN_EXPIRED },
        new object[] { CKR.CKR_PIN_LOCKED },
        new object[] { CKR.CKR_USER_ALREADY_LOGGED_IN },
        new object[] { CKR.CKR_USER_NOT_LOGGED_IN },
        new object[] { CKR.CKR_USER_PIN_NOT_INITIALIZED },
        new object[] { CKR.CKR_USER_TYPE_INVALID },
        new object[] { CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN },
        new object[] { CKR.CKR_USER_TOO_MANY_TYPES },
    };

    [Theory]
    [MemberData(nameof(AuthenticationCases))]
    public void Map_PinAndUserCkr_ReturnsAuthenticationException(CKR ckr)
    {
        var ex = ExceptionMapper.Map(ckr, "C_Login");

        Assert.IsType<Pkcs11AuthenticationException>(ex);
        Assert.Equal(ckr, ex.ReturnValue);
        Assert.Equal("C_Login", ex.Method);
    }

    public static IEnumerable<object[]> SessionCases() => new[]
    {
        new object[] { CKR.CKR_SESSION_CLOSED },
        new object[] { CKR.CKR_SESSION_COUNT },
        new object[] { CKR.CKR_SESSION_HANDLE_INVALID },
        new object[] { CKR.CKR_SESSION_PARALLEL_NOT_SUPPORTED },
        new object[] { CKR.CKR_SESSION_READ_ONLY },
        new object[] { CKR.CKR_SESSION_EXISTS },
        new object[] { CKR.CKR_SESSION_READ_ONLY_EXISTS },
        new object[] { CKR.CKR_SESSION_READ_WRITE_SO_EXISTS },
    };

    [Theory]
    [MemberData(nameof(SessionCases))]
    public void Map_SessionCkr_ReturnsSessionException(CKR ckr)
        => Assert.IsType<Pkcs11SessionException>(ExceptionMapper.Map(ckr, "C_OpenSession"));

    public static IEnumerable<object[]> TokenCases() => new[]
    {
        new object[] { CKR.CKR_TOKEN_NOT_PRESENT },
        new object[] { CKR.CKR_TOKEN_NOT_RECOGNIZED },
        new object[] { CKR.CKR_TOKEN_WRITE_PROTECTED },
        new object[] { CKR.CKR_TOKEN_RESOURCE_EXCEEDED },
        new object[] { CKR.CKR_DEVICE_ERROR },
        new object[] { CKR.CKR_DEVICE_MEMORY },
        new object[] { CKR.CKR_DEVICE_REMOVED },
    };

    [Theory]
    [MemberData(nameof(TokenCases))]
    public void Map_TokenAndDeviceCkr_ReturnsTokenException(CKR ckr)
        => Assert.IsType<Pkcs11TokenException>(ExceptionMapper.Map(ckr, "C_GetTokenInfo"));

    public static IEnumerable<object[]> MechanismCases() => new[]
    {
        new object[] { CKR.CKR_MECHANISM_INVALID },
        new object[] { CKR.CKR_MECHANISM_PARAM_INVALID },
        new object[] { CKR.CKR_KEY_FUNCTION_NOT_PERMITTED },
    };

    [Theory]
    [MemberData(nameof(MechanismCases))]
    public void Map_MechanismCkr_ReturnsMechanismException(CKR ckr)
        => Assert.IsType<Pkcs11MechanismException>(ExceptionMapper.Map(ckr, "C_SignInit"));

    public static IEnumerable<object[]> ObjectCases() => new[]
    {
        new object[] { CKR.CKR_OBJECT_HANDLE_INVALID },
        new object[] { CKR.CKR_ATTRIBUTE_READ_ONLY },
        new object[] { CKR.CKR_ATTRIBUTE_SENSITIVE },
        new object[] { CKR.CKR_ATTRIBUTE_TYPE_INVALID },
        new object[] { CKR.CKR_ATTRIBUTE_VALUE_INVALID },
    };

    [Theory]
    [MemberData(nameof(ObjectCases))]
    public void Map_ObjectAndAttributeCkr_ReturnsObjectException(CKR ckr)
        => Assert.IsType<Pkcs11ObjectException>(ExceptionMapper.Map(ckr, "C_DestroyObject"));

    public static IEnumerable<object[]> ArgumentCases() => new[]
    {
        new object[] { CKR.CKR_ARGUMENTS_BAD },
        new object[] { CKR.CKR_DATA_INVALID },
        new object[] { CKR.CKR_DATA_LEN_RANGE },
        new object[] { CKR.CKR_BUFFER_TOO_SMALL },
    };

    [Theory]
    [MemberData(nameof(ArgumentCases))]
    public void Map_ArgumentCkr_ReturnsArgumentException(CKR ckr)
        => Assert.IsType<Pkcs11ArgumentException>(ExceptionMapper.Map(ckr, "C_GenerateKey"));

    [Theory]
    [InlineData(CKR.CKR_GENERAL_ERROR)]
    [InlineData(CKR.CKR_FUNCTION_FAILED)]
    [InlineData(CKR.CKR_HOST_MEMORY)]
    [InlineData(CKR.CKR_CRYPTOKI_NOT_INITIALIZED)]
    public void Map_UncategorizedCkr_ReturnsUnclassifiedException(CKR ckr)
        => Assert.IsType<Pkcs11UnclassifiedException>(ExceptionMapper.Map(ckr, "C_Finalize"));

    [Fact]
    public void Map_PreservesMethodAndCkr()
    {
        var ex = ExceptionMapper.Map(CKR.CKR_PIN_INCORRECT, "C_Login");

        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        Assert.Equal("C_Login", ex.Method);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ExceptionMapperTests" -c Debug
```

Expected: most or all tests fail. The current `ExceptionMapper.Map` stub returns a base `Pkcs11Exception` regardless of input, so the `Assert.IsType<Pkcs11AuthenticationException>` assertions fail.

- [ ] **Step 3: Implement the dispatch**

Replace the contents of `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/ExceptionMapper.cs` with:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Routes a non-CKR_OK return value to the typed <see cref="Pkcs11Exception"/> subclass
/// that categorizes it. Called from <see cref="Pkcs11Exception.ThrowIfError(CKR, string)"/>.
/// </summary>
/// <remarks>
/// Categories follow PKCS#11 v3.1 §5.3 grouping. A value with no narrower category maps
/// to <see cref="Pkcs11UnclassifiedException"/>.
/// </remarks>
internal static class ExceptionMapper
{
    internal static Pkcs11Exception Map(CKR returnValue, string method)
        => returnValue switch
        {
            // CKR_PIN_* and CKR_USER_* → authentication
            CKR.CKR_PIN_INCORRECT
              or CKR.CKR_PIN_INVALID
              or CKR.CKR_PIN_LEN_RANGE
              or CKR.CKR_PIN_EXPIRED
              or CKR.CKR_PIN_LOCKED
              or CKR.CKR_USER_ALREADY_LOGGED_IN
              or CKR.CKR_USER_NOT_LOGGED_IN
              or CKR.CKR_USER_PIN_NOT_INITIALIZED
              or CKR.CKR_USER_TYPE_INVALID
              or CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN
              or CKR.CKR_USER_TOO_MANY_TYPES
                => new Pkcs11AuthenticationException(returnValue, method, message: null),

            // CKR_SESSION_* → session
            CKR.CKR_SESSION_CLOSED
              or CKR.CKR_SESSION_COUNT
              or CKR.CKR_SESSION_HANDLE_INVALID
              or CKR.CKR_SESSION_PARALLEL_NOT_SUPPORTED
              or CKR.CKR_SESSION_READ_ONLY
              or CKR.CKR_SESSION_EXISTS
              or CKR.CKR_SESSION_READ_ONLY_EXISTS
              or CKR.CKR_SESSION_READ_WRITE_SO_EXISTS
                => new Pkcs11SessionException(returnValue, method, message: null),

            // CKR_TOKEN_*, CKR_DEVICE_* → token/device
            CKR.CKR_TOKEN_NOT_PRESENT
              or CKR.CKR_TOKEN_NOT_RECOGNIZED
              or CKR.CKR_TOKEN_WRITE_PROTECTED
              or CKR.CKR_TOKEN_RESOURCE_EXCEEDED
              or CKR.CKR_DEVICE_ERROR
              or CKR.CKR_DEVICE_MEMORY
              or CKR.CKR_DEVICE_REMOVED
                => new Pkcs11TokenException(returnValue, method, message: null),

            // CKR_MECHANISM_*, CKR_KEY_FUNCTION_NOT_PERMITTED → mechanism
            CKR.CKR_MECHANISM_INVALID
              or CKR.CKR_MECHANISM_PARAM_INVALID
              or CKR.CKR_KEY_FUNCTION_NOT_PERMITTED
                => new Pkcs11MechanismException(returnValue, method, message: null),

            // CKR_OBJECT_*, CKR_ATTRIBUTE_* → object/attribute
            CKR.CKR_OBJECT_HANDLE_INVALID
              or CKR.CKR_ATTRIBUTE_READ_ONLY
              or CKR.CKR_ATTRIBUTE_SENSITIVE
              or CKR.CKR_ATTRIBUTE_TYPE_INVALID
              or CKR.CKR_ATTRIBUTE_VALUE_INVALID
                => new Pkcs11ObjectException(returnValue, method, message: null),

            // CKR_ARGUMENTS_BAD, CKR_DATA_*, CKR_BUFFER_TOO_SMALL → argument
            CKR.CKR_ARGUMENTS_BAD
              or CKR.CKR_DATA_INVALID
              or CKR.CKR_DATA_LEN_RANGE
              or CKR.CKR_BUFFER_TOO_SMALL
                => new Pkcs11ArgumentException(returnValue, method, message: null),

            _ => new Pkcs11UnclassifiedException(returnValue, method, message: null),
        };
}
```

- [ ] **Step 4: Run mapper tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ExceptionMapperTests" -c Debug
```

Expected: all mapper tests pass.

- [ ] **Step 5: Verify the full test suite still passes**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures. Existing call sites still construct base `Pkcs11Exception` via the legacy ctor, which is correct — they will be migrated in Tasks 4-9.

- [ ] **Step 6: Completion checkpoint**

---

### Task 4: Add a ThrowIfError test that validates the end-to-end dispatch

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11ExceptionTests.cs`

- [ ] **Step 1: Append `ThrowIfError` tests to `Pkcs11ExceptionTests.cs`**

Add the following tests at the end of the existing test class (before the closing brace):

```csharp
    [Fact]
    public void ThrowIfError_CkrOk_DoesNotThrow()
    {
        // Should return without throwing.
        Pkcs11Exception.ThrowIfError(CKR.CKR_OK, "C_Initialize");
    }

    [Fact]
    public void ThrowIfError_AuthenticationCkr_ThrowsTypedSubclass()
    {
        var ex = Assert.Throws<Pkcs11AuthenticationException>(
            () => Pkcs11Exception.ThrowIfError(CKR.CKR_PIN_INCORRECT, "C_Login"));

        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        Assert.Equal("C_Login", ex.Method);
    }

    [Fact]
    public void ThrowIfError_UncategorizedCkr_ThrowsUnclassified()
    {
        var ex = Assert.Throws<Pkcs11UnclassifiedException>(
            () => Pkcs11Exception.ThrowIfError(CKR.CKR_GENERAL_ERROR, "C_Finalize"));

        Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
    }

    [Fact]
    public void ThrowIfError_TypedExceptionIsAlsoBasePkcs11Exception()
    {
        // Existing catch (Pkcs11Exception) clauses across the codebase continue to work.
        var ex = Assert.Throws<Pkcs11AuthenticationException>(
            () => Pkcs11Exception.ThrowIfError(CKR.CKR_PIN_INCORRECT, "C_Login"));

        Assert.IsAssignableFrom<Pkcs11Exception>(ex);
    }
```

- [ ] **Step 2: Run tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11ExceptionTests" -c Debug
```

Expected: all `Pkcs11ExceptionTests` (14 total) pass.

- [ ] **Step 3: Completion checkpoint**

---

### Task 5: Migrate throw sites — HighLevel/Pkcs11Library.cs and Session.cs

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Library.cs` (6 sites)
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs` (10 sites)
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Slot.cs` (9 sites)

Purpose: Mechanical sweep — replace every

```csharp
if (rv != CKR.CKR_OK)
    throw new Pkcs11Exception("C_X", rv);
```

with

```csharp
Pkcs11Exception.ThrowIfError(rv, "C_X");
```

This task batches the three smaller files (Pkcs11Library, Session, Slot). Tasks 6-9 batch the larger files.

- [ ] **Step 1: Migrate Pkcs11Library.cs**

For each of the 6 throw sites in `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Library.cs`, locate the `if (rv != CKR.CKR_OK)` + `throw new Pkcs11Exception(...)` pair and replace with the single `Pkcs11Exception.ThrowIfError(rv, "C_X");` call. The `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;` import is already present.

Use `grep -n "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Library.cs` to enumerate the sites.

Some sites may have additional logic between the `if` and the `throw`. In those cases, preserve that logic by inverting the condition:

```csharp
// Before
CKR rv = _p11.C_X(...);
if (rv != CKR.CKR_OK)
{
    SomeCleanup();
    throw new Pkcs11Exception("C_X", rv);
}
// After
CKR rv = _p11.C_X(...);
if (rv != CKR.CKR_OK)
{
    SomeCleanup();
    Pkcs11Exception.ThrowIfError(rv, "C_X");
}
```

(The `ThrowIfError` call is a no-op for `CKR_OK`, but the `if` short-circuits the cleanup for the success case.)

For the simple pattern (no extra logic in the `if`), collapse:

```csharp
// Before
CKR rv = _p11.C_X(...);
if (rv != CKR.CKR_OK)
    throw new Pkcs11Exception("C_X", rv);
// After
CKR rv = _p11.C_X(...);
Pkcs11Exception.ThrowIfError(rv, "C_X");
```

- [ ] **Step 2: Migrate Session.cs (10 sites)**

Same transformation on `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`. Verify each site with `grep -n "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`.

- [ ] **Step 3: Migrate Slot.cs (9 sites)**

Same transformation on `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Slot.cs`.

- [ ] **Step 4: Build and verify the full test suite passes**

```bash
dotnet build src/KerckhoffsLabs.sln -c Debug
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: build succeeds with no `CS0618` warnings from these three files. All tests pass — behavior is identical, only the exception subtype changes (the base class `Pkcs11Exception` is still thrown, but it is now one of the typed subclasses for categorized CKRs).

- [ ] **Step 5: Confirm no remaining throw sites in these files**

```bash
grep -n "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Library.cs \
    src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs \
    src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Slot.cs
```

Expected: no output. All sites migrated.

- [ ] **Step 6: Completion checkpoint**

---

### Task 6: Migrate throw sites — Session.Sign.cs (22 sites)

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs`

- [ ] **Step 1: Migrate every site**

Same mechanical transformation as Task 5, applied to all 22 sites in `Session.Sign.cs`. Locate sites with:

```bash
grep -n "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs
```

For each `if (rv != CKR.CKR_OK) throw new Pkcs11Exception("C_X", rv);` pair, replace with `Pkcs11Exception.ThrowIfError(rv, "C_X");`. Preserve any cleanup logic inside `if` blocks per Task 5 Step 1's guidance.

- [ ] **Step 2: Build and verify the full test suite passes**

```bash
dotnet build src/KerckhoffsLabs.sln -c Debug
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 3: Confirm no remaining throw sites in this file**

```bash
grep -n "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs
```

Expected: no output.

- [ ] **Step 4: Completion checkpoint**

---

### Task 7: Migrate throw sites — Session.Encrypt.cs, Session.Decrypt.cs, Session.Verify.cs

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs` (8 sites)
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs` (8 sites)
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs` (15 sites)

- [ ] **Step 1: Migrate Session.Encrypt.cs**

```bash
grep -n "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs
```

Apply the transformation from Task 5 Step 1 to all 8 sites.

- [ ] **Step 2: Migrate Session.Decrypt.cs**

```bash
grep -n "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs
```

Apply the transformation to all 8 sites.

- [ ] **Step 3: Migrate Session.Verify.cs**

```bash
grep -n "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs
```

Apply the transformation to all 15 sites.

- [ ] **Step 4: Build and verify the full test suite passes**

```bash
dotnet build src/KerckhoffsLabs.sln -c Debug
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 5: Confirm no remaining throw sites in these three files**

```bash
grep -n "new Pkcs11Exception" \
  src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs \
  src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs \
  src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs
```

Expected: no output.

- [ ] **Step 6: Completion checkpoint**

---

### Task 8: Migrate throw sites — Session.Digest.cs, Session.Objects.cs, Session.Keys.cs

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs` (27 sites)
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Objects.cs` (14 sites)
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs` (5 sites)

- [ ] **Step 1: Migrate Session.Digest.cs**

```bash
grep -n "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs
```

Apply the transformation to all 27 sites.

- [ ] **Step 2: Migrate Session.Objects.cs**

```bash
grep -n "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Objects.cs
```

Apply the transformation to all 14 sites.

- [ ] **Step 3: Migrate Session.Keys.cs**

```bash
grep -n "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs
```

Apply the transformation to all 5 sites.

- [ ] **Step 4: Build and verify the full test suite passes**

```bash
dotnet build src/KerckhoffsLabs.sln -c Debug
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 5: Confirm no remaining throw sites in these three files**

```bash
grep -n "new Pkcs11Exception" \
  src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs \
  src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Objects.cs \
  src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs
```

Expected: no output.

- [ ] **Step 6: Completion checkpoint**

---

### Task 9: Migrate throw sites — Session.Derive.cs, Session.Random.cs, Native/Delegates.cs

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Derive.cs` (1 site)
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Random.cs` (2 sites)
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs` (2 sites)

Final mop-up of the last 5 throw sites — all small files.

- [ ] **Step 1: Migrate Session.Derive.cs**

Apply the transformation to the 1 site.

- [ ] **Step 2: Migrate Session.Random.cs**

```bash
grep -n "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Random.cs
```

Apply the transformation to all 2 sites.

- [ ] **Step 3: Migrate Native/Delegates.cs**

```bash
grep -n "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
```

Apply the transformation to all 2 sites. Note: these sites are inside the `C_GetFunctionList` resolver fallback — confirm the `using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;` import is present (it is, but verify).

- [ ] **Step 4: Confirm zero throw sites remain anywhere in the production assembly**

```bash
grep -rn "new Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
```

Expected: no output. Every site has been routed through `ThrowIfError`.

- [ ] **Step 5: Build and verify the full test suite passes**

```bash
dotnet build src/KerckhoffsLabs.sln -c Debug
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures, **and** no `CS0618` warnings (the legacy ctor is no longer called).

- [ ] **Step 6: Completion checkpoint**

---

### Task 10: Make `Pkcs11Exception` abstract; remove legacy ctor

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/Pkcs11Exception.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11ExceptionTests.cs`

After Task 9, the legacy two-arg ctor has no callers. We can now make the base abstract per the spec.

- [ ] **Step 1: Remove the legacy ctor and add the abstract modifier**

Edit `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/Pkcs11Exception.cs`. Change `public class Pkcs11Exception : Exception` to `public abstract class Pkcs11Exception : Exception`, and delete the entire `[Obsolete("Use Pkcs11Exception.ThrowIfError(...)")]` constructor block. The file should end with these three members:

- `public CKR ReturnValue { get; }`
- `public string Method { get; }`
- `public Pkcs11Exception(CKR returnValue, string method, string? message)` ctor — change `public` to `protected` since the class is now abstract.
- `public static void ThrowIfError(CKR returnValue, string method)`

The full replacement file:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Abstract base type for exceptions raised in response to a non-CKR_OK return value from
/// a PKCS#11 native call.
/// </summary>
/// <remarks>
/// Carries the PKCS#11 method name that failed and the underlying CKR. Concrete subclasses
/// (<see cref="Pkcs11AuthenticationException"/>, <see cref="Pkcs11SessionException"/>,
/// etc.) categorize related CKR values so callers can catch by category. All native
/// call-sites should funnel through <see cref="ThrowIfError(CKR, string)"/> rather than
/// constructing instances directly.
/// </remarks>
public abstract class Pkcs11Exception : Exception
{
    /// <summary>PKCS#11 return value that triggered this exception.</summary>
    public CKR ReturnValue { get; }

    /// <summary>Name of the PKCS#11 method whose return value triggered this exception.</summary>
    public string Method { get; }

    /// <summary>
    /// Initializes a new instance carrying the CKR and method name. Used by
    /// <see cref="ExceptionMapper"/> when dispatching <see cref="ThrowIfError(CKR, string)"/>.
    /// </summary>
    /// <param name="returnValue">The PKCS#11 return value.</param>
    /// <param name="method">Name of the failing PKCS#11 method.</param>
    /// <param name="message">Optional explanatory message. When null, a default message
    /// of the form <c>"PKCS#11 method &lt;method&gt; returned &lt;returnValue&gt;"</c> is used.</param>
    protected Pkcs11Exception(CKR returnValue, string method, string? message)
        : base(message ?? $"PKCS#11 method {method} returned {returnValue}")
    {
        ReturnValue = returnValue;
        Method = method;
    }

    /// <summary>
    /// Throws the appropriate typed <see cref="Pkcs11Exception"/> subclass when
    /// <paramref name="returnValue"/> is anything other than <see cref="CKR.CKR_OK"/>.
    /// Returns immediately on success.
    /// </summary>
    /// <param name="returnValue">The PKCS#11 return value to inspect.</param>
    /// <param name="method">Name of the PKCS#11 method that produced the value.</param>
    public static void ThrowIfError(CKR returnValue, string method)
    {
        if (returnValue == CKR.CKR_OK) return;
        throw ExceptionMapper.Map(returnValue, method);
    }
}
```

- [ ] **Step 2: Update Task 1's tests that constructed `Pkcs11Exception` directly**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11ExceptionTests.cs`. The first three tests construct `new Pkcs11Exception(...)` directly, which no longer compiles since the class is abstract. Replace those constructions with the equivalent subclass — `Pkcs11AuthenticationException`, `Pkcs11TokenException`, etc. — whichever the CKR maps to.

The full replacement file:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public class Pkcs11ExceptionTests
{
    [Fact]
    public void ReturnValue_ExposesCkr()
    {
        var ex = new Pkcs11AuthenticationException(CKR.CKR_PIN_INCORRECT, "C_Login", null);

        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        Assert.Equal("C_Login", ex.Method);
    }

    [Fact]
    public void NewCtor_DefaultMessage_MentionsMethodAndCkr()
    {
        var ex = new Pkcs11TokenException(CKR.CKR_DEVICE_ERROR, "C_OpenSession", null);

        Assert.Contains("C_OpenSession", ex.Message);
        Assert.Contains("CKR_DEVICE_ERROR", ex.Message);
    }

    [Fact]
    public void NewCtor_ExplicitMessage_OverridesDefault()
    {
        var ex = new Pkcs11TokenException(CKR.CKR_DEVICE_ERROR, "C_OpenSession", "boom");

        Assert.Equal("boom", ex.Message);
    }

    [Fact]
    public void AuthenticationException_DerivesFromPkcs11Exception()
    {
        var ex = new Pkcs11AuthenticationException(CKR.CKR_PIN_INCORRECT, "C_Login", null);

        Assert.IsAssignableFrom<Pkcs11Exception>(ex);
        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
    }

    [Fact]
    public void SessionException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11SessionException(CKR.CKR_SESSION_HANDLE_INVALID, "C_GetSessionInfo", null));

    [Fact]
    public void TokenException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11TokenException(CKR.CKR_TOKEN_NOT_PRESENT, "C_GetTokenInfo", null));

    [Fact]
    public void MechanismException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11MechanismException(CKR.CKR_MECHANISM_INVALID, "C_SignInit", null));

    [Fact]
    public void ObjectException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11ObjectException(CKR.CKR_OBJECT_HANDLE_INVALID, "C_DestroyObject", null));

    [Fact]
    public void ArgumentException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11ArgumentException(CKR.CKR_ARGUMENTS_BAD, "C_GenerateKey", null));

    [Fact]
    public void UnclassifiedException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11UnclassifiedException(CKR.CKR_GENERAL_ERROR, "C_Finalize", null));

    [Fact]
    public void ThrowIfError_CkrOk_DoesNotThrow()
    {
        Pkcs11Exception.ThrowIfError(CKR.CKR_OK, "C_Initialize");
    }

    [Fact]
    public void ThrowIfError_AuthenticationCkr_ThrowsTypedSubclass()
    {
        var ex = Assert.Throws<Pkcs11AuthenticationException>(
            () => Pkcs11Exception.ThrowIfError(CKR.CKR_PIN_INCORRECT, "C_Login"));

        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        Assert.Equal("C_Login", ex.Method);
    }

    [Fact]
    public void ThrowIfError_UncategorizedCkr_ThrowsUnclassified()
    {
        var ex = Assert.Throws<Pkcs11UnclassifiedException>(
            () => Pkcs11Exception.ThrowIfError(CKR.CKR_GENERAL_ERROR, "C_Finalize"));

        Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
    }

    [Fact]
    public void ThrowIfError_TypedExceptionIsAlsoBasePkcs11Exception()
    {
        var ex = Assert.Throws<Pkcs11AuthenticationException>(
            () => Pkcs11Exception.ThrowIfError(CKR.CKR_PIN_INCORRECT, "C_Login"));

        Assert.IsAssignableFrom<Pkcs11Exception>(ex);
    }
}
```

- [ ] **Step 3: Build and verify the full test suite passes**

```bash
dotnet build src/KerckhoffsLabs.sln -c Debug
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures, 0 warnings related to `Pkcs11Exception`.

- [ ] **Step 4: Completion checkpoint**

Phase A complete: typed exception hierarchy + centralized `ThrowIfError` is in place. Every native call site routes through the mapper; every catch site that previously caught `Pkcs11Exception` continues to catch the typed subclass (covariance via base class).

---

### Task 11: ObjectTemplate root and builder base

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ObjectTemplate.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ObjectTemplateBuilderBase.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ObjectTemplateTests.cs`

Introduces the value type and the generic CRTP builder base. Specific per-class builders (Tasks 12-17) inherit from this base.

- [ ] **Step 1: Write the failing tests for the root type and the base builder**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ObjectTemplateTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public class ObjectTemplateTests
{
    [Fact]
    public void Empty_BuildsEmptyTemplate()
    {
        using var template = ObjectTemplate.Empty().Build();

        Assert.Equal(0, template.Count);
    }

    [Fact]
    public void GenericBuilder_AddsAttribute()
    {
        using var template = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_LABEL, "k")
            .Build();

        Assert.Equal(1, template.Count);
    }

    [Fact]
    public void GenericBuilder_SetAttributeTwice_ReplacesValue()
    {
        // The fluent API treats repeated attributes as "last write wins" per PKCS#11
        // v3.1 §5.5.6 — duplicate CKA in a template is not an error; the latest value
        // overrides earlier ones. The builder collapses them to a single ObjectAttribute.
        using var template = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_LABEL, "first")
            .Attribute(CKA.CKA_LABEL, "second")
            .Build();

        Assert.Equal(1, template.Count);
    }

    [Fact]
    public void Build_TransfersOwnership_FurtherBuildThrows()
    {
        var builder = ObjectTemplate.Empty().Attribute(CKA.CKA_LABEL, "k");

        using var first = builder.Build();
        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Dispose_DisposesOwnedAttributes()
    {
        var template = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_LABEL, "k")
            .Build();

        template.Dispose();
        // Disposing twice must be a no-op.
        template.Dispose();
    }

    [Fact]
    public void Builder_NeverBuilt_DoesNotLeak()
    {
        // Builder that is never built should still release the attributes it accumulated
        // when garbage-collected; the test exercises the Dispose path that the builder
        // exposes so an explicit cleanup is possible.
        var builder = (IDisposable)ObjectTemplate.Empty().Attribute(CKA.CKA_LABEL, "k");
        builder.Dispose();
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ObjectTemplateTests" -c Debug
```

Expected: build errors — `ObjectTemplate`, `Empty()`, and the fluent methods do not exist.

- [ ] **Step 3: Create `ObjectTemplate.cs`**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ObjectTemplate.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// An immutable, owning collection of <see cref="ObjectAttribute"/> values describing a
/// PKCS#11 object — used as the input template for create / generate / find operations.
/// </summary>
/// <remarks>
/// Build instances through the fluent factories on this class
/// (<see cref="ForSecretKey(CKK)"/>, <see cref="ForPrivateKey(CKK)"/>, etc.). Disposing
/// the template disposes every <see cref="ObjectAttribute"/> it owns and releases the
/// associated unmanaged buffers.
/// </remarks>
public sealed class ObjectTemplate : IDisposable
{
    private readonly List<ObjectAttribute> _attributes;
    private bool _disposed;

    internal ObjectTemplate(List<ObjectAttribute> attributes)
    {
        _attributes = attributes;
    }

    /// <summary>Number of attributes in the template.</summary>
    public int Count => _attributes.Count;

    /// <summary>Internal accessor used by call sites that marshal the template to PKCS#11.</summary>
    internal IReadOnlyList<ObjectAttribute> Attributes => _attributes;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        foreach (var attr in _attributes) attr.Dispose();
        _attributes.Clear();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer safety net — releases unmanaged buffers if Dispose was not called.</summary>
    ~ObjectTemplate() => Dispose();

    /// <summary>Begins a fluent template for a secret (symmetric) key of the given type.</summary>
    public static SecretKeyTemplateBuilder ForSecretKey(CKK keyType) => new(keyType);

    /// <summary>Begins a fluent template for an asymmetric private key of the given type.</summary>
    public static PrivateKeyTemplateBuilder ForPrivateKey(CKK keyType) => new(keyType);

    /// <summary>Begins a fluent template for an asymmetric public key of the given type.</summary>
    public static PublicKeyTemplateBuilder ForPublicKey(CKK keyType) => new(keyType);

    /// <summary>Begins a fluent template for a certificate of the given type.</summary>
    public static CertificateTemplateBuilder ForCertificate(CKC certType) => new(certType);

    /// <summary>Begins a fluent template for a data object.</summary>
    public static DataTemplateBuilder ForData() => new();

    /// <summary>Begins a fluent template with no preset attributes. Escape hatch.</summary>
    public static GenericTemplateBuilder Empty() => new();
}
```

- [ ] **Step 4: Create `ObjectTemplateBuilderBase.cs`**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ObjectTemplateBuilderBase.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Shared base for fluent template builders. Uses the curiously-recurring template pattern
/// so each subclass returns its own type from fluent calls and method chaining keeps the
/// caller in the specific builder's API surface.
/// </summary>
/// <typeparam name="TSelf">The concrete builder type — passed for fluent return values.</typeparam>
public abstract class ObjectTemplateBuilderBase<TSelf> : IDisposable
    where TSelf : ObjectTemplateBuilderBase<TSelf>
{
    // Dictionary keyed by CKA so "last write wins" replaces an earlier attribute rather
    // than appending — matches PKCS#11 v3.1 §5.5.6 semantics. We own the ObjectAttribute
    // values and must dispose the displaced one on replacement.
    private readonly Dictionary<CKA, ObjectAttribute> _attributes = new();
    private bool _built;
    private bool _disposed;

    /// <summary>Sets an attribute. If the same CKA is already present, the previous value is disposed and replaced.</summary>
    protected void Set(ObjectAttribute attr)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_built) throw new InvalidOperationException("Builder has already produced an ObjectTemplate. Start a new builder.");

        var key = (CKA)attr.Type;
        if (_attributes.TryGetValue(key, out var existing))
            existing.Dispose();
        _attributes[key] = attr;
    }

    /// <summary>Sets an arbitrary attribute as a ulong value. Escape hatch for attributes the typed API does not cover.</summary>
    public TSelf Attribute(CKA attribute, ulong value)
    {
        Set(new ObjectAttribute(attribute, value));
        return (TSelf)this;
    }

    /// <summary>Sets an arbitrary attribute as a bool value.</summary>
    public TSelf Attribute(CKA attribute, bool value)
    {
        Set(new ObjectAttribute(attribute, value));
        return (TSelf)this;
    }

    /// <summary>Sets an arbitrary attribute as a string value.</summary>
    public TSelf Attribute(CKA attribute, string value)
    {
        Set(new ObjectAttribute(attribute, value));
        return (TSelf)this;
    }

    /// <summary>Sets an arbitrary attribute as a byte buffer.</summary>
    public TSelf Attribute(CKA attribute, ReadOnlySpan<byte> value)
    {
        Set(new ObjectAttribute(attribute, value));
        return (TSelf)this;
    }

    /// <summary>Sets CKA_LABEL.</summary>
    public TSelf Label(string label) => Attribute(CKA.CKA_LABEL, label);

    /// <summary>Sets CKA_ID.</summary>
    public TSelf Id(ReadOnlySpan<byte> id) => Attribute(CKA.CKA_ID, id);

    /// <summary>Sets CKA_TOKEN (true = token object, false = session object).</summary>
    public TSelf OnToken(bool value = true) => Attribute(CKA.CKA_TOKEN, value);

    /// <summary>Finalises the builder and returns an owning <see cref="ObjectTemplate"/>.
    /// The builder cannot be reused after this call — start a new builder for a new template.</summary>
    public ObjectTemplate Build()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_built) throw new InvalidOperationException("Builder has already produced an ObjectTemplate. Start a new builder.");

        var list = new List<ObjectAttribute>(_attributes.Values);
        _attributes.Clear(); // ownership transferred to the ObjectTemplate
        _built = true;
        return new ObjectTemplate(list);
    }

    /// <summary>Disposes any attributes the builder still owns. Safe to call before <see cref="Build"/>.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        foreach (var attr in _attributes.Values) attr.Dispose();
        _attributes.Clear();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer safety net.</summary>
    ~ObjectTemplateBuilderBase() => Dispose();
}
```

- [ ] **Step 5: Create a placeholder `GenericTemplateBuilder.cs`**

The tests reference `ObjectTemplate.Empty()` which returns `GenericTemplateBuilder`. Create a minimal placeholder so the test file compiles — Task 17 fills it in fully.

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/GenericTemplateBuilder.cs`:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Fluent builder for an empty <see cref="ObjectTemplate"/> with no preset attributes.
/// Use this when constructing a template for an object class not covered by the typed
/// builders (vendor-defined CKO values).
/// </summary>
public sealed class GenericTemplateBuilder : ObjectTemplateBuilderBase<GenericTemplateBuilder>
{
    internal GenericTemplateBuilder() { }
}
```

- [ ] **Step 6: Add placeholder stubs for the other five builder types so `ObjectTemplate.cs` compiles**

`ObjectTemplate.cs` references five additional builder types. Tasks 12-16 implement them properly, but `ObjectTemplate.cs` will not compile without at least stubs. Create the following five files, each with a minimal builder that does nothing beyond inheriting the base.

`src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/SecretKeyTemplateBuilder.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>Fluent builder for secret-key templates. Task 12 fills in the typed surface.</summary>
public sealed class SecretKeyTemplateBuilder : ObjectTemplateBuilderBase<SecretKeyTemplateBuilder>
{
    internal SecretKeyTemplateBuilder(CKK keyType)
    {
        // Task 12 populates secure defaults (CKA_CLASS, CKA_KEY_TYPE, CKA_SENSITIVE,
        // CKA_EXTRACTABLE) and the key-usage / value-length fluent methods.
        _ = keyType;
    }
}
```

`src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/PrivateKeyTemplateBuilder.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>Fluent builder for private-key templates. Task 13 fills in the typed surface.</summary>
public sealed class PrivateKeyTemplateBuilder : ObjectTemplateBuilderBase<PrivateKeyTemplateBuilder>
{
    internal PrivateKeyTemplateBuilder(CKK keyType)
    {
        _ = keyType;
    }
}
```

`src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/PublicKeyTemplateBuilder.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>Fluent builder for public-key templates. Task 14 fills in the typed surface.</summary>
public sealed class PublicKeyTemplateBuilder : ObjectTemplateBuilderBase<PublicKeyTemplateBuilder>
{
    internal PublicKeyTemplateBuilder(CKK keyType)
    {
        _ = keyType;
    }
}
```

`src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/CertificateTemplateBuilder.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>Fluent builder for certificate templates. Task 15 fills in the typed surface.</summary>
public sealed class CertificateTemplateBuilder : ObjectTemplateBuilderBase<CertificateTemplateBuilder>
{
    internal CertificateTemplateBuilder(CKC certType)
    {
        _ = certType;
    }
}
```

`src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/DataTemplateBuilder.cs`:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>Fluent builder for data-object templates. Task 16 fills in the typed surface.</summary>
public sealed class DataTemplateBuilder : ObjectTemplateBuilderBase<DataTemplateBuilder>
{
    internal DataTemplateBuilder() { }
}
```

- [ ] **Step 7: Run tests to verify they pass**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ObjectTemplateTests" -c Debug
```

Expected: 6 tests pass.

- [ ] **Step 8: Verify the full test suite still passes**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 9: Completion checkpoint**

---

### Task 12: SecretKeyTemplateBuilder

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/SecretKeyTemplateBuilder.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ObjectTemplateTests.cs`

- [ ] **Step 1: Append `SecretKeyTemplateBuilder` tests to `ObjectTemplateTests.cs`**

Add inside the existing `ObjectTemplateTests` class (before the closing brace):

```csharp
    [Fact]
    public void SecretKey_PresetsClassAndKeyType()
    {
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Build();

        // CKA_CLASS, CKA_KEY_TYPE, CKA_SENSITIVE, CKA_EXTRACTABLE = 4 defaults.
        Assert.Equal(4, template.Count);
    }

    [Fact]
    public void SecretKey_HasSensitiveAndNonExtractableSecureDefaults()
    {
        // The builder should set CKA_SENSITIVE=true and CKA_EXTRACTABLE=false by
        // default. These secure defaults are required by the spec — verify both
        // attributes appear in the produced template with the expected values.
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Build();
        var attrs = template.Attributes;

        var sensitive = attrs.Single(a => a.Type == (ulong)CKA.CKA_SENSITIVE);
        var extractable = attrs.Single(a => a.Type == (ulong)CKA.CKA_EXTRACTABLE);

        // Both attributes carry a CK_BBOOL — value length is 1.
        Assert.Equal(1, sensitive.ValueLength);
        Assert.Equal(1, extractable.ValueLength);
    }

    [Fact]
    public void SecretKey_Extractable_OverridesDefault()
    {
        // Caller explicitly opts into insecure-by-PKCS#11-standard behavior.
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Extractable()
            .Build();

        // Count is still 4 — Extractable() replaces the default value, not adds a new one.
        Assert.Equal(4, template.Count);
    }

    [Fact]
    public void SecretKey_ValueLen_AddsLengthAttribute()
    {
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(256 / 8)
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_VALUE_LEN);
    }

    [Fact]
    public void SecretKey_KeyUsageFluentMethods_AddAttributes()
    {
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Encrypt()
            .Decrypt()
            .Sign()
            .Verify()
            .Wrap()
            .Unwrap()
            .Derive()
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_ENCRYPT);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_DECRYPT);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_SIGN);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_VERIFY);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_WRAP);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_UNWRAP);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_DERIVE);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ObjectTemplateTests" -c Debug
```

Expected: 5 new tests fail (builder produces no defaults, no `.Extractable()` / `.ValueLen()` / `.Encrypt()` / etc. methods exist).

- [ ] **Step 3: Implement `SecretKeyTemplateBuilder`**

Replace the contents of `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/SecretKeyTemplateBuilder.cs` with:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Fluent builder for a secret (symmetric) key template. Defaults to the secure
/// posture of <c>CKA_SENSITIVE = true</c> and <c>CKA_EXTRACTABLE = false</c>; callers can
/// opt out explicitly via <see cref="Sensitive(bool)"/> / <see cref="Extractable"/>.
/// </summary>
public sealed class SecretKeyTemplateBuilder : ObjectTemplateBuilderBase<SecretKeyTemplateBuilder>
{
    internal SecretKeyTemplateBuilder(CKK keyType)
    {
        Set(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
        Set(new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType));
        // Secure defaults — see spec section "Security properties preserved".
        Set(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
        Set(new ObjectAttribute(CKA.CKA_EXTRACTABLE, false));
    }

    /// <summary>Sets <c>CKA_SENSITIVE</c>. Defaults to <c>true</c> on construction.</summary>
    public SecretKeyTemplateBuilder Sensitive(bool value = true)
        => Attribute(CKA.CKA_SENSITIVE, value);

    /// <summary>Sets <c>CKA_EXTRACTABLE = false</c>. Redundant when used right after the
    /// builder ctor, but clarifies intent at the call site.</summary>
    public SecretKeyTemplateBuilder NonExtractable()
        => Attribute(CKA.CKA_EXTRACTABLE, false);

    /// <summary>Sets <c>CKA_EXTRACTABLE = true</c>. Insecure-by-PKCS#11-standard;
    /// callers must explicitly opt in.</summary>
    public SecretKeyTemplateBuilder Extractable()
        => Attribute(CKA.CKA_EXTRACTABLE, true);

    /// <summary>Sets <c>CKA_VALUE_LEN</c> — the key length in bytes (used by
    /// <c>C_GenerateKey</c>).</summary>
    public SecretKeyTemplateBuilder ValueLen(int bytes)
        => Attribute(CKA.CKA_VALUE_LEN, (ulong)bytes);

    /// <summary>Sets <c>CKA_VALUE</c> — the literal key bytes (used by
    /// <c>C_CreateObject</c> when importing key material).</summary>
    public SecretKeyTemplateBuilder Value(ReadOnlySpan<byte> value)
        => Attribute(CKA.CKA_VALUE, value);

    /// <summary>Sets <c>CKA_ENCRYPT</c>.</summary>
    public SecretKeyTemplateBuilder Encrypt(bool value = true) => Attribute(CKA.CKA_ENCRYPT, value);

    /// <summary>Sets <c>CKA_DECRYPT</c>.</summary>
    public SecretKeyTemplateBuilder Decrypt(bool value = true) => Attribute(CKA.CKA_DECRYPT, value);

    /// <summary>Sets <c>CKA_SIGN</c>.</summary>
    public SecretKeyTemplateBuilder Sign(bool value = true) => Attribute(CKA.CKA_SIGN, value);

    /// <summary>Sets <c>CKA_VERIFY</c>.</summary>
    public SecretKeyTemplateBuilder Verify(bool value = true) => Attribute(CKA.CKA_VERIFY, value);

    /// <summary>Sets <c>CKA_WRAP</c>.</summary>
    public SecretKeyTemplateBuilder Wrap(bool value = true) => Attribute(CKA.CKA_WRAP, value);

    /// <summary>Sets <c>CKA_UNWRAP</c>.</summary>
    public SecretKeyTemplateBuilder Unwrap(bool value = true) => Attribute(CKA.CKA_UNWRAP, value);

    /// <summary>Sets <c>CKA_DERIVE</c>.</summary>
    public SecretKeyTemplateBuilder Derive(bool value = true) => Attribute(CKA.CKA_DERIVE, value);
}
```

- [ ] **Step 4: Run tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ObjectTemplateTests" -c Debug
```

Expected: 11 tests pass (6 from Task 11 + 5 new).

- [ ] **Step 5: Verify the full test suite still passes**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 6: Completion checkpoint**

---

### Task 13: PrivateKeyTemplateBuilder

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/PrivateKeyTemplateBuilder.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ObjectTemplateTests.cs`

- [ ] **Step 1: Append tests for `PrivateKeyTemplateBuilder`**

Add inside `ObjectTemplateTests` (before the closing brace):

```csharp
    [Fact]
    public void PrivateKey_PresetsClassKeyTypeAndSecureDefaults()
    {
        using var template = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA).Build();

        // CKA_CLASS, CKA_KEY_TYPE, CKA_PRIVATE=true, CKA_SENSITIVE=true,
        // CKA_EXTRACTABLE=false = 5 defaults.
        Assert.Equal(5, template.Count);
    }

    [Fact]
    public void PrivateKey_AsymmetricUsageFlags_AddAttributes()
    {
        using var template = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Sign()
            .Decrypt()
            .Derive()
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_SIGN);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_DECRYPT);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_DERIVE);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ObjectTemplateTests" -c Debug
```

Expected: 2 new tests fail.

- [ ] **Step 3: Implement `PrivateKeyTemplateBuilder`**

Replace the contents of `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/PrivateKeyTemplateBuilder.cs` with:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Fluent builder for an asymmetric private-key template. Defaults to
/// <c>CKA_PRIVATE = true</c>, <c>CKA_SENSITIVE = true</c>, and
/// <c>CKA_EXTRACTABLE = false</c>; callers can opt out explicitly.
/// </summary>
public sealed class PrivateKeyTemplateBuilder : ObjectTemplateBuilderBase<PrivateKeyTemplateBuilder>
{
    internal PrivateKeyTemplateBuilder(CKK keyType)
    {
        Set(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
        Set(new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType));
        Set(new ObjectAttribute(CKA.CKA_PRIVATE, true));
        Set(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
        Set(new ObjectAttribute(CKA.CKA_EXTRACTABLE, false));
    }

    /// <summary>Sets <c>CKA_SENSITIVE</c>.</summary>
    public PrivateKeyTemplateBuilder Sensitive(bool value = true) => Attribute(CKA.CKA_SENSITIVE, value);

    /// <summary>Reinforces the non-extractable default.</summary>
    public PrivateKeyTemplateBuilder NonExtractable() => Attribute(CKA.CKA_EXTRACTABLE, false);

    /// <summary>Marks the key as extractable — insecure; callers must explicitly opt in.</summary>
    public PrivateKeyTemplateBuilder Extractable() => Attribute(CKA.CKA_EXTRACTABLE, true);

    /// <summary>Sets <c>CKA_SIGN</c>.</summary>
    public PrivateKeyTemplateBuilder Sign(bool value = true) => Attribute(CKA.CKA_SIGN, value);

    /// <summary>Sets <c>CKA_SIGN_RECOVER</c>.</summary>
    public PrivateKeyTemplateBuilder SignRecover(bool value = true) => Attribute(CKA.CKA_SIGN_RECOVER, value);

    /// <summary>Sets <c>CKA_DECRYPT</c>.</summary>
    public PrivateKeyTemplateBuilder Decrypt(bool value = true) => Attribute(CKA.CKA_DECRYPT, value);

    /// <summary>Sets <c>CKA_UNWRAP</c>.</summary>
    public PrivateKeyTemplateBuilder Unwrap(bool value = true) => Attribute(CKA.CKA_UNWRAP, value);

    /// <summary>Sets <c>CKA_DERIVE</c>.</summary>
    public PrivateKeyTemplateBuilder Derive(bool value = true) => Attribute(CKA.CKA_DERIVE, value);
}
```

- [ ] **Step 4: Run tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ObjectTemplateTests" -c Debug
```

Expected: 13 tests pass.

- [ ] **Step 5: Verify the full test suite still passes**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 6: Completion checkpoint**

---

### Task 14: PublicKeyTemplateBuilder

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/PublicKeyTemplateBuilder.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ObjectTemplateTests.cs`

- [ ] **Step 1: Append tests for `PublicKeyTemplateBuilder`**

Add inside `ObjectTemplateTests`:

```csharp
    [Fact]
    public void PublicKey_PresetsClassAndKeyType()
    {
        using var template = ObjectTemplate.ForPublicKey(CKK.CKK_RSA).Build();

        // CKA_CLASS, CKA_KEY_TYPE = 2 defaults. Public keys do not get the
        // sensitive/non-extractable defaults — they are not sensitive material.
        Assert.Equal(2, template.Count);
    }

    [Fact]
    public void PublicKey_VerifyAndEncryptUsageFlags()
    {
        using var template = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Verify()
            .Encrypt()
            .Wrap()
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_VERIFY);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_ENCRYPT);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_WRAP);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ObjectTemplateTests" -c Debug
```

Expected: 2 new tests fail.

- [ ] **Step 3: Implement `PublicKeyTemplateBuilder`**

Replace the contents of `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/PublicKeyTemplateBuilder.cs` with:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Fluent builder for an asymmetric public-key template. Public keys are not sensitive
/// material; no secure-default sensitivity attributes are pre-set.
/// </summary>
public sealed class PublicKeyTemplateBuilder : ObjectTemplateBuilderBase<PublicKeyTemplateBuilder>
{
    internal PublicKeyTemplateBuilder(CKK keyType)
    {
        Set(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
        Set(new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType));
    }

    /// <summary>Sets <c>CKA_VERIFY</c>.</summary>
    public PublicKeyTemplateBuilder Verify(bool value = true) => Attribute(CKA.CKA_VERIFY, value);

    /// <summary>Sets <c>CKA_VERIFY_RECOVER</c>.</summary>
    public PublicKeyTemplateBuilder VerifyRecover(bool value = true) => Attribute(CKA.CKA_VERIFY_RECOVER, value);

    /// <summary>Sets <c>CKA_ENCRYPT</c>.</summary>
    public PublicKeyTemplateBuilder Encrypt(bool value = true) => Attribute(CKA.CKA_ENCRYPT, value);

    /// <summary>Sets <c>CKA_WRAP</c>.</summary>
    public PublicKeyTemplateBuilder Wrap(bool value = true) => Attribute(CKA.CKA_WRAP, value);

    /// <summary>Sets <c>CKA_DERIVE</c>.</summary>
    public PublicKeyTemplateBuilder Derive(bool value = true) => Attribute(CKA.CKA_DERIVE, value);

    /// <summary>Sets <c>CKA_MODULUS_BITS</c> — RSA modulus length (used by
    /// <c>C_GenerateKeyPair</c>).</summary>
    public PublicKeyTemplateBuilder ModulusBits(int bits) => Attribute(CKA.CKA_MODULUS_BITS, (ulong)bits);

    /// <summary>Sets <c>CKA_PUBLIC_EXPONENT</c> — RSA public exponent.</summary>
    public PublicKeyTemplateBuilder PublicExponent(ReadOnlySpan<byte> exponent)
        => Attribute(CKA.CKA_PUBLIC_EXPONENT, exponent);

    /// <summary>Sets <c>CKA_EC_PARAMS</c> — EC curve parameters (DER-encoded).</summary>
    public PublicKeyTemplateBuilder EcParams(ReadOnlySpan<byte> derParams)
        => Attribute(CKA.CKA_EC_PARAMS, derParams);
}
```

- [ ] **Step 4: Run tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ObjectTemplateTests" -c Debug
```

Expected: 15 tests pass.

- [ ] **Step 5: Verify the full test suite still passes**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 6: Completion checkpoint**

---

### Task 15: CertificateTemplateBuilder

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/CertificateTemplateBuilder.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ObjectTemplateTests.cs`

- [ ] **Step 1: Append tests for `CertificateTemplateBuilder`**

Add inside `ObjectTemplateTests`:

```csharp
    [Fact]
    public void Certificate_PresetsClassAndCertType()
    {
        using var template = ObjectTemplate.ForCertificate(CKC.CKC_X_509).Build();

        // CKA_CLASS, CKA_CERTIFICATE_TYPE = 2 defaults.
        Assert.Equal(2, template.Count);
    }

    [Fact]
    public void Certificate_FluentMethods_AddSubjectAndValue()
    {
        byte[] subject = { 0x30, 0x05 };
        byte[] cert = { 0x30, 0x82 };

        using var template = ObjectTemplate.ForCertificate(CKC.CKC_X_509)
            .Subject(subject)
            .Value(cert)
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_SUBJECT);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_VALUE);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ObjectTemplateTests" -c Debug
```

Expected: 2 new tests fail.

- [ ] **Step 3: Implement `CertificateTemplateBuilder`**

Replace the contents of `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/CertificateTemplateBuilder.cs` with:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Fluent builder for a certificate template (CKO_CERTIFICATE).
/// </summary>
public sealed class CertificateTemplateBuilder : ObjectTemplateBuilderBase<CertificateTemplateBuilder>
{
    internal CertificateTemplateBuilder(CKC certType)
    {
        Set(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
        Set(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, certType));
    }

    /// <summary>Sets <c>CKA_SUBJECT</c> — DER-encoded subject name.</summary>
    public CertificateTemplateBuilder Subject(ReadOnlySpan<byte> subject)
        => Attribute(CKA.CKA_SUBJECT, subject);

    /// <summary>Sets <c>CKA_VALUE</c> — DER-encoded certificate body.</summary>
    public CertificateTemplateBuilder Value(ReadOnlySpan<byte> certificate)
        => Attribute(CKA.CKA_VALUE, certificate);

    /// <summary>Sets <c>CKA_TRUSTED</c>.</summary>
    public CertificateTemplateBuilder Trusted(bool value = true)
        => Attribute(CKA.CKA_TRUSTED, value);

    /// <summary>Sets <c>CKA_ISSUER</c> — DER-encoded issuer name.</summary>
    public CertificateTemplateBuilder Issuer(ReadOnlySpan<byte> issuer)
        => Attribute(CKA.CKA_ISSUER, issuer);

    /// <summary>Sets <c>CKA_SERIAL_NUMBER</c> — DER-encoded serial number.</summary>
    public CertificateTemplateBuilder SerialNumber(ReadOnlySpan<byte> serial)
        => Attribute(CKA.CKA_SERIAL_NUMBER, serial);
}
```

- [ ] **Step 4: Run tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ObjectTemplateTests" -c Debug
```

Expected: 17 tests pass.

- [ ] **Step 5: Verify the full test suite still passes**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 6: Completion checkpoint**

---

### Task 16: DataTemplateBuilder

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/DataTemplateBuilder.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ObjectTemplateTests.cs`

- [ ] **Step 1: Append tests for `DataTemplateBuilder`**

Add inside `ObjectTemplateTests`:

```csharp
    [Fact]
    public void Data_PresetsClass()
    {
        using var template = ObjectTemplate.ForData().Build();

        // CKA_CLASS = 1 default.
        Assert.Equal(1, template.Count);
    }

    [Fact]
    public void Data_ValueAndApplication_AddAttributes()
    {
        byte[] payload = { 0x01, 0x02, 0x03 };

        using var template = ObjectTemplate.ForData()
            .Application("my-app")
            .Value(payload)
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_APPLICATION);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_VALUE);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ObjectTemplateTests" -c Debug
```

Expected: 2 new tests fail.

- [ ] **Step 3: Implement `DataTemplateBuilder`**

Replace the contents of `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/DataTemplateBuilder.cs` with:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Fluent builder for a data-object template (CKO_DATA).
/// </summary>
public sealed class DataTemplateBuilder : ObjectTemplateBuilderBase<DataTemplateBuilder>
{
    internal DataTemplateBuilder()
    {
        Set(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA));
    }

    /// <summary>Sets <c>CKA_APPLICATION</c>.</summary>
    public DataTemplateBuilder Application(string application)
        => Attribute(CKA.CKA_APPLICATION, application);

    /// <summary>Sets <c>CKA_OBJECT_ID</c> — DER-encoded OID identifying the data type.</summary>
    public DataTemplateBuilder ObjectId(ReadOnlySpan<byte> derOid)
        => Attribute(CKA.CKA_OBJECT_ID, derOid);

    /// <summary>Sets <c>CKA_VALUE</c> — the data payload.</summary>
    public DataTemplateBuilder Value(ReadOnlySpan<byte> payload)
        => Attribute(CKA.CKA_VALUE, payload);
}
```

- [ ] **Step 4: Run tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ObjectTemplateTests" -c Debug
```

Expected: 19 tests pass.

- [ ] **Step 5: Verify the full test suite still passes**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 6: Completion checkpoint**

---

### Task 17: Final sanity sweep

**Files:**
- None modified; verification only.

This task is a final review of Plan 1's deliverables and a guard against regressions. No code changes — only commands.

- [ ] **Step 1: Verify zero direct construction of `Pkcs11Exception` outside the mapper**

```bash
grep -rn "new Pkcs11AuthenticationException\|new Pkcs11SessionException\|new Pkcs11TokenException\|new Pkcs11MechanismException\|new Pkcs11ObjectException\|new Pkcs11ArgumentException\|new Pkcs11UnclassifiedException" \
  src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
```

Expected: matches ONLY in `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/ExceptionMapper.cs`.

- [ ] **Step 2: Verify zero `throw new Pkcs11Exception(...)` calls anywhere in production**

```bash
grep -rn "throw new Pkcs11" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
```

Expected: no output. (Throws happen exclusively via `Pkcs11Exception.ThrowIfError(...)`.)

- [ ] **Step 3: Verify `Pkcs11Exception` is abstract**

```bash
grep -n "public abstract class Pkcs11Exception" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/Pkcs11Exception.cs
```

Expected: one match.

- [ ] **Step 4: Run the full test suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures, 0 errors. The test count should be the previous total plus approximately 76 new tests:
- `Pkcs11ExceptionTests`: 14 (3 base ctor / message + 7 subclass-derivation + 4 ThrowIfError).
- `ExceptionMapperTests`: 43 (11 auth + 8 session + 7 token + 3 mechanism + 5 object + 4 argument + 4 uncategorized + 1 preservation fact).
- `ObjectTemplateTests`: 19 (6 base + 5 secret + 2 private + 2 public + 2 certificate + 2 data).

- [ ] **Step 5: Run a Release build to catch any warnings-as-errors regressions**

```bash
dotnet build src/KerckhoffsLabs.sln -c Release
```

Expected: build succeeds with no errors and no new warnings related to Plan 1 changes.

- [ ] **Step 6: Completion checkpoint**

Plan 1 is complete. The codebase now has:

- An abstract `Pkcs11Exception` base + 7 typed subclasses, each catchable by category.
- A central `Pkcs11Exception.ThrowIfError(CKR, string)` routing every native call site through `ExceptionMapper`.
- All 129 (formerly direct) throw sites migrated to `ThrowIfError`.
- A fluent `ObjectTemplate` builder API with 6 typed builders plus the generic escape hatch, secure defaults on secret/private keys, and deterministic disposal of unmanaged attribute buffers.
- ~76 new managed-only unit tests covering the above (14 + 43 + 19).

No public behavior changed beyond the exception subtype reported on failure (always a subclass of the original `Pkcs11Exception`, so existing catch sites continue to work). Plan 2 builds on these foundations to introduce `Pkcs11Workspace` and `Pkcs11Key`.
