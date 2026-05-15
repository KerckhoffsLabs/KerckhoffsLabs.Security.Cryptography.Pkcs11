# PKCS#11 Struct-Packing Source Generator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix BL-001 so PKCS#11 struct marshalling is correct on every supported platform (Linux/macOS x64 + Windows x64) without sacrificing the user's single-source-definition-per-struct simplification goal.

**Architecture:** A Roslyn source generator emits, for every `[PackedForPkcs11]`-marked partial struct `T`, a sibling `T_Windows` partial whose `[StructLayout(Sequential, Pack = 1)]` matches OASIS-conformant Windows ABI. Nested decorated types are substituted with their `_Windows` siblings. A `Pkcs11Marshal` runtime helper picks `T` or `T_Windows` based on `OperatingSystem.IsWindows()` at every marshalling site. P/Invoke delegates that pass structs by `ref` get parallel `_Windows` variants; thin dispatchers in `LowLevelPkcs11Library` call the right one. The `Pkcs11Interop` four-tree approach is avoided — one source definition per struct survives, with platform divergence moved from a (broken) compile-time `[StructLayout]` decision to a (correct) build-time generation step.

**Tech Stack:**
- .NET 10, C# `latest`
- Roslyn source generators (`Microsoft.CodeAnalysis.CSharp` 4.x, incremental generator API)
- xUnit 2.9.3 for regression tests
- Existing `KerckhoffsLabs.Runtime.InteropServices` for `NativeCULong` (handles the orthogonal CK_ULONG width axis)

**Phasing:**
- **Phase 1** (Tasks 1–4): Source-gen scaffolding + marker attribute. End state: empty generator project compiles, attribute exists, smoke test passes.
- **Phase 2** (Tasks 5–8): Generator implementation. End state: `_Windows` siblings are produced for marked structs.
- **Phase 3** (Tasks 9–11): `Pkcs11Marshal` runtime helper. End state: SizeOf/Read/Write work correctly on Linux; on Windows they dispatch to `_Windows` siblings (testable on a Windows machine but not yet enforced in CI).
- **Phase 4** (Task 12): `MarshalSizeOfTests` regression suite. End state: Linux struct sizes are pinned; Windows-side assertions are written but `Skip` on non-Windows runners.
- **Phase 5** (Tasks 13–14): Migrate all `[PlatformSpecificPack]`-decorated structs and all `Marshal.X` callsites to the new helper. End state: Linux tests still green; parameter structs marshal through the new path.
- **Phase 6** (Tasks 15–16): P/Invoke dispatch for outer structs passed by `ref`. End state: every `C_*Init` / `C_GetInfo` / `C_GetSlotInfo` / etc. dispatches to a Windows-layout delegate on Windows.
- **Phase 7** (Tasks 17–18): Fix Windows CI (BL-049) so the Windows ABI is actually exercised. End state: green CI on Windows + Linux.
- **Phase 8** (Tasks 19–20): Cleanup. Delete `PlatformSpecificPackAttribute`, close out BL-001 in `BACKLOG.md`.

Phases 1–4 alone deliver working software (the new infrastructure exists, Linux tests are unchanged). Phases 5–6 are the real migration. Phases 7–8 prove correctness on Windows and remove the dead code.

---

## File Structure

### New files

| Path | Responsibility |
|---|---|
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen.csproj` | Roslyn source-generator project. Targets `netstandard2.0` (analyzer ABI requirement). Not shipped as a NuGet — referenced as `<Analyzer>` from the main library. |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/PackedStructsGenerator.cs` | The generator itself. Implements `IIncrementalGenerator`. |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PackedForPkcs11Attribute.cs` | Marker attribute (no `[StructLayout]` on the attribute class — strictly a marker). Internal. |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Pkcs11Marshal.cs` | Runtime dispatcher: `SizeOf<T>()`, `WriteStructure<T>(ptr, in T)`, `ReadStructure<T>(ptr)`, caches the `T_Windows` Type lookup per generic instantiation. |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/MarshalSizeOfTests.cs` | Regression test asserting `Marshal.SizeOf<T>()` against the expected ABI for each platform. |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/Pkcs11MarshalTests.cs` | Unit tests for the runtime helper itself. |

### Modified files (high level — exact line edits in each task)

| Path | What changes |
|---|---|
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` | Add `<ProjectReference>` to the source-gen project with `OutputItemType="Analyzer"` / `ReferenceOutputAssembly="false"`. Drop the `<DefineConstants>WINDOWS</DefineConstants>` block. |
| `src/KerckhoffsLabs.sln` | Add the new source-gen project to the solution. |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PlatformSpecificPackAttribute.cs` | **Deleted in Phase 8.** |
| ~100 files under `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/` and `Native/RawMechanismParams/` | Replace `[PlatformSpecificPack]` with `[PackedForPkcs11]` and add `[StructLayout(LayoutKind.Sequential)]`. Add `partial` keyword on each struct. |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/UnmanagedMemory.cs` | `Write(IntPtr, object)` and `Read(IntPtr, Type)` callsites in the project route through `Pkcs11Marshal`. `SizeOf(Type)` likewise. |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs` | Add 27 `*_WindowsDelegate` variants and corresponding fields. |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs` | Each `C_*` wrapper that takes `ref CK_X` becomes a dispatcher. |
| `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/ObjectAttribute.cs` | Marshal callsites updated. |
| `.github/workflows/ci.yml` | Remove `continue-on-error` from Windows SoftHSM install; ensure binary is on PATH. |
| `BACKLOG.md` | Mark BL-001 closed in Phase 8. |

---

## Phase 1 — Source-gen scaffolding

### Task 1: Create the source-gen project

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen.csproj`

- [ ] **Step 1: Write the csproj**

Path: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen.csproj`

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>netstandard2.0</TargetFramework>
    <LangVersion>latest</LangVersion>
    <Nullable>enable</Nullable>
    <IsRoslynComponent>true</IsRoslynComponent>
    <EnforceExtendedAnalyzerRules>true</EnforceExtendedAnalyzerRules>
    <IsPackable>false</IsPackable>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.CodeAnalysis.CSharp" Version="4.11.0" PrivateAssets="all" />
    <PackageReference Include="Microsoft.CodeAnalysis.Analyzers" Version="3.11.0" PrivateAssets="all" />
  </ItemGroup>
</Project>
```

- [ ] **Step 2: Add a minimal placeholder generator so the project compiles**

Path: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/PackedStructsGenerator.cs`

```csharp
using Microsoft.CodeAnalysis;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen;

[Generator(LanguageNames.CSharp)]
public sealed class PackedStructsGenerator : IIncrementalGenerator
{
    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        // Placeholder — real generator lands in Task 6.
    }
}
```

- [ ] **Step 3: Build the project standalone**

Run: `dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen.csproj`
Expected: `Build succeeded. 0 Error(s).`

- [ ] **Step 4: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/
git commit -m "feat(source-gen): scaffold packed-structs generator project"
```

---

### Task 2: Wire the source-gen project into the main library

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`
- Modify: `src/KerckhoffsLabs.sln`

- [ ] **Step 1: Add the analyzer reference to the main project**

In `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`, find the existing `<ItemGroup>` containing `<PackageReference Include="KerckhoffsLabs.Runtime.InteropServices" ...>` and add a new ItemGroup directly after it:

```xml
  <ItemGroup>
    <ProjectReference
      Include="..\KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen\KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen.csproj"
      OutputItemType="Analyzer"
      ReferenceOutputAssembly="false" />
  </ItemGroup>
```

- [ ] **Step 2: Add the source-gen project to the solution**

Run: `dotnet sln src/KerckhoffsLabs.sln add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen.csproj`
Expected: `Project ... added to the solution.`

- [ ] **Step 3: Rebuild the whole solution**

Run: `dotnet build src/KerckhoffsLabs.sln`
Expected: `Build succeeded. 0 Error(s).` (warnings are fine — pre-existing.)

- [ ] **Step 4: Commit**

```bash
git add src/KerckhoffsLabs.sln src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj
git commit -m "build: wire packed-structs source generator into main library"
```

---

### Task 3: Add `[PackedForPkcs11]` marker attribute

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PackedForPkcs11Attribute.cs`

- [ ] **Step 1: Write the attribute**

Path: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PackedForPkcs11Attribute.cs`

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Marks a native interop struct as requiring a Windows-packed (<c>Pack = 1</c>) sibling.
/// Consumed by the <c>PackedStructsGenerator</c> source generator, which emits a parallel
/// <c>T_Windows</c> partial struct in the same namespace. Runtime dispatch happens in
/// <see cref="Pkcs11Marshal"/> based on <c>OperatingSystem.IsWindows()</c>.
/// </summary>
/// <remarks>
/// The decorated struct MUST be declared <c>partial</c> and MUST carry
/// <c>[StructLayout(LayoutKind.Sequential)]</c> explicitly. This attribute is a marker
/// only — it does NOT itself set the layout.
/// </remarks>
[AttributeUsage(AttributeTargets.Struct, AllowMultiple = false, Inherited = false)]
internal sealed class PackedForPkcs11Attribute : Attribute
{
}
```

- [ ] **Step 2: Build**

Run: `dotnet build src/KerckhoffsLabs.sln`
Expected: `Build succeeded.`

- [ ] **Step 3: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PackedForPkcs11Attribute.cs
git commit -m "feat(native): add [PackedForPkcs11] marker attribute"
```

---

### Task 4: Generator smoke test (consumer struct produces a generated file)

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/PackedStructsGenerator.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_VERSION.cs`

- [ ] **Step 1: Make the generator emit a hardcoded stub for any consumer**

Update `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/PackedStructsGenerator.cs`:

```csharp
using Microsoft.CodeAnalysis;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen;

[Generator(LanguageNames.CSharp)]
public sealed class PackedStructsGenerator : IIncrementalGenerator
{
    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        context.RegisterPostInitializationOutput(static ctx =>
        {
            ctx.AddSource("__PackedStructsGenerator.SmokeTest.g.cs",
                "// PackedStructsGenerator: smoke output\n");
        });
    }
}
```

- [ ] **Step 2: Build the main project and verify the generated file appears**

Run: `dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -p:EmitCompilerGeneratedFiles=true -p:CompilerGeneratedFilesOutputPath=obj/generated`
Expected: `Build succeeded.`

Then verify the file exists:
Run: `find src/KerckhoffsLabs.Security.Cryptography.Pkcs11/obj/generated -name "__PackedStructsGenerator.SmokeTest.g.cs"`
Expected: one match.

- [ ] **Step 3: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/PackedStructsGenerator.cs
git commit -m "feat(source-gen): smoke-test post-initialization output"
```

---

## Phase 2 — Generator implementation

### Task 5: Generator finds `[PackedForPkcs11]`-marked structs

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/PackedStructsGenerator.cs`

- [ ] **Step 1: Replace the smoke generator with a discovery pipeline**

Path: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/PackedStructsGenerator.cs`

```csharp
using System.Collections.Immutable;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen;

[Generator(LanguageNames.CSharp)]
public sealed class PackedStructsGenerator : IIncrementalGenerator
{
    private const string AttributeFullName =
        "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.PackedForPkcs11Attribute";

    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        var marked = context.SyntaxProvider.ForAttributeWithMetadataName(
            AttributeFullName,
            predicate: static (node, _) => node is StructDeclarationSyntax,
            transform: static (ctx, _) => (INamedTypeSymbol)ctx.TargetSymbol);

        context.RegisterSourceOutput(marked.Collect(), static (spc, syms) =>
        {
            foreach (var sym in syms)
            {
                // Emit one trivial file per discovered struct to prove the pipeline works.
                var hint = $"{sym.Name}_Windows.g.cs";
                var body = $"// Discovered: {sym.ToDisplayString()}\n";
                spc.AddSource(hint, SourceText.From(body, Encoding.UTF8));
            }
        });
    }
}
```

- [ ] **Step 2: Mark `CK_VERSION` with the attribute so we have something to discover**

Path: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_VERSION.cs`

Find the current struct declaration. Add `[PackedForPkcs11]` and `[StructLayout(LayoutKind.Sequential)]` and make it `partial`. Existing code:

```csharp
[PlatformSpecificPack]
public struct CK_VERSION
```

becomes:

```csharp
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_VERSION
```

Leave all other files unchanged for now — they'll migrate in Task 13.

- [ ] **Step 3: Build with generated-files output**

Run: `dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -p:EmitCompilerGeneratedFiles=true -p:CompilerGeneratedFilesOutputPath=obj/generated 2>&1 | tail -5`
Expected: `Build succeeded.`

- [ ] **Step 4: Verify discovery output appeared**

Run: `find src/KerckhoffsLabs.Security.Cryptography.Pkcs11/obj/generated -name "CK_VERSION_Windows.g.cs"`
Expected: one match. Its content should be the comment line `// Discovered: KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.CK_VERSION`.

- [ ] **Step 5: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/PackedStructsGenerator.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_VERSION.cs
git commit -m "feat(source-gen): discover [PackedForPkcs11]-marked structs"
```

---

### Task 6: Generator emits `T_Windows` siblings with `Pack=1`

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/PackedStructsGenerator.cs`

- [ ] **Step 1: Implement field-by-field emission**

Replace the `RegisterSourceOutput` body in `PackedStructsGenerator.cs` with the full emission logic. New file:

```csharp
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen;

[Generator(LanguageNames.CSharp)]
public sealed class PackedStructsGenerator : IIncrementalGenerator
{
    private const string AttributeFullName =
        "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.PackedForPkcs11Attribute";

    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        var marked = context.SyntaxProvider.ForAttributeWithMetadataName(
            AttributeFullName,
            predicate: static (node, _) => node is StructDeclarationSyntax,
            transform: static (ctx, _) => (INamedTypeSymbol)ctx.TargetSymbol);

        context.RegisterSourceOutput(marked.Collect(), Emit);
    }

    private static void Emit(SourceProductionContext spc, ImmutableArray<INamedTypeSymbol> syms)
    {
        // Map each marked type's fully-qualified name to its Windows-sibling type name
        // ("CK_INFO" -> "CK_INFO_Windows"). Used to substitute field types when emitting.
        var packedNames = syms
            .ToDictionary(s => s.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                          s => s.Name + "_Windows");

        foreach (var sym in syms)
            spc.AddSource($"{sym.Name}_Windows.g.cs", SourceText.From(Render(sym, packedNames), Encoding.UTF8));
    }

    private static string Render(INamedTypeSymbol sym, IReadOnlyDictionary<string, string> packedNames)
    {
        var ns = sym.ContainingNamespace.ToDisplayString();
        var sb = new StringBuilder();
        sb.AppendLine("// <auto-generated/> PackedStructsGenerator");
        sb.AppendLine("#nullable enable");
        sb.AppendLine("using System.Runtime.InteropServices;");
        sb.AppendLine();
        sb.Append("namespace ").Append(ns).AppendLine(";");
        sb.AppendLine();
        sb.AppendLine("[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]");
        sb.Append("internal partial struct ").Append(sym.Name).AppendLine("_Windows");
        sb.AppendLine("{");

        var fields = sym.GetMembers().OfType<IFieldSymbol>()
            .Where(f => !f.IsStatic && !f.IsConst).ToArray();

        foreach (var f in fields)
            EmitField(sb, f, packedNames);

        sb.AppendLine();
        EmitFromUnified(sb, sym, fields, packedNames);
        sb.AppendLine();
        EmitToUnified(sb, sym, fields, packedNames);

        sb.AppendLine("}");
        return sb.ToString();
    }

    private static void EmitField(StringBuilder sb, IFieldSymbol f,
                                   IReadOnlyDictionary<string, string> packedNames)
    {
        // Forward any [MarshalAs] / [In] / [Out] attributes verbatim.
        foreach (var a in f.GetAttributes())
        {
            var ac = a.AttributeClass;
            if (ac is null) continue;
            // Skip [PackedForPkcs11] (it's on the type, not fields, but defensive).
            if (ac.ToDisplayString() == AttributeFullName) continue;
            sb.Append("    [").Append(a.ToString()).AppendLine("]");
        }
        var typeName = SubstituteFieldType(f.Type, packedNames);
        sb.Append("    public ").Append(typeName).Append(' ').Append(f.Name).AppendLine(";");
    }

    private static string SubstituteFieldType(ITypeSymbol t, IReadOnlyDictionary<string, string> packedNames)
    {
        // Walk arrays / pointers — for now only handle T and T[] (ByValArray flattens to inline).
        if (t is IArrayTypeSymbol arr)
            return SubstituteFieldType(arr.ElementType, packedNames) + "[]";

        var key = t.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        if (packedNames.TryGetValue(key, out var winName))
        {
            // Use the simple name when the windows sibling is in the same namespace
            // (every marked struct lives in Native/ or Native/RawMechanismParams/).
            return winName;
        }
        return t.ToDisplayString();
    }

    private static void EmitFromUnified(StringBuilder sb, INamedTypeSymbol sym,
                                          IFieldSymbol[] fields,
                                          IReadOnlyDictionary<string, string> packedNames)
    {
        sb.Append("    public static ").Append(sym.Name).Append("_Windows FromUnified(in ").Append(sym.Name).AppendLine(" src) => new()");
        sb.AppendLine("    {");
        foreach (var f in fields)
        {
            var key = f.Type is IArrayTypeSymbol arr
                ? arr.ElementType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)
                : f.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

            if (packedNames.TryGetValue(key, out var winName))
            {
                if (f.Type is IArrayTypeSymbol)
                {
                    // Element-wise conversion for arrays of packed types.
                    sb.Append("        ").Append(f.Name).Append(" = src.").Append(f.Name)
                      .Append(" is null ? null! : System.Array.ConvertAll(src.").Append(f.Name)
                      .Append(", ").Append(winName).AppendLine(".FromUnified),");
                }
                else
                {
                    sb.Append("        ").Append(f.Name).Append(" = ").Append(winName)
                      .Append(".FromUnified(in src.").Append(f.Name).AppendLine("),");
                }
            }
            else
            {
                sb.Append("        ").Append(f.Name).Append(" = src.").Append(f.Name).AppendLine(",");
            }
        }
        sb.AppendLine("    };");
    }

    private static void EmitToUnified(StringBuilder sb, INamedTypeSymbol sym,
                                        IFieldSymbol[] fields,
                                        IReadOnlyDictionary<string, string> packedNames)
    {
        sb.Append("    public ").Append(sym.Name).AppendLine(" ToUnified() => new()");
        sb.AppendLine("    {");
        foreach (var f in fields)
        {
            var key = f.Type is IArrayTypeSymbol arr
                ? arr.ElementType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)
                : f.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

            if (packedNames.TryGetValue(key, out var winName))
            {
                if (f.Type is IArrayTypeSymbol)
                {
                    sb.Append("        ").Append(f.Name).Append(" = this.").Append(f.Name)
                      .Append(" is null ? null! : System.Array.ConvertAll(this.").Append(f.Name)
                      .Append(", static w => w.ToUnified()),");
                    sb.AppendLine();
                }
                else
                {
                    sb.Append("        ").Append(f.Name).Append(" = this.").Append(f.Name).AppendLine(".ToUnified(),");
                }
            }
            else
            {
                sb.Append("        ").Append(f.Name).Append(" = this.").Append(f.Name).AppendLine(",");
            }
        }
        sb.AppendLine("    };");
    }
}
```

- [ ] **Step 2: Build the main project and look at the generated output for `CK_VERSION`**

Run: `dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -p:EmitCompilerGeneratedFiles=true -p:CompilerGeneratedFilesOutputPath=obj/generated 2>&1 | tail -5`
Expected: `Build succeeded.`

Then: `cat src/KerckhoffsLabs.Security.Cryptography.Pkcs11/obj/generated/**/CK_VERSION_Windows.g.cs`
Expected output contains:
- `[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]`
- `internal partial struct CK_VERSION_Windows`
- All the field declarations from the original `CK_VERSION`
- `public static CK_VERSION_Windows FromUnified(in CK_VERSION src) => new() { ... };`
- `public CK_VERSION ToUnified() => new() { ... };`

- [ ] **Step 3: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen/PackedStructsGenerator.cs
git commit -m "feat(source-gen): emit T_Windows partials with Pack=1 + FromUnified/ToUnified"
```

---

### Task 7: Verify generator handles nested decorated types

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_INFO.cs`

- [ ] **Step 1: Migrate CK_INFO to `[PackedForPkcs11]` for a nested-type test**

Path: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_INFO.cs`

Replace `[PlatformSpecificPack]` with:

```csharp
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_INFO
```

(Other fields unchanged. The `partial` keyword is the only structural change beyond the attribute swap.)

- [ ] **Step 2: Build and inspect the generated CK_INFO_Windows**

Run: `dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -p:EmitCompilerGeneratedFiles=true -p:CompilerGeneratedFilesOutputPath=obj/generated 2>&1 | tail -5`
Expected: `Build succeeded.`

Then: `cat src/KerckhoffsLabs.Security.Cryptography.Pkcs11/obj/generated/**/CK_INFO_Windows.g.cs`
Expected:
- `public CK_VERSION_Windows CryptokiVersion;` (NOT `CK_VERSION`! — the generator substituted)
- `public CK_VERSION_Windows LibraryVersion;`
- `FromUnified` body assigns `CryptokiVersion = CK_VERSION_Windows.FromUnified(in src.CryptokiVersion)`
- `ToUnified` body assigns `CryptokiVersion = this.CryptokiVersion.ToUnified()`

- [ ] **Step 3: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_INFO.cs
git commit -m "test(source-gen): exercise nested-type substitution on CK_INFO"
```

---

### Task 8: Pin generator output for CK_VERSION and CK_INFO with a snapshot test

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/Pkcs11MarshalTests.cs` (will host the helper tests in Task 11; for now just the size-baseline test)
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/MarshalSizeOfTests.cs` (full suite arrives in Task 12; one assertion now)

- [ ] **Step 1: Write the failing test that asserts CK_INFO_Windows exists with correct fields**

Path: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/MarshalSizeOfTests.cs`

```csharp
using System;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Xunit;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Internal;

/// <summary>
/// Regression tests pinning the native struct sizes per platform. These prevent
/// future struct-layout drift and catch BL-001-class bugs immediately.
/// </summary>
public sealed class MarshalSizeOfTests
{
    // Linux/macOS x64: natural alignment (Pack = default). PKCS#11 spec applies no pragma on non-Windows.
    // The unified type T marshals correctly on these platforms.
    [Fact]
    public void CK_VERSION_size_is_2()
    {
        Assert.Equal(2, Marshal.SizeOf<CK_VERSION>());
    }

    [Fact]
    public void CK_INFO_unified_size_matches_native_on_linux()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return; // Windows assertion lives below.

        // CK_VERSION(2) + byte[32] + NativeCULong(8 on LP64) + byte[32] + CK_VERSION(2)
        //   = 2 + 32 + 6(pad to 8) + 8 + 32 + 2 + 6(trailing align to 8) = 88
        Assert.Equal(88, Marshal.SizeOf<CK_INFO>());
    }

    [Fact]
    public void CK_INFO_Windows_sibling_is_generated()
    {
        var winType = typeof(CK_INFO).Assembly.GetType(
            "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.CK_INFO_Windows");
        Assert.NotNull(winType);
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `dotnet test src/KerckhoffsLabs.sln --filter "FullyQualifiedName~MarshalSizeOfTests" --no-build`
Expected: First build, then 3 passed.

If `CK_INFO_Windows` is reported as `internal`, the reflection lookup still works because `Assembly.GetType` is type-name based, not visibility-filtered. The test should pass without any visibility modifier change.

- [ ] **Step 3: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/MarshalSizeOfTests.cs
git commit -m "test(native): pin CK_VERSION/CK_INFO unified sizes and verify generated sibling"
```

---

## Phase 3 — `Pkcs11Marshal` runtime helper

### Task 9: Implement `Pkcs11Marshal.SizeOf<T>()`

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Pkcs11Marshal.cs`

- [ ] **Step 1: Write the helper with reflective sibling lookup**

Path: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Pkcs11Marshal.cs`

```csharp
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Runtime dispatcher for PKCS#11 struct marshalling. On Linux/macOS, every operation
/// uses the unified type <c>T</c> directly. On Windows, when a generated <c>T_Windows</c>
/// sibling exists (via <see cref="PackedForPkcs11Attribute"/> + the source generator),
/// operations route through that sibling so the <c>Pack = 1</c> layout matches the
/// OASIS-conformant Windows PKCS#11 ABI.
/// </summary>
internal static class Pkcs11Marshal
{
    public static readonly bool IsWindows = OperatingSystem.IsWindows();

    public static int SizeOf<T>() where T : struct => SiblingCache<T>.Size;

    private static class SiblingCache<T> where T : struct
    {
        public static readonly Type? WindowsType;
        public static readonly int Size;
        public static readonly MethodInfo? FromUnified; // static method on T_Windows: T_Windows FromUnified(in T)
        public static readonly MethodInfo? ToUnified;   // instance method on T_Windows: T ToUnified()

        static SiblingCache()
        {
            var asm = typeof(T).Assembly;
            var winName = typeof(T).FullName + "_Windows";
            WindowsType = asm.GetType(winName);

            if (WindowsType is not null)
            {
                FromUnified = WindowsType.GetMethod("FromUnified",
                    BindingFlags.Public | BindingFlags.Static, binder: null,
                    types: [typeof(T).MakeByRefType()], modifiers: null);
                ToUnified = WindowsType.GetMethod("ToUnified",
                    BindingFlags.Public | BindingFlags.Instance, binder: null,
                    types: Type.EmptyTypes, modifiers: null);
            }

            Size = (IsWindows && WindowsType is not null)
                ? Marshal.SizeOf(WindowsType)
                : Marshal.SizeOf<T>();
        }
    }
}
```

- [ ] **Step 2: Build**

Run: `dotnet build src/KerckhoffsLabs.sln`
Expected: `Build succeeded.`

- [ ] **Step 3: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Pkcs11Marshal.cs
git commit -m "feat(native): Pkcs11Marshal.SizeOf<T>() with cached T_Windows lookup"
```

---

### Task 10: Add `WriteStructure<T>` / `ReadStructure<T>`

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Pkcs11Marshal.cs`

- [ ] **Step 1: Add the read/write methods that bridge T ↔ T_Windows on Windows**

Append the following methods to the `Pkcs11Marshal` class body (before the closing brace of the class):

```csharp
    /// <summary>
    /// Marshals <paramref name="value"/> into the unmanaged buffer at <paramref name="ptr"/>,
    /// using the Windows-packed sibling layout when running on Windows and a sibling exists.
    /// The buffer must already be allocated and at least <see cref="SizeOf{T}"/> bytes.
    /// </summary>
    public static void WriteStructure<T>(IntPtr ptr, in T value) where T : struct
    {
        if (IsWindows && SiblingCache<T>.WindowsType is not null && SiblingCache<T>.FromUnified is not null)
        {
            object windowsBoxed = SiblingCache<T>.FromUnified.Invoke(null, [value])!;
            Marshal.StructureToPtr(windowsBoxed, ptr, fDeleteOld: false);
        }
        else
        {
            Marshal.StructureToPtr<T>(value, ptr, fDeleteOld: false);
        }
    }

    /// <summary>
    /// Reads a struct of type <typeparamref name="T"/> from the unmanaged buffer at
    /// <paramref name="ptr"/>, dispatching to the Windows-packed sibling layout on Windows
    /// and round-tripping back to the unified type via <c>ToUnified()</c>.
    /// </summary>
    public static T ReadStructure<T>(IntPtr ptr) where T : struct
    {
        if (IsWindows && SiblingCache<T>.WindowsType is not null && SiblingCache<T>.ToUnified is not null)
        {
            object? windowsBoxed = Marshal.PtrToStructure(ptr, SiblingCache<T>.WindowsType);
            if (windowsBoxed is null)
                throw new InvalidOperationException(
                    $"Marshal.PtrToStructure returned null for {SiblingCache<T>.WindowsType}.");
            return (T)SiblingCache<T>.ToUnified.Invoke(windowsBoxed, null)!;
        }
        return Marshal.PtrToStructure<T>(ptr);
    }
```

- [ ] **Step 2: Build**

Run: `dotnet build src/KerckhoffsLabs.sln`
Expected: `Build succeeded.`

- [ ] **Step 3: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Pkcs11Marshal.cs
git commit -m "feat(native): Pkcs11Marshal.WriteStructure/ReadStructure with sibling dispatch"
```

---

### Task 11: Unit-test the helper on Linux (sibling-less and sibling-aware paths)

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/Pkcs11MarshalTests.cs`

- [ ] **Step 1: Write the tests**

Path: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/Pkcs11MarshalTests.cs`

```csharp
using System;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Xunit;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Internal;

public sealed class Pkcs11MarshalTests
{
    [Fact]
    public void SizeOf_returns_native_size_for_CK_VERSION()
    {
        Assert.Equal(Marshal.SizeOf<CK_VERSION>(), Pkcs11Marshal.SizeOf<CK_VERSION>());
    }

    [Fact]
    public void SizeOf_for_CK_INFO_matches_marshal_sizeof_on_unix()
    {
        if (OperatingSystem.IsWindows()) return;
        Assert.Equal(Marshal.SizeOf<CK_INFO>(), Pkcs11Marshal.SizeOf<CK_INFO>());
    }

    [Fact]
    public void RoundTrip_CK_VERSION_through_WriteRead()
    {
        var src = new CK_VERSION { Major = [3], Minor = [2] };
        int size = Pkcs11Marshal.SizeOf<CK_VERSION>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Pkcs11Marshal.WriteStructure(ptr, src);
            var rt = Pkcs11Marshal.ReadStructure<CK_VERSION>(ptr);
            Assert.Equal(3, rt.Major[0]);
            Assert.Equal(2, rt.Minor[0]);
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    [Fact]
    public void RoundTrip_CK_INFO_through_WriteRead()
    {
        // Pre-populate the byte arrays — Marshal will reject null inline arrays.
        var src = new CK_INFO
        {
            CryptokiVersion = new CK_VERSION { Major = [3], Minor = [2] },
            ManufacturerId = new byte[32],
            Flags = 0,
            LibraryDescription = new byte[32],
            LibraryVersion = new CK_VERSION { Major = [1], Minor = [0] },
        };
        for (int i = 0; i < 32; i++) src.ManufacturerId[i] = (byte)'A';

        int size = Pkcs11Marshal.SizeOf<CK_INFO>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Pkcs11Marshal.WriteStructure(ptr, src);
            var rt = Pkcs11Marshal.ReadStructure<CK_INFO>(ptr);
            Assert.Equal(3, rt.CryptokiVersion.Major[0]);
            Assert.Equal(2, rt.CryptokiVersion.Minor[0]);
            Assert.Equal((byte)'A', rt.ManufacturerId[0]);
            Assert.Equal((byte)'A', rt.ManufacturerId[31]);
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `dotnet test src/KerckhoffsLabs.sln --filter "FullyQualifiedName~Pkcs11MarshalTests" --no-build`
Expected: 4 passed.

- [ ] **Step 3: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/Pkcs11MarshalTests.cs
git commit -m "test(native): Pkcs11Marshal round-trips CK_VERSION and CK_INFO"
```

---

## Phase 4 — `MarshalSizeOfTests` regression suite

### Task 12: Pin sizes for every CK_* struct on Linux; write (currently-skipped) Windows assertions

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/MarshalSizeOfTests.cs`

- [ ] **Step 1: Compute the Linux baseline sizes once**

Run a one-shot probe to capture the current sizes:

```bash
mkdir -p /tmp/sz && cat > /tmp/sz/probe.csproj <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="/home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj" />
  </ItemGroup>
</Project>
EOF
cat > /tmp/sz/Program.cs <<'EOF'
using System;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
void P(string n, Type t) => Console.WriteLine($"        [InlineData(typeof({n}), {Marshal.SizeOf(t)})]");
P("CK_VERSION", typeof(CK_VERSION));
P("CK_INFO", typeof(CK_INFO));
P("CK_SLOT_INFO", typeof(CK_SLOT_INFO));
P("CK_TOKEN_INFO", typeof(CK_TOKEN_INFO));
P("CK_SESSION_INFO", typeof(CK_SESSION_INFO));
P("CK_MECHANISM", typeof(CK_MECHANISM));
P("CK_MECHANISM_INFO", typeof(CK_MECHANISM_INFO));
P("CK_ATTRIBUTE", typeof(CK_ATTRIBUTE));
P("CK_C_INITIALIZE_ARGS", typeof(CK_C_INITIALIZE_ARGS));
P("CK_RSA_PKCS_OAEP_PARAMS", typeof(CK_RSA_PKCS_OAEP_PARAMS));
P("CK_RSA_PKCS_PSS_PARAMS", typeof(CK_RSA_PKCS_PSS_PARAMS));
P("CK_GCM_PARAMS", typeof(CK_GCM_PARAMS));
P("CK_CCM_PARAMS", typeof(CK_CCM_PARAMS));
P("CK_ECDH1_DERIVE_PARAMS", typeof(CK_ECDH1_DERIVE_PARAMS));
P("CK_HKDF_PARAMS", typeof(CK_HKDF_PARAMS));
EOF
cd /tmp/sz && dotnet run 2>&1 | grep InlineData
```

Expected output: a list of `[InlineData(typeof(CK_INFO), 88)]`-style lines. Copy them.

- [ ] **Step 2: Replace `MarshalSizeOfTests.cs` with the parameterized suite**

Path: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/MarshalSizeOfTests.cs`

```csharp
using System;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using Xunit;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Internal;

/// <summary>
/// Pins the marshalled size of every native interop struct, separately per platform.
/// Catches BL-001-class struct-layout drift the moment it lands. The Unix expected values
/// were captured from a probe on Linux x64 at plan-creation time. The Windows expected
/// values are the OASIS pkcs11.h spec ABI (#pragma pack(push, 1)).
/// </summary>
public sealed class MarshalSizeOfTests
{
    [Theory]
    // PASTE THE OUTPUT FROM STEP 1 HERE — example structure:
    [InlineData(typeof(CK_VERSION), 2)]
    [InlineData(typeof(CK_INFO), 88)]
    // ... etc for every struct ...
    public void Unified_struct_size_on_unix(Type t, int expectedSize)
    {
        if (OperatingSystem.IsWindows()) return; // unified T is wrong on Windows; siblings cover that
        Assert.Equal(expectedSize, Marshal.SizeOf(t));
    }

    [Theory]
    // The Windows-sibling spec sizes — these come from OASIS pkcs11t.h #pragma pack(1)
    // and are computed by hand. Add an InlineData per struct.
    [InlineData("CK_VERSION_Windows", 2)]
    [InlineData("CK_INFO_Windows", 72)]                      // 2 + 32 + 4 + 32 + 2
    [InlineData("CK_ATTRIBUTE_Windows", 16)]                 // 4 + 8 + 4
    [InlineData("CK_MECHANISM_Windows", 16)]                 // 4 + 8 + 4
    [InlineData("CK_C_INITIALIZE_ARGS_Windows", 44)]         // 4 * 8 (fn ptrs) + 4 (flags) + 8 (reserved) → on x64 the ptrs are 8 bytes
    public void Windows_sibling_struct_size(string typeName, int expectedSize)
    {
        var t = typeof(CK_INFO).Assembly.GetType(
            "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native." + typeName)
            ?? typeof(CK_INFO).Assembly.GetType(
                "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams." + typeName);
        Assert.NotNull(t);
        Assert.Equal(expectedSize, Marshal.SizeOf(t!));
    }
}
```

Note: the Windows assertions are not platform-gated — `Marshal.SizeOf` returns the same answer regardless of the host OS (the layout is baked into the IL). So this suite passes on Linux today and pins the Windows ABI permanently. Expand the InlineData lines to cover every struct that gets migrated in Task 13.

- [ ] **Step 3: Run the suite**

Run: `dotnet test src/KerckhoffsLabs.sln --filter "FullyQualifiedName~MarshalSizeOfTests" --no-build`
Expected: All InlineData entries pass on Linux.

- [ ] **Step 4: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/MarshalSizeOfTests.cs
git commit -m "test(native): pin marshalled sizes for every CK_* struct, platform-aware"
```

---

## Phase 5 — Migrate decorated structs and marshal callsites

### Task 13: Migrate every `[PlatformSpecificPack]` struct to `[PackedForPkcs11]` + `[StructLayout(Sequential)]` + `partial`

**Files:**
- Modify: 100 files under `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/` and `Native/RawMechanismParams/` that currently use `[PlatformSpecificPack]`. List built by:
  ```bash
  grep -rln "PlatformSpecificPack" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/ --include="*.cs"
  ```

- [ ] **Step 1: For each file in the list above, apply this transformation**

Find:
```csharp
[PlatformSpecificPack]
public struct CK_FOO
```

Replace with:
```csharp
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_FOO
```

The `using System.Runtime.InteropServices;` directive is already present in every Native struct file — no using changes needed. `CK_VERSION.cs` and `CK_INFO.cs` were already migrated in Tasks 5 and 7; skip them.

Mechanical pattern, can be automated with:

```bash
for f in $(grep -rln "PlatformSpecificPack" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/ --include="*.cs"); do
  python3 - "$f" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s = re.sub(r'\[PlatformSpecificPack\]\s*\n(public\s+)struct (\w+)',
           r'[StructLayout(LayoutKind.Sequential)]\n[PackedForPkcs11]\n\1partial struct \2',
           s)
open(p, 'w').write(s)
PY
done
```

Review the changes with `git diff --stat src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/` before committing.

- [ ] **Step 2: Build the solution**

Run: `dotnet build src/KerckhoffsLabs.sln 2>&1 | tail -5`
Expected: `Build succeeded.` Any errors usually indicate a struct with a non-standard pattern (e.g., generic type, additional attributes) — fix those by hand using the same transformation.

- [ ] **Step 3: Verify generator now emits siblings for every struct**

Run: `dotnet build src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -p:EmitCompilerGeneratedFiles=true -p:CompilerGeneratedFilesOutputPath=obj/generated`
Then: `find src/KerckhoffsLabs.Security.Cryptography.Pkcs11/obj/generated -name "*_Windows.g.cs" | wc -l`
Expected: ≥ 100 (one per decorated struct).

- [ ] **Step 4: Run all tests**

Run: `dotnet test src/KerckhoffsLabs.sln --no-build --logger "console;verbosity=minimal" 2>&1 | tail -3`
Expected: same pass/fail counts as before this task (Linux behavior unchanged).

- [ ] **Step 5: Extend the `MarshalSizeOfTests` Theory entries**

For every newly migrated struct, add an `[InlineData(typeof(CK_X), N)]` line to `Unified_struct_size_on_unix` and an `[InlineData("CK_X_Windows", M)]` line to `Windows_sibling_struct_size`. Capture the Unix sizes with the probe from Task 12 Step 1 (extend the probe to enumerate every struct). Compute the Windows sizes by walking the struct fields with `Pack=1` rules.

- [ ] **Step 6: Re-run the suite to lock in the pins**

Run: `dotnet test src/KerckhoffsLabs.sln --filter "FullyQualifiedName~MarshalSizeOfTests"`
Expected: all entries pass.

- [ ] **Step 7: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/ src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Internal/MarshalSizeOfTests.cs
git commit -m "refactor(native): migrate all CK_* structs to [PackedForPkcs11] + partial; pin sizes"
```

---

### Task 14: Replace `Marshal.X` callsites with `Pkcs11Marshal.X`

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/UnmanagedMemory.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/ObjectAttribute.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_C_INITIALIZE_ARGS.cs`

- [ ] **Step 1: In `UnmanagedMemory.cs`, route `Write(IntPtr, object)`, `Read(IntPtr, Type)`, `SizeOf(Type)` through `Pkcs11Marshal` when the type is a PKCS#11 packed struct**

Replace the existing implementations (lines around 153, 193, 256 — match by method signature):

```csharp
    public static int SizeOf(Type structureType)
    {
        ArgumentNullException.ThrowIfNull(structureType);
        // For [PackedForPkcs11]-marked types, dispatch to the platform-appropriate sibling.
        // For all other types, fall through to Marshal.SizeOf.
        if (structureType.IsValueType && IsPackedForPkcs11(structureType))
            return SizeOfPacked(structureType);
        return Marshal.SizeOf(structureType);
    }

    public static void Write(IntPtr memory, object structure)
    {
        if (memory == IntPtr.Zero) throw new ArgumentNullException(nameof(memory));
        ArgumentNullException.ThrowIfNull(structure);

        if (IsPackedForPkcs11(structure.GetType()))
            WritePacked(memory, structure);
        else
            Marshal.StructureToPtr(structure, memory, false);
    }

    public static object? Read(IntPtr memory, Type structureType)
    {
        if (memory == IntPtr.Zero) throw new ArgumentNullException(nameof(memory));
        ArgumentNullException.ThrowIfNull(structureType);

        if (structureType.IsValueType && IsPackedForPkcs11(structureType))
            return ReadPacked(memory, structureType);
        return Marshal.PtrToStructure(memory, structureType);
    }

    // ---- Packed-struct dispatch helpers ----

    private static bool IsPackedForPkcs11(Type t) =>
        t.IsDefined(typeof(PackedForPkcs11Attribute), inherit: false);

    private static int SizeOfPacked(Type t)
    {
        var winType = Pkcs11Marshal.IsWindows
            ? t.Assembly.GetType(t.FullName + "_Windows")
            : null;
        return Marshal.SizeOf(winType ?? t);
    }

    private static void WritePacked(IntPtr memory, object structure)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            var winType = structure.GetType().Assembly.GetType(structure.GetType().FullName + "_Windows");
            if (winType is not null)
            {
                var fromUnified = winType.GetMethod("FromUnified",
                    System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
                if (fromUnified is not null)
                {
                    object windowsBoxed = fromUnified.Invoke(null, [structure])!;
                    Marshal.StructureToPtr(windowsBoxed, memory, false);
                    return;
                }
            }
        }
        Marshal.StructureToPtr(structure, memory, false);
    }

    private static object? ReadPacked(IntPtr memory, Type t)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            var winType = t.Assembly.GetType(t.FullName + "_Windows");
            if (winType is not null)
            {
                object? winBoxed = Marshal.PtrToStructure(memory, winType);
                if (winBoxed is null) return null;
                var toUnified = winType.GetMethod("ToUnified",
                    System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);
                return toUnified?.Invoke(winBoxed, null);
            }
        }
        return Marshal.PtrToStructure(memory, t);
    }
```

- [ ] **Step 2: In `ObjectAttribute.cs`, find any direct `Marshal.SizeOf` / `Marshal.StructureToPtr` / `Marshal.PtrToStructure` callsites and route through `UnmanagedMemory.SizeOf` / `UnmanagedMemory.Write` / `UnmanagedMemory.Read` (which now dispatch correctly)**

Locate every `Marshal.SizeOf(typeof(CK_ATTRIBUTE))` and similar — replace with `UnmanagedMemory.SizeOf(typeof(CK_ATTRIBUTE))`. Same for `StructureToPtr`/`PtrToStructure`. The actual file `ObjectAttribute.cs` is ~400 lines; review with `grep -n "Marshal\.\(SizeOf\|StructureToPtr\|PtrToStructure\)" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/ObjectAttribute.cs` and replace each match.

- [ ] **Step 3: `CK_C_INITIALIZE_ARGS.cs` — same treatment**

Run: `grep -n "Marshal\.\(SizeOf\|StructureToPtr\|PtrToStructure\)" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_C_INITIALIZE_ARGS.cs`

For every match, replace with the `UnmanagedMemory.*` equivalent. Add a `using ...Native;` only if not already present (the file is in the Native namespace).

- [ ] **Step 4: Build and run all tests**

Run: `dotnet build src/KerckhoffsLabs.sln && dotnet test src/KerckhoffsLabs.sln --no-build --logger "console;verbosity=minimal" 2>&1 | tail -3`
Expected: same pass count as before (370 passed, 23 skipped is the current state); Linux behavior unchanged.

- [ ] **Step 5: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/UnmanagedMemory.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/ObjectAttribute.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_C_INITIALIZE_ARGS.cs
git commit -m "refactor(native): route all marshal callsites through Pkcs11Marshal dispatch"
```

---

## Phase 6 — P/Invoke dispatch for outer structs passed by `ref`

### Task 15: Add `_Windows` delegate variants in `Delegates.cs`

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs`

Twenty-seven delegates declare `ref CK_X` parameters or arrays of them (verified via `grep -c "ref CK_[A-Z]" Delegates.cs`). For each, add a parallel `*_WindowsDelegate` whose signature uses the `_Windows` sibling type. Concrete list (one line per affected delegate):

```
C_GetInfoDelegate            → C_GetInfoDelegate_Windows            (ref CK_INFO → ref CK_INFO_Windows)
C_GetSlotInfoDelegate        → C_GetSlotInfoDelegate_Windows        (ref CK_SLOT_INFO)
C_GetTokenInfoDelegate       → C_GetTokenInfoDelegate_Windows       (ref CK_TOKEN_INFO)
C_GetMechanismInfoDelegate   → C_GetMechanismInfoDelegate_Windows   (ref CK_MECHANISM_INFO)
C_GetSessionInfoDelegate     → C_GetSessionInfoDelegate_Windows     (ref CK_SESSION_INFO)
C_EncryptInitDelegate        → C_EncryptInitDelegate_Windows        (ref CK_MECHANISM)
C_DecryptInitDelegate        → C_DecryptInitDelegate_Windows
C_DigestInitDelegate         → C_DigestInitDelegate_Windows
C_SignInitDelegate           → C_SignInitDelegate_Windows
C_SignRecoverInitDelegate    → C_SignRecoverInitDelegate_Windows
C_VerifyInitDelegate         → C_VerifyInitDelegate_Windows
C_VerifyRecoverInitDelegate  → C_VerifyRecoverInitDelegate_Windows
C_GenerateKeyDelegate        → C_GenerateKeyDelegate_Windows        (ref CK_MECHANISM + CK_ATTRIBUTE[])
C_GenerateKeyPairDelegate    → C_GenerateKeyPairDelegate_Windows
C_WrapKeyDelegate            → C_WrapKeyDelegate_Windows
C_UnwrapKeyDelegate          → C_UnwrapKeyDelegate_Windows
C_DeriveKeyDelegate          → C_DeriveKeyDelegate_Windows
C_MessageEncryptInitDelegate → C_MessageEncryptInitDelegate_Windows
C_MessageDecryptInitDelegate → C_MessageDecryptInitDelegate_Windows
C_MessageSignInitDelegate    → C_MessageSignInitDelegate_Windows
C_MessageVerifyInitDelegate  → C_MessageVerifyInitDelegate_Windows
C_EncapsulateKeyDelegate     → C_EncapsulateKeyDelegate_Windows
C_DecapsulateKeyDelegate     → C_DecapsulateKeyDelegate_Windows
C_VerifySignatureInitDelegate→ C_VerifySignatureInitDelegate_Windows
C_AsyncCompleteDelegate      → C_AsyncCompleteDelegate_Windows      (ref CK_ASYNC_DATA)
C_WrapKeyAuthenticatedDelegate   → C_WrapKeyAuthenticatedDelegate_Windows
C_UnwrapKeyAuthenticatedDelegate → C_UnwrapKeyAuthenticatedDelegate_Windows
```

- [ ] **Step 1: For each delegate above, add the `_Windows` variant immediately below it**

Example pattern (apply to all 27):

```csharp
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetInfoDelegate(ref CK_INFO info);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetInfoDelegate_Windows(ref CK_INFO_Windows info);
```

For delegates that also take `CK_ATTRIBUTE[]`, substitute that too:

```csharp
internal delegate NativeCULong C_GenerateKeyDelegate(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GenerateKeyDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, CK_ATTRIBUTE_Windows[] template, NativeCULong count, ref NativeCULong key);
```

- [ ] **Step 2: Add parallel fields in the `Delegates` class**

Each delegate has a corresponding field in `Delegates.cs` (look for `internal C_GetInfoDelegate C_GetInfo` near line 1020). For each, add an optional `_Windows`-typed field right beside it:

```csharp
internal C_GetInfoDelegate C_GetInfo = null!;
internal C_GetInfoDelegate_Windows? C_GetInfo_Windows;
```

- [ ] **Step 3: In `Delegates.Initialize` / `TryLoadFromGetInterface` / `TryLoadV30Symbols`, populate the `_Windows` field from the same function pointer used to populate the unified one**

Pattern: every `GetDelegateForFunctionPointer<C_XDelegate>(ptr)` now also gets `_Windows = GetDelegateForFunctionPointer<C_XDelegate_Windows>(ptr)`. The two delegates dispatch the same native function pointer — only the managed signature differs.

Example, find lines like:
```csharp
C_GetInfo = (C_GetInfoDelegate)Marshal.GetDelegateForFunctionPointer(funcList.C_GetInfo, typeof(C_GetInfoDelegate));
```

Replace with:
```csharp
C_GetInfo = (C_GetInfoDelegate)Marshal.GetDelegateForFunctionPointer(funcList.C_GetInfo, typeof(C_GetInfoDelegate));
C_GetInfo_Windows = (C_GetInfoDelegate_Windows)Marshal.GetDelegateForFunctionPointer(funcList.C_GetInfo, typeof(C_GetInfoDelegate_Windows));
```

- [ ] **Step 4: Build**

Run: `dotnet build src/KerckhoffsLabs.sln 2>&1 | tail -5`
Expected: `Build succeeded.` (Errors usually point at struct-name typos in the new delegate signatures — fix per-error.)

- [ ] **Step 5: Tests still green**

Run: `dotnet test src/KerckhoffsLabs.sln --no-build --logger "console;verbosity=minimal" 2>&1 | tail -3`
Expected: same pass count (Linux uses the unified delegates; nothing exercises the `_Windows` ones yet).

- [ ] **Step 6: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs
git commit -m "feat(native): add _Windows delegate variants for all ref CK_X P/Invokes"
```

---

### Task 16: Dispatch in `LowLevelPkcs11Library` wrappers

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs`

Each public `C_*` method in `LowLevelPkcs11Library` that takes `ref CK_X` or `CK_X[]` parameters needs a Windows dispatch path.

- [ ] **Step 1: Refactor input-only structs (mechanism, attribute arrays)**

Pattern for `C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)`:

```csharp
public CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
{
    if (Pkcs11Marshal.IsWindows && _delegates!.C_EncryptInit_Windows is { } winFn)
    {
        var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
        return (CKR)(ulong)winFn(session, ref winMech, key);
    }
    return (CKR)(ulong)_delegates!.C_EncryptInit(session, ref mechanism, key);
}
```

Apply the same pattern to: `C_DecryptInit`, `C_DigestInit`, `C_SignInit`, `C_SignRecoverInit`, `C_VerifyInit`, `C_VerifyRecoverInit`, `C_MessageEncryptInit`, `C_MessageDecryptInit`, `C_MessageSignInit`, `C_MessageVerifyInit`, `C_VerifySignatureInit`.

- [ ] **Step 2: For mechanism + attribute-array methods, convert the array too**

Pattern for `C_GenerateKey(NativeCULong session, ref CK_MECHANISM mech, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong key)`:

```csharp
public CKR C_GenerateKey(NativeCULong session, ref CK_MECHANISM mech, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong key)
{
    if (Pkcs11Marshal.IsWindows && _delegates!.C_GenerateKey_Windows is { } winFn)
    {
        var winMech = CK_MECHANISM_Windows.FromUnified(in mech);
        var winTpl  = template is null ? null! : System.Array.ConvertAll(template, CK_ATTRIBUTE_Windows.FromUnified);
        return (CKR)(ulong)winFn(session, ref winMech, winTpl, count, ref key);
    }
    return (CKR)(ulong)_delegates!.C_GenerateKey(session, ref mech, template, count, ref key);
}
```

Apply to: `C_GenerateKey`, `C_GenerateKeyPair`, `C_DeriveKey`, `C_WrapKey`, `C_UnwrapKey`, `C_EncapsulateKey`, `C_DecapsulateKey`, `C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated`.

- [ ] **Step 3: For output structs (`C_GetInfo`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetSessionInfo`, `C_GetMechanismInfo`, `C_AsyncComplete`), the wrapper must copy the result back**

Pattern for `C_GetInfo(ref CK_INFO info)`:

```csharp
public CKR C_GetInfo(ref CK_INFO info)
{
    if (Pkcs11Marshal.IsWindows && _delegates!.C_GetInfo_Windows is { } winFn)
    {
        var winInfo = default(CK_INFO_Windows);
        var rv = winFn(ref winInfo);
        info = winInfo.ToUnified();
        return (CKR)(ulong)rv;
    }
    return (CKR)(ulong)_delegates!.C_GetInfo(ref info);
}
```

Apply to the five `C_Get*Info` methods and `C_AsyncComplete`.

- [ ] **Step 4: Find every `ref CK_*` caller of `LowLevelPkcs11Library` outside of the file itself**

Run: `grep -rn "C_[A-Z][a-zA-Z]*\s*(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/ --include="*.cs" | grep -v "//"` and verify none of them bypass the dispatcher (i.e. nobody calls `_delegates.C_X` directly outside `LowLevelPkcs11Library`). The `LowLevelPkcs11Library` wrappers are the single dispatch point.

- [ ] **Step 5: Build and test**

Run: `dotnet build src/KerckhoffsLabs.sln 2>&1 | tail -5`
Expected: `Build succeeded.`

Run: `dotnet test src/KerckhoffsLabs.sln --no-build --logger "console;verbosity=minimal" 2>&1 | tail -3`
Expected: same pass count as before (Linux ignores the Windows branch).

- [ ] **Step 6: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs
git commit -m "feat(native): dispatch C_* wrappers to Windows-layout delegates on Windows"
```

---

## Phase 7 — Fix Windows CI (BL-049)

### Task 17: Make Windows SoftHSM install mandatory and verifiable

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Read the current Windows install step**

Run: `grep -n -A 3 "Install SoftHSM2 (Windows)" .github/workflows/ci.yml`
Expected: shows `choco install -y softhsm` with `continue-on-error: true`.

- [ ] **Step 2: Replace it with a robust install + verification**

Replace the section in `.github/workflows/ci.yml` (the YAML around the existing `Install SoftHSM2 (Windows)` step) with:

```yaml
      - name: Install SoftHSM2 (Windows)
        if: runner.os == 'Windows'
        shell: pwsh
        run: |
          choco install -y softhsm --no-progress
          if (-not (Get-Command softhsm2-util.exe -ErrorAction SilentlyContinue))
          {
              # Locate the SoftHSM install and prepend to PATH for downstream steps.
              $candidate = (Get-ChildItem -Path 'C:\Program Files\SoftHSM2\bin\softhsm2-util.exe' -ErrorAction SilentlyContinue)
              if (-not $candidate) {
                  Write-Error "SoftHSM2 install did not produce softhsm2-util.exe"
                  exit 1
              }
              echo "$($candidate.DirectoryName)" >> $env:GITHUB_PATH
          }
          softhsm2-util.exe --version
```

The `continue-on-error: true` is removed. The PATH is fixed up if choco didn't already do it. `softhsm2-util.exe --version` fails the job on a broken install.

- [ ] **Step 3: Commit and push to a feature branch to verify CI**

```bash
git add .github/workflows/ci.yml
git commit -m "ci(windows): require softhsm2 install + version verification (closes BL-049)"
git push -u origin <feature-branch>
```

Then watch the CI run for the windows-latest leg. Expected: Windows job succeeds at the install step and proceeds to `dotnet test`.

---

### Task 18: Verify Windows tests now exercise the dispatcher

**Files:** none (this is a CI verification task)

- [ ] **Step 1: Inspect the Windows test run output for SoftHSM-backed tests**

In the GitHub Actions UI for the Windows job, search the test output for `_SoftHsm`. Expected: SoftHSM-backed tests run (no `[ConditionalFact skipped: SoftHsm unavailable]`).

- [ ] **Step 2: Confirm `MarshalSizeOfTests` passes on Windows**

In the Windows job logs, find `MarshalSizeOfTests`. Expected: all `Windows_sibling_struct_size` Theory entries pass.

- [ ] **Step 3: If anything fails, triage by size mismatch**

Common failure modes:
- A struct's expected Windows size in `MarshalSizeOfTests` is computed wrong by hand — fix the InlineData.
- A struct field used a non-substituted nested type (e.g., the generator didn't substitute because of a generic type) — extend the generator's `SubstituteFieldType` to handle the case.
- A `ref CK_X` callsite was missed in `LowLevelPkcs11Library` — search for `_delegates.C_` references that don't go through a dispatcher.

For each failure, write the fix, push, watch CI go green.

- [ ] **Step 4: Commit any fixes**

```bash
git add <files-touched>
git commit -m "fix(native): <specific issue found on Windows CI>"
```

---

## Phase 8 — Cleanup

### Task 19: Delete `PlatformSpecificPackAttribute`

**Files:**
- Delete: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PlatformSpecificPackAttribute.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` (drop the `<DefineConstants>WINDOWS</DefineConstants>` block)

- [ ] **Step 1: Confirm no source file still references the old attribute**

Run: `grep -rn "PlatformSpecificPack" src/`
Expected: zero matches.

- [ ] **Step 2: Delete the file**

Run: `git rm src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PlatformSpecificPackAttribute.cs`
Expected: file removed.

- [ ] **Step 3: Drop the `<DefineConstants>WINDOWS</DefineConstants>` block from the csproj**

In `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`, find and delete:

```xml
  <PropertyGroup Condition="'$(TargetPlatformIdentifier)' == 'windows'">
    <DefineConstants>WINDOWS</DefineConstants>
  </PropertyGroup>
```

- [ ] **Step 4: Build and test**

Run: `dotnet build src/KerckhoffsLabs.sln && dotnet test src/KerckhoffsLabs.sln --no-build --logger "console;verbosity=minimal" 2>&1 | tail -3`
Expected: `Build succeeded.` + same green test counts.

- [ ] **Step 5: Commit**

```bash
git add -u src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
git commit -m "chore(native): delete obsolete [PlatformSpecificPack] attribute"
```

---

### Task 20: Close BL-001 in `BACKLOG.md`

**Files:**
- Modify: `BACKLOG.md`

- [ ] **Step 1: Update the summary**

In `BACKLOG.md`'s `## Summary` section, decrement the Critical count from `4` to `3` and update the headline-risks bullet about packing to remove BL-001 (struct packing is now correct on every platform).

- [ ] **Step 2: Mark BL-001 as resolved**

Add a `**Status: Resolved (date YYYY-MM-DD)**` line near the top of the BL-001 item. Don't delete the item — preserve the historical record.

- [ ] **Step 3: Commit**

```bash
git add BACKLOG.md
git commit -m "docs(backlog): close BL-001 — struct packing source-gen + Windows CI in place"
```

---

## Self-Review

**1. Spec coverage:**
- (1) source-gen project — Task 1, 2.
- (2) `[PackedForPkcs11]` attribute — Task 3.
- (3) generator emits `T_Windows` with substituted fields — Tasks 5, 6, 7.
- (4) `Pkcs11Marshal` helpers — Tasks 9, 10, 11. Plus `UnmanagedMemory` wrappers in Task 14.
- (5) `Marshal.X` callsite migration — Tasks 13 (structs), 14 (callsites), 15–16 (P/Invoke dispatch).
- (6) `MarshalSizeOfTests` — Tasks 8, 12, 13 (extension).
- (7) Windows CI fix — Tasks 17, 18.
- All seven spec bullets are covered.

**2. Placeholder scan:** no `TBD` / `TODO` / "similar to" / "for each struct, do …" without showing the steps. Migration tasks (13, 15, 16) name the structs/delegates explicitly and give the full transformation pattern per case.

**3. Type consistency:** `Pkcs11Marshal`, `PackedForPkcs11Attribute`, `PackedStructsGenerator` referenced consistently. The generated convention `T_Windows`, the methods `FromUnified(in T)` and `ToUnified()`, the field name patterns — all match across Tasks 6, 9, 10, 14, 15, 16.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-15-pkcs11-struct-packing-source-gen.md`. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, automatic spec-compliance + code-quality review between tasks, fast iteration. Best for a 20-task plan like this.
2. **Inline Execution** — execute tasks in this session, batch with checkpoints at phase boundaries.

Which approach?
