using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators;

internal static class DispatchEmitter
{
    /// <summary>The out-length parameter paired with an output span, or null.</summary>
    internal static ParamSpec? PairedLength(FunctionSpec f, int index)
    {
        if (f.Params[index].ManagedType != "System.Span<byte>") return null;
        if (index + 1 >= f.Params.Length) return null;
        var next = f.Params[index + 1];
        // NativeCULong is reached only through a global using, so ToDisplayString() fully
        // qualifies it here just as it does for the ref/out case in NativeTypes — normalize
        // through Simple() before comparing, or every span looks unpaired.
        return next.RefKind == RefKind.Out && Simple(next.ManagedType) == "NativeCULong" ? next : null;
    }

    /// <summary>The native argument types a managed parameter expands to.</summary>
    internal static IEnumerable<string> NativeTypes(FunctionSpec f, int index)
    {
        var p = f.Params[index];
        switch (p.RefKind)
        {
            case RefKind.Ref or RefKind.Out:
                yield return Simple(p.ManagedType) + "*";
                yield break;
        }
        if (IsTemplate(p, out _))
        {
            yield return AttributeType + "*";
            yield return "NativeCULong";
            yield break;
        }
        if (p.ManagedType == "System.ReadOnlySpan<byte>")
        {
            yield return "byte*";
            if (!p.Unsized) yield return "NativeCULong";
            yield break;
        }
        if (p.ManagedType == "System.Span<byte>")
        {
            // A span paired with a trailing `out NativeCULong` contributes only the pointer —
            // the paired out-parameter's own ref/out case yields the NativeCULong* for the length.
            // An unpaired span (e.g. C_GenerateRandom) has no such out-parameter to carry the
            // capacity, so it is treated exactly like ReadOnlySpan<byte>: pointer plus length.
            yield return "byte*";
            if (PairedLength(f, index) is null) yield return "NativeCULong";
            yield break;
        }
        if (p.ManagedType == "bool") { yield return "byte"; yield break; }
        if (IsArray(p.ManagedType, out var elementType))
        {
            yield return Simple(elementType) + "*";
            yield break;
        }
        yield return Simple(p.ManagedType);
    }

    /// <summary>The expression passed for a managed parameter, given the pointer local bound for it.</summary>
    internal static IEnumerable<string> NativeArgs(FunctionSpec f, int index)
    {
        var p = f.Params[index];
        switch (p.RefKind)
        {
            case RefKind.Ref or RefKind.Out:
                yield return p.Name + "Ptr";
                yield break;
        }
        if (IsTemplate(p, out _))
        {
            yield return p.Name + "Ptr";
            yield return $"(NativeCULong){p.Name}.Length";
            yield break;
        }
        if (p.ManagedType == "System.ReadOnlySpan<byte>")
        {
            yield return p.Name + "Ptr";
            if (!p.Unsized) yield return $"(NativeCULong){p.Name}.Length";
            yield break;
        }
        if (p.ManagedType == "System.Span<byte>")
        {
            yield return p.Name + "Ptr";
            if (PairedLength(f, index) is null) yield return $"(NativeCULong){p.Name}.Length";
            yield break;
        }
        if (p.ManagedType == "bool") { yield return $"(byte)({p.Name} ? 1 : 0)"; yield break; }
        if (IsArray(p.ManagedType, out _))
        {
            yield return p.Name + "Ptr";
            yield break;
        }
        yield return p.Name;
    }

    /// <summary>`fixed` bindings a parameter needs, as (declaration text).</summary>
    internal static IEnumerable<string> Fixed(ParamSpec p)
    {
        if (p.RefKind is RefKind.Ref or RefKind.Out)
            yield return $"fixed ({Simple(p.ManagedType)}* {p.Name}Ptr = &{p.Name})";
        if (IsTemplate(p, out _))
            yield return $"fixed ({AttributeType}* {p.Name}Ptr = {p.Name})";
        if (p.ManagedType is "System.ReadOnlySpan<byte>" or "System.Span<byte>")
            yield return $"fixed (byte* {p.Name}Ptr = {p.Name})";
        if (IsArray(p.ManagedType, out var elementType))
            yield return $"fixed ({Simple(elementType)}* {p.Name}Ptr = {p.Name})";
    }

    /// <summary>The unified attribute-template element type, both arms pin a pointer to.</summary>
    private const string AttributeType = "CK_ATTRIBUTE";

    /// <summary>
    /// Shortens a fully qualified <c>ToDisplayString()</c> spelling back to what the hand-written
    /// wrapper used. Every named type Roslyn hands us is namespace-qualified, while
    /// <c>Delegates.cs</c> never wrote a qualifier — <c>NativeCULong</c> comes in through a global
    /// using and the <c>CK_*</c> structs share the generated file's own namespace. Generic spans
    /// keep their spelling: the type tests elsewhere compare against the qualified form.
    /// </summary>
    private static string Simple(string managedType)
    {
        if (managedType.IndexOf('<') >= 0) return managedType;
        int dot = managedType.LastIndexOf('.');
        return dot < 0 ? managedType : managedType.Substring(dot + 1);
    }

    /// <summary>
    /// Matches an array managed type (<c>T[]</c> or the nullable <c>T[]?</c> array parameters
    /// use for an optional buffer), yielding its element type when it does.
    /// </summary>
    private static bool IsArray(string managedType, out string elementType)
    {
        var t = managedType.EndsWith("?", System.StringComparison.Ordinal)
            ? managedType.Substring(0, managedType.Length - 1)
            : managedType;
        if (t.EndsWith("[]", System.StringComparison.Ordinal))
        {
            elementType = t.Substring(0, t.Length - 2);
            return true;
        }
        elementType = "";
        return false;
    }

    /// <summary>
    /// Matches an attribute template — a span of <c>CK_ATTRIBUTE</c>, which expands to a pointer
    /// plus its count. <paramref name="writable"/> is true for the <c>Span</c> form, the one the
    /// token writes back into.
    /// </summary>
    private static bool IsTemplate(ParamSpec p, out bool writable)
    {
        writable = p.ManagedType.StartsWith("System.Span<", System.StringComparison.Ordinal);
        return (writable || p.ManagedType.StartsWith("System.ReadOnlySpan<", System.StringComparison.Ordinal))
            && p.ManagedType.EndsWith(AttributeType + ">", System.StringComparison.Ordinal);
    }

    /// <summary>
    /// A <c>ref</c>/<c>out</c> struct the Windows arm converts instead of pinning. PackedStruct comes
    /// from DispatchModel's real <c>[PackedForPkcs11]</c> attribute check, not a "CK_" name-prefix
    /// guess — a packed struct that was ever named differently would otherwise be silently missed
    /// here while KLPKCS11014 (which does use the attribute) correctly demanded WindowsLayout for it,
    /// producing exactly the Windows-only struct-layout bug that diagnostic exists to prevent.
    /// </summary>
    private static bool IsPackedStruct(ParamSpec p) =>
        p.RefKind is RefKind.Ref or RefKind.Out && p.PackedStruct;

    /// <summary>
    /// Local holding the Pack=1 copy of a struct parameter: <c>winMech</c> for the mechanism the
    /// token reads, <c>win</c> for the struct it fills. A wrapper never takes two of either, so
    /// the two names never collide.
    /// </summary>
    private static string PackedLocal(ParamSpec p) => p.FilledByToken ? "win" : "winMech";

    /// <summary>
    /// Local holding the Pack=1 copy of a template. Only <c>C_GenerateKeyPair</c> passes two, and
    /// it names them for the key each belongs to; every other wrapper has a single template.
    /// </summary>
    private static string TemplateLocal(ParamSpec p) => p.Name switch
    {
        "publicKeyTemplate" => "winPub",
        "privateKeyTemplate" => "winPriv",
        _ => "winTpl",
    };

    internal static string NativeSignature(FunctionSpec f)
    {
        var parts = new List<string>();
        for (int i = 0; i < f.Params.Length; i++)
            parts.AddRange(NativeTypes(f, i));
        parts.Add("NativeCULong");
        return string.Join(", ", parts);
    }

    /// <summary>Retypes a native signature to the Pack=1 twin the Windows ABI expects.</summary>
    private static string Packed(string signature) =>
        Regex.Replace(signature, @"\bCK_[A-Z_0-9]+\b", m => m.Value + "_Windows");

    internal static string Field(FunctionSpec f)
    {
        var sb = new StringBuilder();
        sb.Append("    public delegate* unmanaged[Cdecl]<").Append(NativeSignature(f))
          .Append("> ").Append(f.Name).AppendLine(";");
        if (f.WindowsLayout)
            sb.Append("    public delegate* unmanaged[Cdecl]<").Append(Packed(NativeSignature(f)))
              .Append("> ").Append(f.Name).AppendLine("_Windows;");
        return sb.ToString();
    }

    /// <summary>
    /// The Windows arm: convert every packed struct at the boundary, call the Pack=1 twin bound
    /// from the same native address, then mirror back whatever the token wrote. Emitted as a
    /// guarded block ahead of the unified body, which stays exactly what it is everywhere else.
    /// </summary>
    internal static string WindowsArm(FunctionSpec f)
    {
        var conversions = new List<string>();
        var fixups = new List<string>();
        var args = new List<string>();
        // Write-backs carry their own indentation: the template mirror is a nested loop.
        var writeBacks = new List<string>();

        for (int i = 0; i < f.Params.Length; i++)
        {
            var p = f.Params[i];
            if (IsPackedStruct(p))
            {
                string local = PackedLocal(p);
                string packed = Simple(p.ManagedType) + "_Windows";
                if (p.FilledByToken)
                {
                    conversions.Add($"{packed} {local} = default;");
                    writeBacks.Add($"            {p.Name} = {local}.ToUnified();");
                }
                else
                {
                    conversions.Add($"{packed} {local} = {packed}.FromUnified(in {p.Name});");
                }
                args.Add("&" + local);
                continue;
            }
            if (IsTemplate(p, out bool writable))
            {
                string local = TemplateLocal(p);
                conversions.Add($"{AttributeType}_Windows[]? {local} = ToWindowsTemplate({p.Name});");
                fixups.Add($"fixed ({AttributeType}_Windows* {p.Name}Ptr = {local})");
                args.Add(p.Name + "Ptr");
                args.Add($"(NativeCULong){p.Name}.Length");
                if (writable)
                {
                    // The token writes the value and its length back into the packed copy, so
                    // mirror the result into the caller's template before returning.
                    writeBacks.Add($"            if ({local} is not null)");
                    writeBacks.Add($"                for (int i = 0; i < {local}.Length; i++)");
                    writeBacks.Add($"                    {p.Name}[i] = {local}[i].ToUnified();");
                }
                continue;
            }
            args.AddRange(NativeArgs(f, i));
            fixups.AddRange(Fixed(p));
        }

        var sb = new StringBuilder();
        sb.AppendLine("        if (Pkcs11Marshal.IsWindows)");
        sb.AppendLine("        {");
        sb.Append("            ThrowIfUnbound(_fp.").Append(f.Name).AppendLine("_Windows);");
        foreach (var c in conversions)
            sb.Append("            ").AppendLine(c);

        string call = $"_fp.{f.Name}_Windows({string.Join(", ", args)});";
        if (writeBacks.Count == 0)
        {
            // Nothing to mirror back: the call is the return statement.
            foreach (var fx in fixups)
                sb.Append("            ").AppendLine(fx);
            sb.Append(fixups.Count > 0 ? "                " : "            ").Append("return ").AppendLine(call);
        }
        else if (fixups.Count == 0)
        {
            sb.Append("            NativeCULong winRv = ").AppendLine(call);
        }
        else
        {
            // The write-backs outlive the `fixed` scope, so the status lands in a local first.
            sb.AppendLine("            NativeCULong winRv;");
            foreach (var fx in fixups)
                sb.Append("            ").AppendLine(fx);
            sb.Append("                winRv = ").AppendLine(call);
        }

        foreach (var w in writeBacks)
            sb.AppendLine(w);
        if (writeBacks.Count > 0)
            sb.AppendLine("            return winRv;");

        sb.AppendLine("        }");
        sb.AppendLine();
        return sb.ToString();
    }

    /// <summary>Availability check for an optional v3.0/v3.2 function: <c>HasC_X</c>.</summary>
    internal static string HasProperty(FunctionSpec f) =>
        $"    internal unsafe bool Has{f.Name} => _fp.{f.Name} is not null;\n";

    /// <summary>
    /// Per-function binder for an optional v3.0/v3.2 function: takes the raw entry-point address
    /// (<see cref="System.IntPtr.Zero"/> means "the token doesn't provide this function") and, when
    /// present, casts it into the dispatch table. A <see cref="FunctionSpec.WindowsLayout"/>
    /// function binds both the unified and Pack=1 pointer from the same address so the call site
    /// can pick the layout at dispatch time.
    /// </summary>
    internal static string Binder(FunctionSpec f)
    {
        string bare = f.Name.Substring(2);           // C_LoginUser -> LoginUser
        var sb = new StringBuilder();
        sb.Append("    private unsafe void Bind").Append(bare).AppendLine("(IntPtr address)");
        sb.AppendLine("    {");
        if (f.WindowsLayout)
        {
            sb.AppendLine("        if (address == IntPtr.Zero)");
            sb.AppendLine("            return;");
            sb.Append("        _fp.").Append(f.Name).Append(" = (delegate* unmanaged[Cdecl]<")
              .Append(NativeSignature(f)).AppendLine(">)address;");
            sb.Append("        _fp.").Append(f.Name).Append("_Windows = (delegate* unmanaged[Cdecl]<")
              .Append(Packed(NativeSignature(f))).AppendLine(">)address;");
        }
        else
        {
            sb.AppendLine("        if (address != IntPtr.Zero)");
            sb.Append("            _fp.").Append(f.Name).Append(" = (delegate* unmanaged[Cdecl]<")
              .Append(NativeSignature(f)).AppendLine(">)address;");
        }
        sb.AppendLine("    }");
        return sb.ToString();
    }

    /// <summary>
    /// Assigns a v2.40 field — and its Windows twin, when the function carries one — from the
    /// same-named slot of the <c>CK_FUNCTION_LIST</c> table read via <c>C_GetFunctionList</c>.
    /// Both casts read the same struct field; only the target pointer type differs.
    /// </summary>
    internal static string InitializeAssignment(FunctionSpec f)
    {
        var sb = new StringBuilder();
        sb.Append("        _fp.").Append(f.Name).Append(" = (delegate* unmanaged[Cdecl]<")
          .Append(NativeSignature(f)).Append(">)funcList.").Append(f.Name).AppendLine(";");
        if (f.WindowsLayout)
            sb.Append("        _fp.").Append(f.Name).Append("_Windows = (delegate* unmanaged[Cdecl]<")
              .Append(Packed(NativeSignature(f))).Append(">)funcList.").Append(f.Name).AppendLine(";");
        return sb.ToString();
    }

    /// <summary>Calls a v3.x function's binder with the address carried in a v3.0/v3.2 function-list table.</summary>
    internal static string TableBindCall(FunctionSpec f, string tableVar) =>
        $"        Bind{f.Name.Substring(2)}({tableVar}.{f.Name});\n";

    /// <summary>Calls a v3.x function's binder with the address an export resolver hands back.</summary>
    internal static string ResolverBindCall(FunctionSpec f) =>
        $"        Bind{f.Name.Substring(2)}(resolveExport(\"{f.Name}\"));\n";

    internal static string Body(FunctionSpec f)
    {
        var sb = new StringBuilder();
        var args = new List<string>();
        var fixups = new List<string>();
        for (int i = 0; i < f.Params.Length; i++)
        {
            args.AddRange(NativeArgs(f, i));
            fixups.AddRange(Fixed(f.Params[i]));
        }

        // Seed each out-length from its paired span's capacity before the guard, so the
        // token is told how much room it has to write into. Both arms need it, so it goes
        // ahead of the Windows branch.
        for (int i = 0; i < f.Params.Length; i++)
        {
            var paired = PairedLength(f, i);
            if (paired is not null)
                sb.Append("        ").Append(paired.Name)
                  .Append(" = (NativeCULong)").Append(f.Params[i].Name).AppendLine(".Length;");
        }

        if (f.WindowsLayout)
            sb.Append(WindowsArm(f));

        sb.Append("        ThrowIfUnbound(_fp.").Append(f.Name).AppendLine(");");

        // A wrapper whose only pin is the ref struct itself keeps that pin on the call line;
        // splitting a two-token statement across two lines only obscures it.
        string call = $"return _fp.{f.Name}({string.Join(", ", args)});";
        if (fixups.Count == 1 && f.Params.Any(IsPackedStruct))
        {
            sb.Append("        ").Append(fixups[0]).Append(' ').AppendLine(call);
            return sb.ToString();
        }

        foreach (var fx in fixups)
            sb.Append("        ").AppendLine(fx);
        sb.Append(fixups.Count > 0 ? "            " : "        ").AppendLine(call);
        return sb.ToString();
    }
}
