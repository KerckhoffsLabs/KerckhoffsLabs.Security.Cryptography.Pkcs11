using System;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators;

internal sealed record ParamSpec(
    string Name,
    string ManagedType,
    RefKind RefKind,
    bool Unsized,
    bool FilledByToken,
    bool PackedStruct);

internal sealed record FunctionSpec(
    string Name,
    string Version,
    bool WindowsLayout,
    bool IsPartial,
    ImmutableArray<ParamSpec> Params);

/// <summary>
/// Builds a <see cref="FunctionSpec"/> from a <c>[Pkcs11Function]</c>-tagged method, or reports why
/// it cannot: every shape <see cref="DispatchEmitter"/> knows how to emit is validated here first, so
/// a declaration the emitter cannot handle is a build error instead of silently wrong (or
/// non-compiling) generated code.
/// </summary>
internal static class DispatchModel
{
    private const string UnsizedAttr = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.UnsizedAttribute";
    private const string FilledAttr = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.FilledByTokenAttribute";
    private const string PackedAttr = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.PackedForPkcs11Attribute";

    private const string ReadOnlySpanByte = "System.ReadOnlySpan<byte>";
    private const string SpanByte = "System.Span<byte>";

    private const string HelpBase = "https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#";

    private static readonly DiagnosticDescriptor UnmappedType = new(
        "KLPKCS11011",
        title: "Parameter type has no interop mapping",
        messageFormat: "Parameter '{0}' of '{1}' has type '{2}', which the dispatch generator cannot map to a native argument",
        category: "Interop",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "The dispatch generator only knows how to marshal ReadOnlySpan<byte>/Span<byte>, " +
            "ReadOnlySpan<CK_ATTRIBUTE>/Span<CK_ATTRIBUTE> templates, bool, arrays and ref/out of an unmanaged " +
            "type, and any other unmanaged type by value. A parameter of any other shape — a reference type, " +
            "a managed type, or a ref struct other than the two spans above — has no native representation.",
        helpLinkUri: HelpBase + "KLPKCS11011");

    private static readonly DiagnosticDescriptor UnpairedOutputSpan = new(
        "KLPKCS11012",
        title: "Output span needs a paired length",
        messageFormat: "Parameter '{0}' of '{1}' is a Span<byte> not followed by 'out NativeCULong {0}Len'; the direction is ambiguous",
        category: "Interop",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "A Span<byte> that is the last parameter fills to its own capacity (the C_GenerateRandom " +
            "idiom) and needs no pairing. A Span<byte> anywhere else must be immediately followed by " +
            "'out NativeCULong' so the token can report how much of the buffer it actually wrote; anything else " +
            "in that position means the pairing was intended but the shape is wrong.",
        helpLinkUri: HelpBase + "KLPKCS11012");

    private static readonly DiagnosticDescriptor MisplacedAnnotation = new(
        "KLPKCS11013",
        title: "Annotation does not apply to this parameter shape",
        messageFormat: "[{0}] on parameter '{1}' of '{2}' does not apply to a parameter of type '{3}'",
        category: "Interop",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "[Unsized] only applies to a ReadOnlySpan<byte> (it suppresses the trailing length " +
            "argument for a fixed-width field or NUL-terminated string). [FilledByToken] only applies to a " +
            "ref or out parameter of a [PackedForPkcs11] struct (it selects the Windows write-back arm). " +
            "Either attribute on any other parameter shape is silently ignored by the emitter, which is " +
            "exactly the kind of guess this generator refuses to make.",
        helpLinkUri: HelpBase + "KLPKCS11013");

    private static readonly DiagnosticDescriptor WindowsLayoutMismatch = new(
        "KLPKCS11014",
        title: "WindowsLayout disagrees with the parameters",
        messageFormat: "'{0}' {1}; a packed struct parameter and WindowsLayout must agree, or the Windows struct layout is silently wrong",
        category: "Interop",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "WindowsLayout = true emits a Pack=1 twin field and a conversion arm; it is pointless " +
            "without a [PackedForPkcs11] parameter (directly, as a span element, or as an array element) to " +
            "convert. Conversely, a [PackedForPkcs11] parameter without WindowsLayout = true means the call " +
            "unpacks the struct with the unified (non-Pack=1) layout on Windows — a struct-layout bug that " +
            "compiles cleanly and is invisible to this repository's Linux CI.",
        helpLinkUri: HelpBase + "KLPKCS11014");

    private static readonly DiagnosticDescriptor UnrecognizedVersion = new(
        "KLPKCS11015",
        title: "Unrecognized Cryptoki version",
        messageFormat: "'{0}' declares [Pkcs11Function] with an unrecognized Cryptoki version ({1}); add it to DispatchModel's version mapping instead of guessing",
        category: "Interop",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "The version argument selects which native function-list the pointer is bound from " +
            "(CK_FUNCTION_LIST / _3_0 / _3_2). A Cryptoki enum member the generator does not recognize would " +
            "otherwise fall through to a default and bind from the wrong table silently.",
        helpLinkUri: HelpBase + "KLPKCS11015");

    /// <summary>
    /// Validates and builds the spec for one <c>[Pkcs11Function]</c> declaration. Every diagnosable
    /// problem is reported (not just the first) so a broken declaration is fixed in one pass; returns
    /// <see langword="false"/> if anything was reported, in which case <paramref name="spec"/> is
    /// meaningless and the caller must skip the function rather than emit from it.
    /// </summary>
    internal static bool TryBuild(IMethodSymbol m, Action<Diagnostic> report, out FunctionSpec spec)
    {
        spec = null!;
        bool ok = true;

        var attr = m.GetAttributes().First(a =>
            a.AttributeClass?.ToDisplayString() == DispatchGenerator.AttributeFullName);

        // Binder/HasProperty/InitializeAssignment all derive their generated member names from
        // f.Name.Substring(2), assuming the "C_" prefix every cryptoki function name carries. This
        // is not one of the five diagnosable shapes above: [Pkcs11Function] is internal and used
        // nowhere but Delegates.cs, so a non-"C_" name can only be a same-file authoring mistake, not
        // a shape a caller legitimately explores. A thrown exception fails the generator (and so the
        // build) immediately rather than silently emitting a malformed "Bind" method name.
        if (!m.Name.StartsWith("C_", StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"[Pkcs11Function] on '{m.Name}' does not start with \"C_\"; DispatchEmitter's " +
                "Binder/HasProperty/InitializeAssignment derive generated member names from this prefix.");

        string version;
        if (attr.ConstructorArguments.Length == 0)
        {
            // No constructor argument reached the generator — most likely a compilation already in
            // error (the constructor parameter has no default, so this cannot happen in valid code).
            // Falling back to V240 preserves the original defensive behavior rather than cascading a
            // second, misleading diagnostic on top of whatever CS error already fired.
            version = "V240";
        }
        else
        {
            object? raw = attr.ConstructorArguments[0].Value;
            string? mapped = raw switch { 0 => "V240", 1 => "V300", 2 => "V320", _ => null };
            if (mapped is null)
            {
                report(Diagnostic.Create(UnrecognizedVersion, Loc(m), m.Name, raw?.ToString() ?? "<none>"));
                ok = false;
                mapped = "V240"; // placeholder; spec is discarded since ok is false
            }
            version = mapped;
        }

        bool windows = attr.NamedArguments
            .Any(kv => kv.Key == "WindowsLayout" && kv.Value.Value is true);

        var paramsBuilder = ImmutableArray.CreateBuilder<ParamSpec>(m.Parameters.Length);
        bool anyPacked = false;
        string? packedParamName = null;

        foreach (IParameterSymbol p in m.Parameters)
        {
            string managedType = p.Type.ToDisplayString();
            bool unsized = p.GetAttributes().Any(a => a.AttributeClass?.ToDisplayString() == UnsizedAttr);
            bool filled = p.GetAttributes().Any(a => a.AttributeClass?.ToDisplayString() == FilledAttr);
            bool packedStruct = IsPackedForPkcs11(p.Type);

            if (!IsSupportedShape(p, managedType))
            {
                report(Diagnostic.Create(UnmappedType, Loc(p), p.Name, m.Name, managedType));
                ok = false;
            }

            if (unsized && managedType != ReadOnlySpanByte)
            {
                report(Diagnostic.Create(MisplacedAnnotation, Loc(p), "Unsized", p.Name, m.Name, managedType));
                ok = false;
            }
            if (filled && !IsPackedRefOrOut(p))
            {
                report(Diagnostic.Create(MisplacedAnnotation, Loc(p), "FilledByToken", p.Name, m.Name, managedType));
                ok = false;
            }

            if (CarriesPackedStruct(p))
            {
                anyPacked = true;
                packedParamName ??= p.Name;
            }

            paramsBuilder.Add(new ParamSpec(p.Name, managedType, p.RefKind, unsized, filled, packedStruct));
        }

        ImmutableArray<ParamSpec> ps = paramsBuilder.MoveToImmutable();

        // KLPKCS11012: a Span<byte> that isn't the last parameter and isn't immediately followed by
        // 'out NativeCULong' has nowhere for the token to report how much it wrote. A trailing
        // Span<byte> is exempt — C_GenerateRandom fills the buffer to its own capacity and reports
        // nothing back, which is unambiguous precisely because nothing else follows it to confuse the
        // pairing with.
        for (int i = 0; i < ps.Length - 1; i++)
        {
            if (ps[i].ManagedType != SpanByte) continue;
            ParamSpec next = ps[i + 1];
            bool paired = next.RefKind == RefKind.Out && SimpleName(next.ManagedType) == "NativeCULong";
            if (!paired)
            {
                report(Diagnostic.Create(UnpairedOutputSpan, Loc(m.Parameters[i]), ps[i].Name, m.Name));
                ok = false;
            }
        }

        // KLPKCS11014, both directions.
        if (windows && !anyPacked)
        {
            report(Diagnostic.Create(WindowsLayoutMismatch, Loc(m), m.Name,
                "declares WindowsLayout but has no packed struct parameter"));
            ok = false;
        }
        else if (!windows && anyPacked)
        {
            report(Diagnostic.Create(WindowsLayoutMismatch, Loc(m), m.Name,
                $"has packed struct parameter '{packedParamName}' but does not declare WindowsLayout"));
            ok = false;
        }

        if (!ok) return false;

        spec = new FunctionSpec(m.Name, version, windows, m.IsPartialDefinition, ps);
        return true;
    }

    /// <summary>
    /// True for every parameter shape <see cref="DispatchEmitter"/> knows how to turn into a native
    /// argument: a ref/out or array of an unmanaged type (the same test the C# 'unmanaged' constraint
    /// and 'fixed' both use — it is what makes a type safe to pin and pass as a pointer), the two
    /// attribute-template spans, ReadOnlySpan/Span&lt;byte&gt;, bool, or any other unmanaged type by
    /// value.
    /// </summary>
    private static bool IsSupportedShape(IParameterSymbol p, string managedType)
    {
        // in / ref readonly are not one of the shapes DispatchEmitter knows how to emit: it has no
        // RefKind.In case, so a parameter of this kind would fall through to the plain by-value
        // branch below and be passed BY VALUE into a delegate* unmanaged[Cdecl]<...> where cryptoki
        // expects a POINTER — a silent ABI mismatch. Rejected outright rather than silently
        // accepted and mis-emitted: nothing in the real declarations uses in/ref readonly, and
        // DispatchEmitter has no conversion path that would make supporting it worthwhile today.
        if (p.RefKind is RefKind.In or RefKind.RefReadOnlyParameter)
            return false;

        if (p.RefKind is RefKind.Ref or RefKind.Out)
            return p.Type.IsUnmanagedType;

        if (IsAttributeTemplate(p.Type)) return true;
        if (managedType is ReadOnlySpanByte or SpanByte) return true;
        if (managedType == "bool") return true;
        if (p.Type is IArrayTypeSymbol array) return array.ElementType.IsUnmanagedType;

        return p.Type.IsUnmanagedType;
    }

    /// <summary>
    /// A ref/out/in/ref-readonly parameter of a struct carrying <c>[PackedForPkcs11]</c> — the only
    /// shape [FilledByToken] applies to. in/ref readonly are included here (and in
    /// <see cref="CarriesPackedStruct"/>) purely so a packed struct passed that way is still
    /// recognized as packed for these two checks; <see cref="IsSupportedShape"/> separately rejects
    /// in/ref readonly outright, so a declaration using one never reaches the emitter regardless.
    /// </summary>
    private static bool IsPackedRefOrOut(IParameterSymbol p) =>
        p.RefKind is RefKind.Ref or RefKind.Out or RefKind.In or RefKind.RefReadOnlyParameter
        && IsPackedForPkcs11(p.Type);

    /// <summary>
    /// True when a parameter's type carries a <c>[PackedForPkcs11]</c> struct somewhere WindowsLayout
    /// needs to convert it: directly (<c>ref CK_MECHANISM</c>, or in/ref readonly of one), as a span
    /// element (<c>ReadOnlySpan&lt;CK_ATTRIBUTE&gt;</c>), or as an array element
    /// (<c>CK_INTERFACE[]?</c>).
    /// </summary>
    private static bool CarriesPackedStruct(IParameterSymbol p)
    {
        if (p.RefKind is RefKind.Ref or RefKind.Out or RefKind.In or RefKind.RefReadOnlyParameter
            && IsPackedForPkcs11(p.Type)) return true;
        if (TryGetSpanElementType(p.Type, out ITypeSymbol spanElement) && IsPackedForPkcs11(spanElement)) return true;
        if (p.Type is IArrayTypeSymbol array && IsPackedForPkcs11(array.ElementType)) return true;
        return false;
    }

    private static bool IsPackedForPkcs11(ITypeSymbol t) =>
        t.GetAttributes().Any(a => a.AttributeClass?.ToDisplayString() == PackedAttr);

    /// <summary>Matches the attribute-template shape: a Span or ReadOnlySpan of exactly CK_ATTRIBUTE.</summary>
    private static bool IsAttributeTemplate(ITypeSymbol t) =>
        TryGetSpanElementType(t, out ITypeSymbol element) && element.Name == "CK_ATTRIBUTE";

    private static bool TryGetSpanElementType(ITypeSymbol t, out ITypeSymbol element)
    {
        if (t is INamedTypeSymbol { IsGenericType: true, TypeArguments.Length: 1 } named
            && named.ContainingNamespace?.ToDisplayString() == "System"
            && named.Name is "Span" or "ReadOnlySpan")
        {
            element = named.TypeArguments[0];
            return true;
        }
        element = null!;
        return false;
    }

    /// <summary>
    /// Shortens a fully qualified <c>ToDisplayString()</c> spelling back to what <c>Delegates.cs</c>
    /// wrote. Mirrors <see cref="DispatchEmitter"/>'s own helper of the same name — kept local rather
    /// than shared because it stays this three-line shape in both places and a shared helper would add
    /// an inter-file dependency for no benefit.
    /// </summary>
    private static string SimpleName(string managedType)
    {
        if (managedType.IndexOf('<') >= 0) return managedType;
        int dot = managedType.LastIndexOf('.');
        return dot < 0 ? managedType : managedType.Substring(dot + 1);
    }

    private static Location Loc(ISymbol s) => s.Locations.Length > 0 ? s.Locations[0] : Location.None;
}
