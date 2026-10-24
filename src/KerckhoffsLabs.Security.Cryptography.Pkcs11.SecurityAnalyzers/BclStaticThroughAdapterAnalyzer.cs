using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.SecurityAnalyzers;

/// <summary>
/// Reports a BCL static member reached through a PKCS#11 adapter type (KLPKCS11012 / KLPKCS11013).
/// </summary>
/// <remarks>
/// Every adapter derives from its BCL algorithm type (<c>MLDsaPkcs11 : MLDsa</c>,
/// <c>AesPkcs11 : Aes</c>, <c>SHA256Pkcs11 : SHA256</c> …), and C# resolves a static member through
/// the derived name as well as the declaring one. So <c>MLDsaPkcs11.GenerateKey(…)</c> compiles and
/// reads like a token operation, but it binds to <c>MLDsa.GenerateKey</c> and makes an exportable
/// software key; <c>AesPkcs11.Create()</c> returns a plain software <c>Aes</c>;
/// <c>MLKemPkcs11.IsSupported</c> reports the OS crypto library's support, not the token's. Nothing
/// the library declares is involved, so there is no symbol to mark obsolete.
/// <para>
/// Key factories, object factories and capability probes are KLPKCS11012 (Warning): the result is
/// a different object, or a different answer, from the one the adapter name promises. The remaining
/// inherited statics (<c>HashData</c>, <c>IsWeakKey</c>, <c>GetKeyWrapPaddedLength</c> …) compute
/// the same value either way and only run in software, so they are KLPKCS11013 (Info). An adapter is
/// any type in this library's assembly that derives from a <c>System.Security.Cryptography</c> type,
/// so a new adapter is covered without touching this analyzer.
/// </para>
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class BclStaticThroughAdapterAnalyzer : DiagnosticAnalyzer
{
    /// <summary>The id for a BCL key factory, object factory or capability probe.</summary>
    public const string FactoryDiagnosticId = "KLPKCS11012";

    /// <summary>The id for any other BCL static helper.</summary>
    public const string HelperDiagnosticId = "KLPKCS11013";

    private const string LibraryAssembly = "KerckhoffsLabs.Security.Cryptography.Pkcs11";

    private static readonly DiagnosticDescriptor FactoryRule = new(
        FactoryDiagnosticId,
        title: "BCL key factory or capability check reached through a PKCS#11 adapter type",
        messageFormat:
            "'{0}.{1}' calls '{2}.{1}', which {3}; name '{2}' if that is intended, otherwise create or " +
            "open the key on the token and wrap it in '{0}'",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description:
            "A PKCS#11 adapter derives from its BCL algorithm type, so the base type's static members are " +
            "also reachable through the adapter's name. GenerateKey, Import*, Create and IsSupported then " +
            "run the BCL's own implementation: they produce exportable software keys and objects that never " +
            "touch the token, or report the operating system's algorithm support rather than the token's.",
        helpLinkUri:
            "https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11012");

    private static readonly DiagnosticDescriptor HelperRule = new(
        HelperDiagnosticId,
        title: "BCL static helper reached through a PKCS#11 adapter type",
        messageFormat: "'{0}.{1}' calls '{2}.{1}', which {3}; name '{2}' to make that explicit",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Info,
        isEnabledByDefault: true,
        description:
            "A PKCS#11 adapter derives from its BCL algorithm type, so the base type's static members are " +
            "also reachable through the adapter's name. Static helpers such as HashData run in software, " +
            "never on the token; calling them through the BCL type says so.",
        helpLinkUri:
            "https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11013");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(FactoryRule, HelperRule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(start =>
        {
            if (!SeesLibrary(start.Compilation))
                return; // not a consumer of this library

            start.RegisterOperationAction(
                ctx =>
                {
                    // Implicit invocations (collection-initializer Add …) have no name expression of their own.
                    if (ctx.Operation.Syntax is InvocationExpressionSyntax invocation)
                        Analyze(ctx, ((IInvocationOperation)ctx.Operation).TargetMethod, invocation.Expression);
                },
                OperationKind.Invocation);
            start.RegisterOperationAction(
                ctx => Analyze(ctx, ((IMemberReferenceOperation)ctx.Operation).Member, ctx.Operation.Syntax),
                OperationKind.PropertyReference, OperationKind.FieldReference, OperationKind.EventReference, OperationKind.MethodReference);
        });
    }

    private static bool SeesLibrary(Compilation compilation)
    {
        if (compilation.AssemblyName == LibraryAssembly)
            return true;
        foreach (AssemblyIdentity reference in compilation.ReferencedAssemblyNames)
        {
            if (reference.Name == LibraryAssembly)
                return true;
        }
        return false;
    }

    // MLDsaPkcs11.GenerateKey(…), Alias.IsSupported, SHA256Pkcs11.HashData. `name` is the member's
    // name expression, never the invocation. Only a member access can name an adapter: a bare name
    // cannot, because `using static` imports only the members a type declares itself, never
    // inherited ones, and every adapter is sealed, so no consumer type inherits its base's statics
    // through it.
    private static void Analyze(OperationAnalysisContext context, ISymbol member, SyntaxNode name)
    {
        INamedTypeSymbol? declaring = member.ContainingType;
        if (!member.IsStatic || declaring is null || !IsCryptographyType(declaring))
            return;
        if (name is not MemberAccessExpressionSyntax access)
            return;
        if (IsInsideNameOf(context.Operation))
            return; // nameof(AesPkcs11.Create) names the member; nothing runs

        // The receiver as written: `MLDsaPkcs11`, `Pkcs11.Algorithms.MLDsaPkcs11`, `global::…`, or an
        // alias. The member is declared on the BCL type, so an adapter receiver is never its owner.
        if (context.Operation.SemanticModel?.GetSymbolInfo(access.Expression, context.CancellationToken).Symbol
            is not INamedTypeSymbol adapter || !IsAdapter(adapter))
            return;

        bool factory = IsFactory(member.Name);
        context.ReportDiagnostic(Diagnostic.Create(
            factory ? FactoryRule : HelperRule,
            access.GetLocation(),
            adapter.Name, member.Name, declaring.Name, Consequence(member.Name, declaring.Name, factory)));
    }

    private static bool IsAdapter(INamedTypeSymbol type)
    {
        if (type.ContainingAssembly?.Name != LibraryAssembly)
            return false;
        for (INamedTypeSymbol? baseType = type.BaseType; baseType is not null; baseType = baseType.BaseType)
        {
            if (IsCryptographyType(baseType))
                return true;
        }
        return false;
    }

    // System.Security.Cryptography or a namespace under it, compared without allocating a display string.
    private static bool IsCryptographyType(INamedTypeSymbol type)
    {
        for (INamespaceSymbol? ns = type.ContainingNamespace; ns is not null && !ns.IsGlobalNamespace; ns = ns.ContainingNamespace)
        {
            if (ns.Name == "Cryptography"
                && ns.ContainingNamespace is { Name: "Security" } security
                && security.ContainingNamespace is { Name: "System" } system
                && system.ContainingNamespace is { IsGlobalNamespace: true })
                return true;
        }
        return false;
    }

    private static bool IsInsideNameOf(IOperation operation)
    {
        for (IOperation? current = operation.Parent; current is not null; current = current.Parent)
        {
            if (current is INameOfOperation)
                return true;
        }
        return false;
    }

    private static bool IsFactory(string name)
        => name is "Create" or "GenerateKey" or "IsSupported"
            || name.StartsWith("Import", System.StringComparison.Ordinal);

    private static string Consequence(string name, string declaring, bool factory)
    {
        if (factory)
        {
            return name switch
            {
                "GenerateKey" => "generates an exportable software key in process memory, not a token key",
                "IsSupported" => $"reports whether the operating system supports {declaring}, not whether the token does",
                "Create" => $"returns a software {declaring} that never touches the token",
                _ => "loads the key into process memory as a software key, not onto the token",
            };
        }
        return name is "HashData" or "TryHashData" or "HashDataAsync"
            ? "hashes in software, not on the token"
            : $"is {declaring}'s own software helper and never touches the token";
    }
}
