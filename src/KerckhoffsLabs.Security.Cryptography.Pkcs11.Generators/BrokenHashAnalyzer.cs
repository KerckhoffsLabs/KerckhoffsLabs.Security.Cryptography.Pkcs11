using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators;

/// <summary>
/// Reports a broken hash selected for a signature or MAC (KLPKCS11010).
/// </summary>
/// <remarks>
/// <c>SHA1Pkcs11</c> and <c>MD5Pkcs11</c> — the standalone digest façades — are <c>[Obsolete]</c>
/// (KLPKCS11002 / KLPKCS11001). But the same broken hashes reach the token as a <em>value</em>:
/// <c>rsa.SignData(data, HashAlgorithmName.SHA1, …)</c>, <c>new HMACPkcs11(key, HashAlgorithmName.MD5)</c>.
/// The BCL's <c>HashAlgorithmName.SHA1</c> is not a symbol this library can obsolete, so without this
/// analyzer those call sites compile clean and fail only at the runtime <c>AllowInsecure</c> gate
/// (<c>CKM_SHA1_RSA_PKCS</c>, <c>CKM_ECDSA_SHA1</c>, <c>CKM_SHA_1_HMAC</c> …).
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class BrokenHashAnalyzer : DiagnosticAnalyzer
{
    private const string HashNameType = "System.Security.Cryptography.HashAlgorithmName";
    private const string LibraryNamespace = "KerckhoffsLabs.Security.Cryptography.Pkcs11";

    /// <summary>Hashes that are collision-broken in signature / MAC contexts.</summary>
    public static readonly ImmutableHashSet<string> BrokenHashes = ImmutableHashSet.Create("MD5", "SHA1");

    private static readonly DiagnosticDescriptor Rule = new(
        "KLPKCS11010",
        title: "Broken hash in a signature or MAC",
        messageFormat:
            "'HashAlgorithmName.{0}' is collision-broken and is rejected for signatures and MACs; " +
            "use SHA256 or stronger",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description:
            "MD5 and SHA-1 are collision-broken (SHAttered), so signing or MACing with them is gated at " +
            "runtime by Pkcs11Workspace.AllowInsecure. Note that verifying an existing SHA-1 signature is " +
            "gated too: the mechanism guard is direction-agnostic. Suppress only alongside a documented " +
            "interop reason.",
        helpLinkUri:
            "https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11010");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(start =>
        {
            INamedTypeSymbol? hashName = start.Compilation.GetTypeByMetadataName(HashNameType);
            if (hashName is null)
                return;

            start.RegisterOperationAction(ctx => Analyze(ctx, hashName, ((IInvocationOperation)ctx.Operation).TargetMethod, ((IInvocationOperation)ctx.Operation).Arguments), OperationKind.Invocation);
            start.RegisterOperationAction(ctx => Analyze(ctx, hashName, ((IObjectCreationOperation)ctx.Operation).Constructor, ((IObjectCreationOperation)ctx.Operation).Arguments), OperationKind.ObjectCreation);
        });
    }

    [SuppressMessage("Major Code Smell", "S3267:Loops should be simplified with LINQ expressions",
        Justification = "These analyzers run an operation action on every object creation / invocation in the compilation, and again on each keystroke in the IDE. foreach over ImmutableArray<IArgumentOperation> uses the struct enumerator and allocates nothing, whereas Select boxes it into IEnumerable and allocates an iterator per call. Roslyn analyzer guidance is to keep LINQ off these paths, and the analyzers here follow it — System.Linq is imported only by the source generator, which runs far less often. The argument lists are one to three elements, so the LINQ form would trade a real allocation for no readability gain.")]
    private static void Analyze(
        OperationAnalysisContext context,
        INamedTypeSymbol hashName,
        IMethodSymbol? target,
        ImmutableArray<IArgumentOperation> arguments)
    {
        // Only calls into this library's façades: a broken hash handed to unrelated BCL code is not
        // ours to police, and the gate that would reject it is ours alone.
        if (target?.ContainingType is null || !IsLibraryType(target.ContainingType))
            return;

        foreach (IArgumentOperation argument in arguments)
        {
            if (Unwrap(argument.Value) is IPropertyReferenceOperation property
                && BrokenHashes.Contains(property.Property.Name)
                && SymbolEqualityComparer.Default.Equals(property.Property.ContainingType, hashName))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Rule, argument.Value.Syntax.GetLocation(), property.Property.Name));
            }
        }
    }

    private static bool IsLibraryType(INamedTypeSymbol type)
    {
        string? ns = type.ContainingNamespace?.ToDisplayString();
        return ns is not null
            && (ns == LibraryNamespace || ns.StartsWith(LibraryNamespace + ".", System.StringComparison.Ordinal));
    }

    private static IOperation Unwrap(IOperation operation)
        => operation is IConversionOperation conversion ? Unwrap(conversion.Operand) : operation;
}
