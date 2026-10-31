using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.SecurityAnalyzers;

/// <summary>
/// Reports every <c>KeyMaterialExportRule.Allow</c> call site (KLPKCS11012).
/// </summary>
/// <remarks>
/// <c>Allow</c> is the one way to let a policy read derived, agreed or encapsulated secrets off the token
/// in the clear. It is legitimate (a protocol that needs the bytes), so it is not <c>[Obsolete]</c>, but
/// every use deserves a reviewer's eye: the warning makes the opt-in visible in the build, and the
/// suppression that silences it is where its justification lives. At run time each allowed export also
/// logs a warning (<c>KeyMaterialExportAllowed</c>); this is the compile-time half of the same signal.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class KeyMaterialExportOptInAnalyzer : DiagnosticAnalyzer
{
    private const string RuleType = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.KeyMaterialExportRule";
    private const string KindType = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.KeyMaterialExportKind";
    private const string UnknownKinds = "the listed kinds";

    private static readonly DiagnosticDescriptor Rule = new(
        "KLPKCS11012",
        title: "Secret key material export opted in",
        messageFormat: "KeyMaterialExportRule.Allow lets this policy read {0} off the token in the clear",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description:
            "KeyMaterialExportRule.Allow opts a policy in to reading the named kinds of secret key material " +
            "(ECDH shared secrets, KEM shared secrets, KDF output) off the token into managed memory, where " +
            "the token can no longer protect them. Keep secrets on the token where you can (Derive to a " +
            "sensitive key, EncapsulateKey / DecapsulateKey). Where the bytes are genuinely needed, suppress " +
            "this diagnostic at the call site with a one-line justification.",
        helpLinkUri:
            "https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11012");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(start =>
        {
            INamedTypeSymbol? rule = start.Compilation.GetTypeByMetadataName(RuleType);
            INamedTypeSymbol? kind = start.Compilation.GetTypeByMetadataName(KindType);
            if (rule is null || kind is null)
                return;

            start.RegisterOperationAction(ctx => Analyze(ctx, rule, kind), OperationKind.Invocation);
        });
    }

    private static void Analyze(OperationAnalysisContext context, INamedTypeSymbol rule, INamedTypeSymbol kind)
    {
        var invocation = (IInvocationOperation)context.Operation;
        IMethodSymbol target = invocation.TargetMethod;
        if (target.Name != "Allow" || !SymbolEqualityComparer.Default.Equals(target.ContainingType, rule))
            return;

        context.ReportDiagnostic(Diagnostic.Create(Rule, invocation.Syntax.GetLocation(), DescribeKinds(invocation, kind)));
    }

    // The kinds as written, when every element is a KeyMaterialExportKind member named in the source
    // ([KeyMaterialExportKind.KdfOutput], new[] { ... }); anything else (a variable, a cast, a LINQ query)
    // is not known until run time.
    private static string DescribeKinds(IInvocationOperation invocation, INamedTypeSymbol kind)
    {
        IArgumentOperation? kindsArgument = invocation.Arguments.Where(a => a.Parameter?.Ordinal == 0).LastOrDefault();

        ImmutableArray<IOperation> elements = kindsArgument is null ? default : Elements(Unwrap(kindsArgument.Value));
        if (elements.IsDefaultOrEmpty)
            return UnknownKinds;

        var names = new string[elements.Length];
        for (int i = 0; i < elements.Length; i++)
        {
            if (Unwrap(elements[i]) is not IFieldReferenceOperation field
                || !SymbolEqualityComparer.Default.Equals(field.Field.ContainingType, kind))
                return UnknownKinds;
            names[i] = field.Field.Name;
        }
        return string.Join(", ", names);
    }

    private static ImmutableArray<IOperation> Elements(IOperation kinds) => kinds switch
    {
        ICollectionExpressionOperation collection => collection.Elements,
        IArrayCreationOperation { Initializer: { } initializer } => initializer.ElementValues,
        _ => default,
    };

    private static IOperation Unwrap(IOperation operation)
        => operation is IConversionOperation conversion ? Unwrap(conversion.Operand) : operation;
}
