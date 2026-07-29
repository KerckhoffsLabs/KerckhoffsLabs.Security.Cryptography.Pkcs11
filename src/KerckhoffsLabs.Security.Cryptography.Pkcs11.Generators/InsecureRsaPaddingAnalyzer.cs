using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators;

/// <summary>
/// Reports RSA <em>encryption</em> without OAEP (KLPKCS11008).
/// </summary>
/// <remarks>
/// The weak primitives that are types (MD5, DES, …) carry an <c>[Obsolete]</c> with a diagnostic id,
/// so a deliberate use can be suppressed precisely. RSAES-PKCS#1 v1.5 and raw RSA have no such
/// symbol to mark: the choice is a <em>value</em> — <c>RSAEncryptionPadding.Pkcs1</c> handed to a BCL
/// override, or <c>CKM_RSA_PKCS</c> / <c>CKM_RSA_X_509</c> handed to a <c>Mechanism</c> — so an
/// analyzer is the only way to give them the same compile-time signal. Both routes end at the same
/// runtime <c>AllowInsecure</c> gate.
/// <para>
/// Signatures are deliberately NOT reported: RSASSA-PKCS#1 v1.5 with a strong hash
/// (<c>CKM_SHA256_RSA_PKCS</c> …) is FIPS 186-5-approved and required by JWT RS256, TLS 1.2 and
/// X.509. Only the encryption/raw mechanisms carry the Bleichenbacher/ROBOT exposure.
/// </para>
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class InsecureRsaPaddingAnalyzer : DiagnosticAnalyzer
{
    private const string DiagnosticId = "KLPKCS11008";

    private const string RsaFacade = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.RSAPkcs11";
    private const string MechanismType = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Mechanism";
    private const string CkmType = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Common.CKM";
    private const string PaddingType = "System.Security.Cryptography.RSAEncryptionPadding";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "RSA encryption without OAEP padding",
        messageFormat:
            "'{0}' selects RSA encryption without OAEP, which is vulnerable to Bleichenbacher " +
            "padding-oracle attacks; use RSAEncryptionPadding.OaepSHA256 (CKM_RSA_PKCS_OAEP)",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description:
            "RSAES-PKCS#1 v1.5 and raw RSA encryption are gated at runtime by Pkcs11Workspace.AllowInsecure. " +
            "Suppress this diagnostic only alongside a documented reason to keep the legacy padding; " +
            "RSASSA-PKCS#1 v1.5 signatures with a strong hash are unaffected and remain allowed.",
        helpLinkUri:
            "https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11008");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(start =>
        {
            INamedTypeSymbol? rsa = start.Compilation.GetTypeByMetadataName(RsaFacade);
            INamedTypeSymbol? mechanism = start.Compilation.GetTypeByMetadataName(MechanismType);
            INamedTypeSymbol? ckm = start.Compilation.GetTypeByMetadataName(CkmType);
            INamedTypeSymbol? padding = start.Compilation.GetTypeByMetadataName(PaddingType);
            if (rsa is null && mechanism is null)
                return; // not a consumer of this library

            if (rsa is not null && padding is not null)
                start.RegisterOperationAction(ctx => AnalyzeRsaCall(ctx, rsa, padding), OperationKind.Invocation);

            if (mechanism is not null && ckm is not null)
                start.RegisterOperationAction(ctx => AnalyzeMechanism(ctx, mechanism, ckm), OperationKind.ObjectCreation);
        });
    }

    // RSAPkcs11.Encrypt/Decrypt(..., RSAEncryptionPadding.Pkcs1)
    [SuppressMessage("Major Code Smell", "S3267:Loops should be simplified with LINQ expressions",
        Justification = "These analyzers run an operation action on every object creation / invocation in the compilation, and again on each keystroke in the IDE. foreach over ImmutableArray<IArgumentOperation> uses the struct enumerator and allocates nothing, whereas Select boxes it into IEnumerable and allocates an iterator per call. Roslyn analyzer guidance is to keep LINQ off these paths, and the analyzers here follow it — System.Linq is imported only by the source generator, which runs far less often. The argument lists are one to three elements, so the LINQ form would trade a real allocation for no readability gain.")]
    private static void AnalyzeRsaCall(OperationAnalysisContext context, INamedTypeSymbol rsa, INamedTypeSymbol padding)
    {
        var invocation = (IInvocationOperation)context.Operation;
        IMethodSymbol target = invocation.TargetMethod;

        if (target.Name is not ("Encrypt" or "Decrypt"))
            return;
        if (!SymbolEqualityComparer.Default.Equals(target.ContainingType, rsa))
            return;

        foreach (IArgumentOperation argument in invocation.Arguments)
        {
            if (Unwrap(argument.Value) is IPropertyReferenceOperation property
                && property.Property.Name == "Pkcs1"
                && SymbolEqualityComparer.Default.Equals(property.Property.ContainingType, padding))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Rule, argument.Value.Syntax.GetLocation(), "RSAEncryptionPadding.Pkcs1"));
            }
        }
    }

    // new Mechanism(CKM.CKM_RSA_PKCS) / new Mechanism(CKM.CKM_RSA_X_509)
    [SuppressMessage("Major Code Smell", "S3267:Loops should be simplified with LINQ expressions",
        Justification = "These analyzers run an operation action on every object creation / invocation in the compilation, and again on each keystroke in the IDE. foreach over ImmutableArray<IArgumentOperation> uses the struct enumerator and allocates nothing, whereas Select boxes it into IEnumerable and allocates an iterator per call. Roslyn analyzer guidance is to keep LINQ off these paths, and the analyzers here follow it — System.Linq is imported only by the source generator, which runs far less often. The argument lists are one to three elements, so the LINQ form would trade a real allocation for no readability gain.")]
    private static void AnalyzeMechanism(OperationAnalysisContext context, INamedTypeSymbol mechanism, INamedTypeSymbol ckm)
    {
        var creation = (IObjectCreationOperation)context.Operation;
        if (!SymbolEqualityComparer.Default.Equals(creation.Type, mechanism))
            return;

        foreach (IArgumentOperation argument in creation.Arguments)
        {
            if (Unwrap(argument.Value) is IFieldReferenceOperation field
                && field.Field.Name is "CKM_RSA_PKCS" or "CKM_RSA_X_509"
                && SymbolEqualityComparer.Default.Equals(field.Field.ContainingType, ckm))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Rule, argument.Value.Syntax.GetLocation(), $"CKM.{field.Field.Name}"));
            }
        }
    }

    // Arguments reach the operation tree wrapped in conversions (e.g. enum → parameter type).
    private static IOperation Unwrap(IOperation operation)
        => operation is IConversionOperation conversion ? Unwrap(conversion.Operand) : operation;
}
