using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators;

/// <summary>
/// Reports use of a broken, deprecated, or unauthenticated mechanism (KLPKCS11009).
/// </summary>
/// <remarks>
/// The weak primitives that have a façade type (MD5, DES, RC2 …) are <c>[Obsolete]</c>, but the same
/// mechanisms are reachable directly as <em>values</em> — <c>new Mechanism(CKM.CKM_AES_CBC)</c>, or
/// <c>AesPkcs11.Mode = CipherMode.CBC</c> — where there is no symbol to mark. Those routes reach the
/// same runtime <c>AllowInsecure</c> gate (<c>Pkcs11Session.GuardMechanism</c>) with no compile-time
/// warning at all; this analyzer supplies one. Unauthenticated AES modes are the common case: AES
/// itself is fine, so <c>AesPkcs11</c> is deliberately not obsolete.
/// <para>
/// RSA encryption without OAEP has its own id (KLPKCS11008) and is excluded here.
/// <see cref="InsecureMechanismData.GatedMechanisms"/> mirrors <c>GuardMechanism</c>'s set exactly; a test pins the two
/// together so they cannot drift.
/// </para>
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class InsecureMechanismAnalyzer : DiagnosticAnalyzer
{
    private const string MechanismType = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Mechanism";
    private const string CkmType = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Common.CKM";
    private const string AesFacade = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.AesPkcs11";
    private const string CipherModeType = "System.Security.Cryptography.CipherMode";


    private static readonly DiagnosticDescriptor Rule = new(
        "KLPKCS11009",
        title: "Broken, deprecated, or unauthenticated mechanism",
        messageFormat:
            "'{0}' is rejected by the secure-by-default policy ({1}); it throws " +
            "InsecureOperationException unless Pkcs11Workspace.AllowInsecure is set",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description:
            "Broken primitives (MD2/MD5/SHA-1, RC2/RC4, DES/3DES, SEED, CAST, RC5, Blowfish, Skipjack, " +
            "RIPEMD, DSA) and unauthenticated AES modes (ECB/CBC/CTR/CTS/OFB/CFB) are gated at runtime by " +
            "Pkcs11Workspace.AllowInsecure. Prefer authenticated AES (GCM/CCM) and SHA-2/SHA-3. Suppress " +
            "this diagnostic only alongside a documented interop reason.",
        helpLinkUri:
            "https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11009");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(start =>
        {
            INamedTypeSymbol? mechanism = start.Compilation.GetTypeByMetadataName(MechanismType);
            INamedTypeSymbol? ckm = start.Compilation.GetTypeByMetadataName(CkmType);
            INamedTypeSymbol? aes = start.Compilation.GetTypeByMetadataName(AesFacade);
            INamedTypeSymbol? cipherMode = start.Compilation.GetTypeByMetadataName(CipherModeType);

            if (mechanism is not null && ckm is not null)
                start.RegisterOperationAction(ctx => AnalyzeMechanism(ctx, mechanism, ckm), OperationKind.ObjectCreation);

            if (aes is not null && cipherMode is not null)
                start.RegisterOperationAction(ctx => AnalyzeAesMode(ctx, aes, cipherMode), OperationKind.SimpleAssignment);
        });
    }

    // new Mechanism(CKM.CKM_AES_CBC), new Mechanism(CKM.CKM_DES3_CBC), ...
    private static void AnalyzeMechanism(OperationAnalysisContext context, INamedTypeSymbol mechanism, INamedTypeSymbol ckm)
    {
        var creation = (IObjectCreationOperation)context.Operation;
        if (!SymbolEqualityComparer.Default.Equals(creation.Type, mechanism))
            return;

        foreach (IArgumentOperation argument in creation.Arguments)
        {
            if (Unwrap(argument.Value) is IFieldReferenceOperation field
                && InsecureMechanismData.GatedMechanisms.Contains(field.Field.Name)
                && SymbolEqualityComparer.Default.Equals(field.Field.ContainingType, ckm))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Rule, argument.Value.Syntax.GetLocation(), $"CKM.{field.Field.Name}", "broken or deprecated mechanism"));
            }
        }
    }

    // aes.Mode = CipherMode.CBC (on an AesPkcs11 instance)
    private static void AnalyzeAesMode(OperationAnalysisContext context, INamedTypeSymbol aes, INamedTypeSymbol cipherMode)
    {
        var assignment = (ISimpleAssignmentOperation)context.Operation;

        if (assignment.Target is not IPropertyReferenceOperation property
            || property.Property.Name != "Mode"
            || property.Instance is null
            || !SymbolEqualityComparer.Default.Equals(property.Instance.Type, aes))
            return;

        if (Unwrap(assignment.Value) is IFieldReferenceOperation field
            && InsecureMechanismData.WeakCipherModes.Contains(field.Field.Name)
            && SymbolEqualityComparer.Default.Equals(field.Field.ContainingType, cipherMode))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                Rule, assignment.Value.Syntax.GetLocation(),
                $"CipherMode.{field.Field.Name}", "unauthenticated AES mode: use GCM or CCM"));
        }
    }

    private static IOperation Unwrap(IOperation operation)
        => operation is IConversionOperation conversion ? Unwrap(conversion.Operand) : operation;
}
