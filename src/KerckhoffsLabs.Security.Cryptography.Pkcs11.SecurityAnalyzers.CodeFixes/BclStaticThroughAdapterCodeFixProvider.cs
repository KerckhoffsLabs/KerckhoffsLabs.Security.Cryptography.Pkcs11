using System.Collections.Immutable;
using System.Composition;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Editing;
using Microsoft.CodeAnalysis.Simplification;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.SecurityAnalyzers.CodeFixes;

/// <summary>
/// Names the BCL type a static member really belongs to (KLPKCS11014 / KLPKCS11015):
/// <c>MLDsaPkcs11.GenerateKey(…)</c> becomes <c>MLDsa.GenerateKey(…)</c>.
/// </summary>
/// <remarks>
/// The call keeps doing exactly what it did; the fix only makes the software path visible at the
/// call site. Choosing the token-backed API instead is a design decision the fix cannot make. The
/// BCL type is written fully qualified and annotated, so the simplifier reduces it to its shortest
/// unambiguous form and adds the <c>using</c> directive when one is needed.
/// </remarks>
[ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(BclStaticThroughAdapterCodeFixProvider)), Shared]
public sealed class BclStaticThroughAdapterCodeFixProvider : CodeFixProvider
{
    // One key for every diagnostic, so Fix All rewrites a document's call sites in one pass.
    private const string EquivalenceKey = nameof(BclStaticThroughAdapterCodeFixProvider);

    public override ImmutableArray<string> FixableDiagnosticIds => ImmutableArray.Create(
        BclStaticThroughAdapterAnalyzer.FactoryDiagnosticId, BclStaticThroughAdapterAnalyzer.HelperDiagnosticId);

    public override FixAllProvider GetFixAllProvider() => WellKnownFixAllProviders.BatchFixer;

    public override async Task RegisterCodeFixesAsync(CodeFixContext context)
    {
        SyntaxNode? root = await context.Document.GetSyntaxRootAsync(context.CancellationToken).ConfigureAwait(false);
        SemanticModel? model = await context.Document.GetSemanticModelAsync(context.CancellationToken).ConfigureAwait(false);
        if (root is null || model is null)
            return;

        foreach (Fixable fixable in context.Diagnostics
            .Select(diagnostic => Resolve(root, model, diagnostic, context.CancellationToken))
            .OfType<Fixable>())
        {
            context.RegisterCodeFix(
                CodeAction.Create(
                    $"Call '{fixable.Declaring.Name}.{fixable.MemberName}' directly",
                    ct => QualifyAsync(context.Document, fixable.Access, fixable.Declaring, ct),
                    EquivalenceKey),
                fixable.Diagnostic);
        }
    }

    // The member access a diagnostic reports (`Adapter.Member`) and the BCL type that declares the member, or null
    // when the reported node is not a member access or its symbol cannot be resolved.
    private static Fixable? Resolve(SyntaxNode root, SemanticModel model, Diagnostic diagnostic, CancellationToken cancellationToken)
    {
        if (root.FindNode(diagnostic.Location.SourceSpan, getInnermostNodeForTie: true) is not MemberAccessExpressionSyntax access)
            return null;

        SymbolInfo info = model.GetSymbolInfo(access, cancellationToken);
        ISymbol? member = info.Symbol ?? (info.CandidateSymbols.Length > 0 ? info.CandidateSymbols[0] : null);
        return member?.ContainingType is INamedTypeSymbol declaring
            ? new Fixable(diagnostic, access, declaring, member.Name)
            : null;
    }

    private sealed class Fixable(Diagnostic diagnostic, MemberAccessExpressionSyntax access, INamedTypeSymbol declaring, string memberName)
    {
        public Diagnostic Diagnostic { get; } = diagnostic;
        public MemberAccessExpressionSyntax Access { get; } = access;
        public INamedTypeSymbol Declaring { get; } = declaring;
        public string MemberName { get; } = memberName;
    }

    private static async Task<Document> QualifyAsync(Document document, MemberAccessExpressionSyntax access, INamedTypeSymbol declaring, CancellationToken cancellationToken)
    {
        SyntaxNode? root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
        if (root is null)
            return document;

        TypeSyntax bcl = SyntaxFactory.ParseTypeName(declaring.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat))
            .WithAdditionalAnnotations(Simplifier.Annotation, Simplifier.AddImportsAnnotation);

        Document changed = document.WithSyntaxRoot(
            root.ReplaceNode(access.Expression, bcl.WithTriviaFrom(access.Expression)));
        changed = await ImportAdder.AddImportsAsync(changed, Simplifier.AddImportsAnnotation, cancellationToken: cancellationToken).ConfigureAwait(false);
        return await Simplifier.ReduceAsync(changed, Simplifier.Annotation, cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
