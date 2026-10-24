using System.Collections.Immutable;
using System.Composition;
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
/// Names the BCL type a static member really belongs to (KLPKCS11012 / KLPKCS11013):
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

        foreach (Diagnostic diagnostic in context.Diagnostics)
        {
            // The analyzer reports on the member access itself: `Adapter.Member`.
            if (root.FindNode(diagnostic.Location.SourceSpan, getInnermostNodeForTie: true) is not MemberAccessExpressionSyntax access)
                continue;

            SymbolInfo info = model.GetSymbolInfo(access, context.CancellationToken);
            ISymbol? member = info.Symbol ?? (info.CandidateSymbols.Length > 0 ? info.CandidateSymbols[0] : null);
            if (member?.ContainingType is not INamedTypeSymbol declaring)
                continue;

            context.RegisterCodeFix(
                CodeAction.Create(
                    $"Call '{declaring.Name}.{member.Name}' directly",
                    ct => QualifyAsync(context.Document, access, declaring, ct),
                    EquivalenceKey),
                diagnostic);
        }
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
