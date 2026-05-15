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
