using Microsoft.CodeAnalysis;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGen;

[Generator(LanguageNames.CSharp)]
public sealed class PackedStructsGenerator : IIncrementalGenerator
{
    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        context.RegisterPostInitializationOutput(static ctx =>
        {
            ctx.AddSource("__PackedStructsGenerator.SmokeTest.g.cs",
                "// PackedStructsGenerator: smoke output\n");
        });
    }
}
