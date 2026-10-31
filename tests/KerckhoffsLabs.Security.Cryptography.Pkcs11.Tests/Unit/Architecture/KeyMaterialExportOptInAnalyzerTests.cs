using System.Collections.Immutable;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.SecurityAnalyzers;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Architecture;

/// <summary>
/// KLPKCS11012 marks every <see cref="KeyMaterialExportRule.Allow"/> call site, so an opt-in to reading
/// secrets off the token shows up in review and must be suppressed with a reason. The tests' own build
/// proves it fires (the suppressions there would otherwise be unused); these compile in-memory source
/// against the library to pin what it reports, where, and what it leaves alone.
/// </summary>
public sealed class KeyMaterialExportOptInAnalyzerTests
{
    private const string Usings =
        "using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;\n";

    [Fact]
    public async Task Allow_CallSite_ReportsKLPKCS11012()
    {
        const string call = "KeyMaterialExportRule.Allow([KeyMaterialExportKind.KdfOutput], \"HKDF in managed code\")";
        string source = Usings + $"static class C {{ static object M() => {call}; }}";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);

        Diagnostic diagnostic = Assert.Single(diagnostics);
        Assert.Equal("KLPKCS11012", diagnostic.Id);
        Assert.Equal(DiagnosticSeverity.Warning, diagnostic.Severity);
        Assert.Equal(call, source.Substring(diagnostic.Location.SourceSpan.Start, diagnostic.Location.SourceSpan.Length));
        Assert.Equal(
            "KeyMaterialExportRule.Allow lets this policy read KdfOutput off the token in the clear",
            diagnostic.GetMessage(System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public async Task Allow_SeveralConstantKinds_NamesEachInTheMessage()
    {
        string source = Usings +
            "static class C { static object M() => KeyMaterialExportRule.Allow(" +
            "new[] { KeyMaterialExportKind.EcdhSharedSecret, KeyMaterialExportKind.KemSharedSecret }, \"r\"); }";

        Diagnostic diagnostic = Assert.Single(await AnalyzeAsync(source));

        Assert.Equal(
            "KeyMaterialExportRule.Allow lets this policy read EcdhSharedSecret, KemSharedSecret off the token in the clear",
            diagnostic.GetMessage(System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public async Task Allow_KindsNotKnownAtCompileTime_SaysTheListedKinds()
    {
        string source = Usings +
            "static class C { static object M(KeyMaterialExportKind[] kinds) => KeyMaterialExportRule.Allow(kinds, \"r\"); }";

        Diagnostic diagnostic = Assert.Single(await AnalyzeAsync(source));

        Assert.Equal(
            "KeyMaterialExportRule.Allow lets this policy read the listed kinds off the token in the clear",
            diagnostic.GetMessage(System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public async Task Refuse_CallSite_ReportsNothing()
    {
        string source = Usings + "static class C { static object M() => KeyMaterialExportRule.Refuse(); }";

        Assert.Empty(await AnalyzeAsync(source));
    }

    [Fact]
    public async Task UnrelatedMethodNamedAllow_ReportsNothing()
    {
        string source = Usings +
            "static class KeyMaterialExportRule2 { public static object Allow(KeyMaterialExportKind[] k, string r) => r; }\n" +
            "namespace Other { static class KeyMaterialExportRule { public static object Allow(object k, string r) => r; } }\n" +
            "static class C { static object M() => KeyMaterialExportRule2.Allow([KeyMaterialExportKind.KdfOutput], \"r\");\n" +
            "  static object N() => Other.KeyMaterialExportRule.Allow(1, \"r\"); }";

        Assert.Empty(await AnalyzeAsync(source));
    }

    [Fact]
    public async Task LibraryNotReferenced_ReportsNothing()
    {
        string source = "static class KeyMaterialExportRule { public static object Allow(object k, string r) => r; }\n" +
            "static class C { static object M() => KeyMaterialExportRule.Allow(1, \"r\"); }";

        Assert.Empty(await AnalyzeAsync(source, referenceLibrary: false));
    }

    /// <summary>
    /// Compiles <paramref name="source"/> against the BCL (and the library) and returns the analyzer's
    /// diagnostics. The source must compile: an analyzer silent on code with errors proves nothing.
    /// </summary>
    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(string source, bool referenceLibrary = true)
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
            .Split(Path.PathSeparator)
            .Select(path => (MetadataReference)MetadataReference.CreateFromFile(path))
            .ToList();
        if (referenceLibrary)
            references.Add(MetadataReference.CreateFromFile(typeof(KeyMaterialExportRule).Assembly.Location));

        CSharpCompilation compilation = CSharpCompilation.Create(
            "AnalyzerUnderTest",
            [CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Latest), cancellationToken: TestContext.Current.CancellationToken)],
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable));

        Assert.Empty(compilation.GetDiagnostics(TestContext.Current.CancellationToken).Where(d => d.Severity == DiagnosticSeverity.Error));

        return await compilation
            .WithAnalyzers([new KeyMaterialExportOptInAnalyzer()])
            .GetAnalyzerDiagnosticsAsync(TestContext.Current.CancellationToken);
    }
}
