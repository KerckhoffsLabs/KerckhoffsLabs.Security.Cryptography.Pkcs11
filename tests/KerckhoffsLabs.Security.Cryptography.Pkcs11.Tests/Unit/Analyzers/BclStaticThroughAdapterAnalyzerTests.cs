using System.Collections.Immutable;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.SecurityAnalyzers;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.SecurityAnalyzers.CodeFixes;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Analyzers;

/// <summary>
/// KLPKCS11012 / KLPKCS11013: a BCL static reached through an adapter's name, and the code fix that
/// names the BCL type instead. Snippets are compiled in memory against the real library, so every
/// adapter case below is one a consumer can actually write; the field, event and own-static cases
/// use a stand-in adapter assembly, since no BCL base declares a static field or event.
/// </summary>
public sealed class BclStaticThroughAdapterAnalyzerTests
{
    private const string Usings = """
        using System;
        using System.Security.Cryptography;
        using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

        """;

    private static readonly CSharpParseOptions ParseOptions = new(LanguageVersion.Latest);

    // SYSLIB5006: several ML-DSA / ML-KEM members are still evaluation-only in .NET 10.
    private static readonly CSharpCompilationOptions CompilationOptions =
        new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable)
            .WithSpecificDiagnosticOptions([new("SYSLIB5006", ReportDiagnostic.Suppress)]);

    // The shared framework the tests run on, plus nothing else: the library is added per test, so
    // the stand-in adapter assembly can take its name.
    private static readonly ImmutableArray<MetadataReference> Framework = LoadFramework();

    private static readonly MetadataReference Library =
        MetadataReference.CreateFromFile(typeof(Pkcs11Key).Assembly.Location);

    private static ImmutableArray<MetadataReference> LoadFramework()
    {
        string runtime = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        return [.. ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
            .Split(Path.PathSeparator)
            .Where(path => Path.GetDirectoryName(path) == runtime)
            .Select(path => (MetadataReference)MetadataReference.CreateFromFile(path))];
    }

    // -----------------------------------------------------------------------
    // KLPKCS11012 — key factories, object factories, capability checks
    // -----------------------------------------------------------------------

    [Fact]
    public async Task GenerateKey_ThroughTheAdapterName_IsAWarningNamingTheBclMember()
    {
        Diagnostic diagnostic = Assert.Single(await AnalyzeAsync(Usings + """
            static class C { static MLDsa M() => MLDsaPkcs11.GenerateKey(MLDsaAlgorithm.MLDsa65); }
            """));

        Assert.Equal(BclStaticThroughAdapterAnalyzer.FactoryDiagnosticId, diagnostic.Id);
        Assert.Equal(DiagnosticSeverity.Warning, diagnostic.Severity);
        Assert.Equal(
            "'MLDsaPkcs11.GenerateKey' calls 'MLDsa.GenerateKey', which generates an exportable software key in " +
            "process memory, not a token key; name 'MLDsa' if that is intended, otherwise create or open the key " +
            "on the token and wrap it in 'MLDsaPkcs11'",
            diagnostic.GetMessage(System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal("MLDsaPkcs11.GenerateKey", SourceAt(diagnostic));
    }

    [Theory]
    [InlineData("static MLDsa M(byte[] spki) => MLDsaPkcs11.ImportSubjectPublicKeyInfo(spki);",
        "MLDsaPkcs11.ImportSubjectPublicKeyInfo", "loads the key into process memory as a software key, not onto the token")]
    [InlineData("static MLKem M(string pem) => MLKemPkcs11.ImportFromPem(pem);",
        "MLKemPkcs11.ImportFromPem", "loads the key into process memory as a software key, not onto the token")]
    [InlineData("static Aes M() => AesPkcs11.Create();",
        "AesPkcs11.Create", "returns a software Aes that never touches the token")]
    [InlineData("static RSA M() => RSAPkcs11.Create(3072);",
        "RSAPkcs11.Create", "returns a software RSA that never touches the token")]
    [InlineData("static bool M() => MLKemPkcs11.IsSupported;",
        "MLKemPkcs11.IsSupported", "reports whether the operating system supports MLKem, not whether the token does")]
    [InlineData("static Func<MLDsaAlgorithm, MLDsa> M() => MLDsaPkcs11.GenerateKey;",
        "MLDsaPkcs11.GenerateKey", "generates an exportable software key in process memory, not a token key")]
    [InlineData("static MLDsa M() => global::KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MLDsaPkcs11.GenerateKey(MLDsaAlgorithm.MLDsa44);",
        "global::KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MLDsaPkcs11.GenerateKey", "generates an exportable software key in process memory, not a token key")]
    public async Task FactoryOrCapabilityMember_ThroughTheAdapterName_IsAWarning(string member, string reported, string consequence)
    {
        Diagnostic diagnostic = Assert.Single(await AnalyzeAsync(Usings + $"static class C {{ {member} }}"));

        Assert.Equal(BclStaticThroughAdapterAnalyzer.FactoryDiagnosticId, diagnostic.Id);
        Assert.Equal(reported, SourceAt(diagnostic));
        Assert.Contains(consequence, diagnostic.GetMessage(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Alias_IsReportedUnderTheAdapterItNames()
    {
        Diagnostic diagnostic = Assert.Single(await AnalyzeAsync(Usings + """
            using Signer = KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MLDsaPkcs11;
            static class C { static MLDsa M() => Signer.GenerateKey(MLDsaAlgorithm.MLDsa65); }
            """));

        Assert.Equal(BclStaticThroughAdapterAnalyzer.FactoryDiagnosticId, diagnostic.Id);
        Assert.StartsWith("'MLDsaPkcs11.GenerateKey' calls 'MLDsa.GenerateKey'",
            diagnostic.GetMessage(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------
    // KLPKCS11013 — pure software helpers
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData("static byte[] M(byte[] data) => SHA256Pkcs11.HashData(data);",
        "SHA256Pkcs11.HashData", "'SHA256Pkcs11.HashData' calls 'SHA256.HashData', which hashes in software, not on the token; name 'SHA256' to make that explicit")]
    [InlineData("static bool M(byte[] d, Span<byte> o) => SHA512Pkcs11.TryHashData(d, o, out _);",
        "SHA512Pkcs11.TryHashData", "'SHA512Pkcs11.TryHashData' calls 'SHA512.TryHashData', which hashes in software, not on the token; name 'SHA512' to make that explicit")]
    [InlineData("static int M() => AesPkcs11.GetKeyWrapPaddedLength(20);",
        "AesPkcs11.GetKeyWrapPaddedLength", "'AesPkcs11.GetKeyWrapPaddedLength' calls 'Aes.GetKeyWrapPaddedLength', which is Aes's own software helper and never touches the token; name 'Aes' to make that explicit")]
    public async Task PureHelper_ThroughTheAdapterName_IsInfo(string member, string reported, string message)
    {
        Diagnostic diagnostic = Assert.Single(await AnalyzeAsync(Usings + $"static class C {{ {member} }}"));

        Assert.Equal(BclStaticThroughAdapterAnalyzer.HelperDiagnosticId, diagnostic.Id);
        Assert.Equal(DiagnosticSeverity.Info, diagnostic.Severity);
        Assert.Equal(reported, SourceAt(diagnostic));
        Assert.Equal(message, diagnostic.GetMessage(System.Globalization.CultureInfo.InvariantCulture));
    }

    // -----------------------------------------------------------------------
    // Not reported
    // -----------------------------------------------------------------------

    [Theory]
    // The BCL type named directly: the call says what it does.
    [InlineData("static MLDsa M() => MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);")]
    [InlineData("static byte[] M(byte[] data) => SHA256.HashData(data);")]
    // Instance members run on the token.
    [InlineData("static byte[] M(MLDsaPkcs11 key) => key.ExportSubjectPublicKeyInfo();")]
    [InlineData("static int M(AesPkcs11 aes) => aes.KeySize;")]
    // nameof runs nothing.
    [InlineData("static string M() => nameof(AesPkcs11.Create);")]
    // Declared on System.Object, not on a cryptography type.
    [InlineData("static bool M(object a, object b) => SHA256Pkcs11.ReferenceEquals(a, b);")]
    // A library type that is not an adapter: its statics are its own.
    [InlineData("static byte[] M(KerckhoffsLabs.Security.Cryptography.Pkcs11.Pkcs11Session s) => Rfc2898DeriveBytesPkcs11.Pbkdf2(s, new byte[1], new byte[16], 1, HashAlgorithmName.SHA256, 32);")]
    public async Task NotABclStaticThroughAnAdapter_IsNotReported(string member)
        => Assert.Empty(await AnalyzeAsync(Usings + $"static class C {{ {member} }}"));

    [Fact]
    public void UsingStaticOfAnAdapter_DoesNotImportItsBaseStatics()
    {
        // Why the analyzer only looks at member accesses: `using static` imports the members a type
        // declares itself, never inherited ones, so a bare GenerateKey cannot reach MLDsa through
        // the adapter. If the language ever changed that, this would compile and the rule would
        // need to cover bare names too.
        CSharpCompilation compilation = CSharpCompilation.Create(
            "Consumer",
            [CSharpSyntaxTree.ParseText(Usings + """
                using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MLDsaPkcs11;
                static class C { static MLDsa M() => GenerateKey(MLDsaAlgorithm.MLDsa65); }
                """, ParseOptions, cancellationToken: TestContext.Current.CancellationToken)],
            Framework.Add(Library),
            CompilationOptions);

        Assert.Contains(compilation.GetDiagnostics(TestContext.Current.CancellationToken), d => d.Id == "CS0103");
    }

    // -----------------------------------------------------------------------
    // Adapter detection by assembly — fields, events, the adapter's own statics
    // -----------------------------------------------------------------------

    private const string StandInBcl = """
        namespace System.Security.Cryptography.StandIn
        {
            public abstract class Widget
            {
                public static int Counter;
                public static event System.EventHandler? Changed { add { } remove { } }
                public static int Helper() => 0;
            }
        }
        """;

    private const string StandInAdapter = """
        namespace StandIn
        {
            public sealed class WidgetPkcs11 : System.Security.Cryptography.StandIn.Widget
            {
                public static int Own() => 1;
            }
        }
        """;

    [Theory]
    [InlineData("static int M() => StandIn.WidgetPkcs11.Counter;", "StandIn.WidgetPkcs11.Counter")]
    [InlineData("static void M() => StandIn.WidgetPkcs11.Changed += (_, _) => { };", "StandIn.WidgetPkcs11.Changed")]
    [InlineData("static int M() => StandIn.WidgetPkcs11.Helper();", "StandIn.WidgetPkcs11.Helper")]
    public async Task AnyTypeOfTheLibraryAssemblyDerivingFromACryptographyType_IsAnAdapter(string member, string reported)
    {
        Diagnostic diagnostic = Assert.Single(await AnalyzeWithStandInAsync(
            "KerckhoffsLabs.Security.Cryptography.Pkcs11", $"static class C {{ {member} }}"));

        Assert.Equal(BclStaticThroughAdapterAnalyzer.HelperDiagnosticId, diagnostic.Id);
        Assert.Equal(reported, SourceAt(diagnostic));
    }

    [Fact]
    public async Task TheAdaptersOwnStatic_IsNotReported()
        => Assert.Empty(await AnalyzeWithStandInAsync(
            "KerckhoffsLabs.Security.Cryptography.Pkcs11", "static class C { static int M() => StandIn.WidgetPkcs11.Own(); }"));

    [Fact]
    public async Task ADerivedTypeFromAnotherAssembly_IsNotAnAdapter()
        => Assert.Empty(await AnalyzeWithStandInAsync(
            "SomeOther.Library", "static class C { static int M() => StandIn.WidgetPkcs11.Helper(); }"));

    // -----------------------------------------------------------------------
    // Code fix
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData(
        "static MLDsa M() => MLDsaPkcs11.GenerateKey(MLDsaAlgorithm.MLDsa65);",
        "static MLDsa M() => MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);")]
    [InlineData(
        "static bool M() => MLKemPkcs11.IsSupported;",
        "static bool M() => MLKem.IsSupported;")]
    [InlineData(
        "static byte[] M(byte[] data) => /* a */ SHA256Pkcs11 /* b */ .HashData(data);",
        "static byte[] M(byte[] data) => /* a */ SHA256 /* b */ .HashData(data);")]
    [InlineData(
        "static Func<MLDsaAlgorithm, MLDsa> M() => MLDsaPkcs11.GenerateKey;",
        "static Func<MLDsaAlgorithm, MLDsa> M() => MLDsa.GenerateKey;")]
    [InlineData(
        "static MLDsa M() => global::KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MLDsaPkcs11.GenerateKey(MLDsaAlgorithm.MLDsa44);",
        "static MLDsa M() => MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);")]
    [InlineData(
        "static void M(byte[] a, byte[] b) { _ = SHA384Pkcs11.HashData(a); _ = SHA384Pkcs11.HashData(b); }",
        "static void M(byte[] a, byte[] b) { _ = SHA384.HashData(a); _ = SHA384.HashData(b); }")]
    public async Task CodeFix_ReplacesTheReceiverWithTheBclType(string before, string after)
        => Assert.Equal(
            Usings + $"static class C {{ {after} }}",
            await FixAsync(Usings + $"static class C {{ {before} }}"));

    [Fact]
    public async Task CodeFix_Alias_ReplacesTheAliasWithTheBclType()
    {
        const string alias = "using Signer = KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MLDsaPkcs11;\n";

        Assert.Equal(
            Usings + alias + "static class C { static MLDsa M() => MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65); }",
            await FixAsync(Usings + alias + "static class C { static MLDsa M() => Signer.GenerateKey(MLDsaAlgorithm.MLDsa65); }"));
    }

    [Fact]
    public async Task CodeFix_AddsTheUsingDirective_WhenTheBclNamespaceIsNotImported()
    {
        Assert.Equal(
            """
            using System.Security.Cryptography;
            using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

            static class C { static object M() => Aes.Create(); }
            """,
            await FixAsync("""
                using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

                static class C { static object M() => AesPkcs11.Create(); }
                """));
    }

    // -----------------------------------------------------------------------
    // Harness
    // -----------------------------------------------------------------------

    private static string SourceAt(Diagnostic diagnostic)
        => diagnostic.Location.SourceTree!.GetText().ToString(diagnostic.Location.SourceSpan);

    private static Task<ImmutableArray<Diagnostic>> AnalyzeAsync(params string[] sources)
        => AnalyzeAsync(Framework.Add(Library), sources);

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeWithStandInAsync(string adapterAssembly, string source)
    {
        MetadataReference bcl = Emit("StandIn.Bcl", StandInBcl, Framework);
        MetadataReference adapter = Emit(adapterAssembly, StandInAdapter, Framework.Add(bcl));
        return await AnalyzeAsync(Framework.Add(bcl).Add(adapter), [source]);
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(ImmutableArray<MetadataReference> references, string[] sources)
    {
        CSharpCompilation compilation = CSharpCompilation.Create(
            "Consumer",
            sources.Select(source => CSharpSyntaxTree.ParseText(source, ParseOptions)),
            references,
            CompilationOptions);
        AssertCompiles(compilation);

        return await compilation
            .WithAnalyzers([new BclStaticThroughAdapterAnalyzer()])
            .GetAnalyzerDiagnosticsAsync(TestContext.Current.CancellationToken);
    }

    private static MetadataReference Emit(string assemblyName, string source, ImmutableArray<MetadataReference> references)
    {
        CSharpCompilation compilation = CSharpCompilation.Create(
            assemblyName, [CSharpSyntaxTree.ParseText(source, ParseOptions)], references, CompilationOptions);
        using var image = new MemoryStream();
        Microsoft.CodeAnalysis.Emit.EmitResult result = compilation.Emit(image);
        Assert.True(result.Success, string.Join(Environment.NewLine, result.Diagnostics));
        return MetadataReference.CreateFromImage(image.ToArray());
    }

    private static void AssertCompiles(Compilation compilation)
    {
        var errors = compilation.GetDiagnostics(TestContext.Current.CancellationToken)
            .Where(d => d.Severity == DiagnosticSeverity.Error)
            .ToList();
        Assert.True(errors.Count == 0, string.Join(Environment.NewLine, errors));
    }

    // Applies the fix to the first remaining diagnostic until none is left, then returns the text.
    private static async Task<string> FixAsync(string source)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var workspace = new AdhocWorkspace();
        ProjectId projectId = ProjectId.CreateNewId();
        DocumentId documentId = DocumentId.CreateNewId(projectId);
        Document document = workspace.CurrentSolution
            .AddProject(projectId, "Consumer", "Consumer", LanguageNames.CSharp)
            .WithProjectCompilationOptions(projectId, CompilationOptions)
            .WithProjectParseOptions(projectId, ParseOptions)
            .AddMetadataReferences(projectId, Framework.Add(Library))
            .AddDocument(documentId, "Consumer.cs", source)
            .GetDocument(documentId)!;

        for (int fixes = 0; ; fixes++)
        {
            Compilation compilation = (await document.Project.GetCompilationAsync(ct))!;
            AssertCompiles(compilation);
            ImmutableArray<Diagnostic> diagnostics = await compilation
                .WithAnalyzers([new BclStaticThroughAdapterAnalyzer()])
                .GetAnalyzerDiagnosticsAsync(ct);
            if (diagnostics.IsEmpty)
            {
                Assert.True(fixes > 0, "The source had nothing to fix.");
                return (await document.GetTextAsync(ct)).ToString();
            }
            Assert.True(fixes < 10, "The code fix does not converge.");

            var actions = new List<CodeAction>();
            await new BclStaticThroughAdapterCodeFixProvider().RegisterCodeFixesAsync(
                new CodeFixContext(document, diagnostics[0], (action, _) => actions.Add(action), ct));
            ImmutableArray<CodeActionOperation> operations = await Assert.Single(actions).GetOperationsAsync(ct);
            document = Assert.Single(operations.OfType<ApplyChangesOperation>()).ChangedSolution.GetDocument(documentId)!;
        }
    }
}
