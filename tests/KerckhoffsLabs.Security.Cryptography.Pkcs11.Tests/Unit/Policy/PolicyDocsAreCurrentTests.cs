using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>
/// Keeps the generated policy catalogue documentation — <c>docs/policies/secure-only.md</c>
/// and <c>docs/policies/fips-only.md</c> — byte-for-byte in sync with what <see cref="PolicyCatalogueMarkdown"/>
/// renders from the real <c>SecureOnly</c>/<c>FipsOnly</c> catalogues.
/// </summary>
/// <remarks>
/// Run with the <c>UPDATE_POLICY_DOCS=1</c> environment variable set to regenerate the committed files
/// instead of asserting against them (the test still passes in that mode). Without it — which is every CI
/// run, since CI never sets it — this test only reads the committed files and never writes: a stale file
/// fails the assertion rather than silently rewriting itself.
/// </remarks>
public sealed class PolicyDocsAreCurrentTests
{
    private const string UpdateEnvironmentVariable = "UPDATE_POLICY_DOCS";

    public static TheoryData<string, string> Pages => new()
    {
        { "SecureOnly", "docs/policies/secure-only.md" },
        { "FipsOnly", "docs/policies/fips-only.md" },
    };

    private static PolicyCatalogue CatalogueFor(string policyName) => policyName switch
    {
        "SecureOnly" => CryptoPolicy.SecureOnly.Catalogue,
        "FipsOnly" => FipsOnlyPolicy.Catalogue,
        _ => throw new ArgumentOutOfRangeException(nameof(policyName)),
    };

    [Theory]
    [MemberData(nameof(Pages))]
    public void GeneratedDoc_MatchesTheCommittedFile(string policyName, string relativePath)
    {
        string repoRoot = FindRepoRoot();
        string path = Path.Join(repoRoot, relativePath.Replace('/', Path.DirectorySeparatorChar));
        string rendered = PolicyCatalogueMarkdown.Render(CatalogueFor(policyName), policyName);
        var utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

        if (Environment.GetEnvironmentVariable(UpdateEnvironmentVariable) == "1")
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, rendered, utf8NoBom);
            return;
        }

        Assert.True(File.Exists(path), $"{relativePath} does not exist; run with {UpdateEnvironmentVariable}=1 to regenerate.");
        byte[] committed = File.ReadAllBytes(path);
        byte[] expected = utf8NoBom.GetBytes(rendered);
        Assert.True(
            committed.AsSpan().SequenceEqual(expected),
            $"{relativePath} is stale (the {policyName} catalogue changed); run with {UpdateEnvironmentVariable}=1 to regenerate.");
    }

    /// <summary>Walks up from the test assembly's own directory to the directory containing <c>src/KerckhoffsLabs.sln</c>.</summary>
    private static string FindRepoRoot()
    {
        for (DirectoryInfo? dir = new(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Join(dir.FullName, "src", "KerckhoffsLabs.sln")))
                return dir.FullName;
        }
        throw new InvalidOperationException(
            $"Could not locate the repo root (looked for src/KerckhoffsLabs.sln walking up from {AppContext.BaseDirectory}).");
    }
}
