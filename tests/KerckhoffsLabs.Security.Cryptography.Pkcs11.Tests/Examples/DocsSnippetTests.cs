using System.Text.RegularExpressions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

/// <summary>
/// The docs pages include example code by region (docfx <c>[!code-csharp[](path#region)]</c>). Every
/// include must name a region that exists, and every region in the examples project must be shown by
/// some page, so a renamed region or an orphaned example fails here rather than on the docs site.
/// </summary>
public sealed partial class DocsSnippetTests
{
    [GeneratedRegex(@"\[!code-csharp\[[^\]]*\]\(([^)#]+)#([^)]+)\)\]")]
    private static partial Regex Include();

    [GeneratedRegex(@"^\s*#region\s+(\S+)", RegexOptions.Multiline)]
    private static partial Regex Region();

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Join(dir.FullName, "KerckhoffsLabs.sln")))
                return dir.FullName;
        throw new InvalidOperationException("KerckhoffsLabs.sln not found above the test binaries.");
    }

    private static IEnumerable<(string Page, string File, string Region)> Includes()
    {
        string docs = Path.Join(RepoRoot(), "docs");
        foreach (string page in Directory.EnumerateFiles(docs, "*.md", SearchOption.AllDirectories)
                     .Where(p => !p.Contains($"{Path.DirectorySeparatorChar}_site{Path.DirectorySeparatorChar}", StringComparison.Ordinal)))
            foreach (Match m in Include().Matches(File.ReadAllText(page)))
                yield return (page, Path.GetFullPath(Path.Join(Path.GetDirectoryName(page)!, m.Groups[1].Value)), m.Groups[2].Value);
    }

    private static IEnumerable<(string File, string Region)> SampleRegions()
    {
        string samples = Path.Join(RepoRoot(), "samples");
        foreach (string file in Directory.EnumerateFiles(samples, "*.cs", SearchOption.AllDirectories)
                     .Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)))
            foreach (Match m in Region().Matches(File.ReadAllText(file)))
                yield return (Path.GetFullPath(file), m.Groups[1].Value);
    }

    [Fact]
    public void DocsIncludes_ResolveToRegions()
    {
        HashSet<(string, string)> regions = [.. SampleRegions()];
        string[] broken = [.. Includes().Where(i => !regions.Contains((i.File, i.Region)))
            .Select(i => $"{Path.GetFileName(i.Page)} → {i.File}#{i.Region}")];
        Assert.True(broken.Length == 0, $"Docs includes with no matching #region: {string.Join("; ", broken)}.");
    }

    [Fact]
    public void EverySampleRegion_IsIncludedByADocsPage()
    {
        HashSet<(string, string)> included = [.. Includes().Select(i => (i.File, i.Region))];
        string[] orphans = [.. SampleRegions().Where(r => !included.Contains(r)).Select(r => $"{Path.GetFileName(r.File)}#{r.Region}")];
        Assert.True(orphans.Length == 0, $"Example regions no docs page shows: {string.Join(", ", orphans)}.");
    }
}
