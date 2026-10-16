using System.Text.RegularExpressions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Architecture;

/// <summary>
/// Every OID the library uses is spelled out once, in <c>Common/Oids.cs</c>, next to the standard that
/// assigns it. A string literal elsewhere in <c>src/</c> that looks like an OID fails here; comments are
/// not code and are skipped.
/// </summary>
public sealed partial class OidLiteralTests
{
    // A quoted dotted-decimal string of at least four arcs whose first arc is 0, 1 or 2: an OID, not a
    // version number like "3.0".
    [GeneratedRegex("\"[0-2](\\.[0-9]+){3,}\"")]
    private static partial Regex OidLiteral();

    private static readonly string SourceRoot = Path.Join(RepositoryRoot.Find(), "src");

    private static readonly string OidsFile =
        Path.Join(SourceRoot, "KerckhoffsLabs.Security.Cryptography.Pkcs11", "Common", "Oids.cs");

    [Fact]
    public void OidLiterals_AppearOnlyInOidsCs()
    {
        char sep = Path.DirectorySeparatorChar;
        string[] violations = [.. Directory.EnumerateFiles(SourceRoot, "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{sep}obj{sep}", StringComparison.Ordinal)
                && !path.Contains($"{sep}bin{sep}", StringComparison.Ordinal)
                && !string.Equals(path, OidsFile, StringComparison.Ordinal))
            .SelectMany(path => File.ReadLines(path).Select((line, index) => (path, line, number: index + 1)))
            .Where(l => !l.line.TrimStart().StartsWith("//", StringComparison.Ordinal) && OidLiteral().IsMatch(l.line))
            .Select(l => $"{Path.GetRelativePath(SourceRoot, l.path)}:{l.number}: {l.line.Trim()}")];

        Assert.True(violations.Length == 0,
            "OID literals outside Common/Oids.cs; add them to Oids and reference the constant:\n" + string.Join("\n", violations));
    }

    // Guards the scan: the pattern does match the literals it is meant to find.
    [Fact]
    public void Scan_FindsTheLiteralsInOidsCs()
        => Assert.Contains(File.ReadLines(OidsFile), line => OidLiteral().IsMatch(line));
}
