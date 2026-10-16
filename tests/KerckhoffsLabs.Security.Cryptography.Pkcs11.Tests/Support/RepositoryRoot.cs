namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>The repository checkout the tests run from, for tests that read or regenerate committed files.</summary>
internal static class RepositoryRoot
{
    /// <summary>Walks up from the test assembly's own directory to the directory containing <c>KerckhoffsLabs.sln</c>.</summary>
    public static string Find()
    {
        for (DirectoryInfo? dir = new(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Join(dir.FullName, "KerckhoffsLabs.sln")))
                return dir.FullName;
        }
        throw new InvalidOperationException(
            $"Could not locate the repo root (looked for KerckhoffsLabs.sln walking up from {AppContext.BaseDirectory}).");
    }
}
