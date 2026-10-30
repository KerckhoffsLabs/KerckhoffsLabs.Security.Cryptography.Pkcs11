using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// Where wolfPKCS11 keeps its token. It reads the directory from <c>WOLFPKCS11_TOKEN_PATH</c> through
/// <c>getenv()</c> and otherwise falls back to <c>~/.wolfPKCS11</c>, so a fixture whose variable never reached
/// the native environment would still pass every other test, while its tokens piled up in the user's
/// home and carried state from one run to the next.
/// </summary>
[Collection("WolfPkcs11")]
public sealed class WolfPkcs11FixtureTests(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Token_LivesInTheFixtureDirectory()
    {
        Assert.NotEmpty(Directory.EnumerateFileSystemEntries(_backend.TokenDirectory));
        Assert.False(
            Directory.Exists(Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".wolfPKCS11")),
            "wolfPKCS11 wrote its token under ~/.wolfPKCS11 instead of WOLFPKCS11_TOKEN_PATH.");
    }
}
