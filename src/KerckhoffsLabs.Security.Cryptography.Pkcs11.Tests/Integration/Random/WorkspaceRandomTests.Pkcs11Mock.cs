using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Random;

/// <summary>
/// Workspace-facade RNG tests: verify <see cref="Pkcs11Workspace.GenerateRandom(int)"/>
/// delegates to the session and enforces its argument guard. Session-level RNG behavior
/// across backends lives in <c>RandomTests</c>.
/// </summary>
[Collection("Mock")]
public sealed class WorkspaceRandomTests(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    [Fact]
    public void GenerateRandom_ReturnsRequestedLength()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        byte[] bytes = workspace.GenerateRandom(32);

        Assert.Equal(32, bytes.Length);
    }

    [Fact]
    public void GenerateRandom_ZeroLength_ThrowsArgumentOutOfRange()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateRandom(0));
    }
}
