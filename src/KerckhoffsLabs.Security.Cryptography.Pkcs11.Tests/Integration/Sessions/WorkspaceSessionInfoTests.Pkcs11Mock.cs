using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sessions;

/// <summary>
/// Exercises the public <see cref="Pkcs11Workspace.GetSessionInfo"/> accessor: it delegates to the
/// underlying session and is guarded by the workspace's disposed check. Decoding of the individual
/// fields is covered by <c>SessionInfoTests</c> / <c>Pkcs11SessionTests</c> with controlled fakes.
/// </summary>
[Collection("Mock")]
public sealed class WorkspaceSessionInfoTests(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact]
    public void GetSessionInfo_ReturnsInfo()
    {
        using var workspace = OpenWorkspace();

        SessionInfo info = workspace.GetSessionInfo();

        Assert.NotNull(info);
        Assert.True(Enum.IsDefined(info.State), $"unexpected session state: {info.State}");
    }

    [Fact]
    public void GetSessionInfo_AfterDispose_Throws()
    {
        var workspace = OpenWorkspace();
        workspace.Dispose();

        Assert.Throws<ObjectDisposedException>(() => workspace.GetSessionInfo());
    }
}
