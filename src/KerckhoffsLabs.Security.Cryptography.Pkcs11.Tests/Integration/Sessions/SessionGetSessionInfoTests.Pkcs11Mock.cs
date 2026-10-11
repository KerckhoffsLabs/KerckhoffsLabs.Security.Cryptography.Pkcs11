using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sessions;

/// <summary>
/// Exercises the public <see cref="Pkcs11Session.GetSessionInfo"/> accessor: it delegates to the
/// session core and is guarded by the session's disposed check. Decoding of the individual
/// fields is covered by <c>SessionInfoTests</c> / <c>Pkcs11SessionCoreTests</c> with controlled fakes.
/// </summary>
[Collection("Mock")]
public sealed class SessionGetSessionInfoTests(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    private Pkcs11Session OpenSession() =>
        _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact]
    public void GetSessionInfo_ReturnsInfo()
    {
        using var session = OpenSession();

        SessionInfo info = session.GetSessionInfo();

        Assert.NotNull(info);
        Assert.True(Enum.IsDefined(info.State), $"unexpected session state: {info.State}");
    }

    [Fact]
    public void GetSessionInfo_AfterDispose_Throws()
    {
        var session = OpenSession();
        session.Dispose();

        Assert.Throws<ObjectDisposedException>(() => session.GetSessionInfo());
    }
}
